using System.Diagnostics;
using System.Threading.Channels;

namespace TailEvidence;
public static class Runner
{
    public static Result Run(Configuration config, string mode)
    {
        config.Validate();
        if (mode is not ("healthy" or "slow"))
            throw new ArgumentException("Mode.");
        var clock = Time.Observe();
        if (config.Count > config.RawCapacity)
            return new("INCOMPLETE", "RAW_RECORD_CAP_BEFORE_START", mode, config, 0, "", clock, null, []);
        var records = Schedule.Create(config);
        var digest = Schedule.Digest(records, config.PeriodUs);
        using var stop = new CancellationTokenSource();
        var token = stop.Token;
        var serviceBaseUs = mode == "healthy" ? 10 : 500;
        // A separate whole-pipeline run warms the same paths. Its samples never enter measured records/counts.
        var warmupPlanned = 0;
        var warmupCompleted = 0;
        if (config.WarmupCount > 0)
        {
            var warmup = Run(config with { Count = Math.Min(config.Count, config.WarmupCount), WarmupCount = 0, DrainUs = Math.Min(config.DrainUs, 100000) }, mode);
            if (warmup.Status != "COMPLETE")
                return new("INCOMPLETE", "WARMUP_INCOMPLETE", mode, config, 0, digest, clock, null, []);
            warmupPlanned = warmup.Statistics!.Counts.Planned;
            warmupCompleted = warmup.Statistics.Counts.CompletedAtCutoff;
        }

        var queue = Channel.CreateBounded<Sample>(new BoundedChannelOptions(config.Capacity) { SingleWriter = true, SingleReader = true, FullMode = BoundedChannelFullMode.Wait, AllowSynchronousContinuations = false });
        var origin = checked(Stopwatch.GetTimestamp() + Stopwatch.Frequency / 100);
        var cutoff = checked(records[^1].Intended + Time.Ticks(config.DrainUs));
        var absoluteCutoff = checked(origin + cutoff);
        var lateBudget = Time.Ticks(config.LatenessBudgetUs);
        Exception? error = null;
        void Fail(Exception failure)
        {
            Interlocked.CompareExchange(ref error, failure, null);
            stop.Cancel();
        }

        var consumer = new Thread(() =>
        {
            try
            {
                while (!token.IsCancellationRequested && Stopwatch.GetTimestamp() <= absoluteCutoff)
                {
                    if (!queue.Reader.TryRead(out var sample))
                    {
                        Thread.Yield();
                        continue;
                    }

                    var start = Stopwatch.GetTimestamp();
                    if (start > absoluteCutoff)
                        break;
                    sample.ServiceStart = start - origin;
                    var target = checked(start + Time.Ticks(checked(serviceBaseUs * sample.WorkUnits)));
                    if (!Wait(Math.Min(target, absoluteCutoff), token))
                        break;
                    var finish = Stopwatch.GetTimestamp();
                    if (finish <= absoluteCutoff && finish >= target)
                        sample.Completion = finish - origin;
                }
            }
            catch (Exception failure)
            {
                Fail(failure);
            }
        })
        {
            IsBackground = true,
            Name = "bounded-single-consumer"
        };
        var generator = new Thread(() =>
        {
            try
            {
                foreach (var sample in records)
                {
                    if (token.IsCancellationRequested)
                        break;
                    Wait(checked(origin + sample.Intended), token);
                    var observed = Stopwatch.GetTimestamp() - origin;
                    sample.Observed = observed;
                    if (observed - sample.Intended > lateBudget || observed > cutoff)
                        continue;
                    sample.ActualSend = observed;
                    var admission = Stopwatch.GetTimestamp() - origin;
                    if (admission > cutoff)
                        continue; // Attempt rejected at adapter cutoff; never enqueued.
                    sample.Enqueue = admission;
                    sample.Admitted = true;
                    if (!queue.Writer.TryWrite(sample))
                    {
                        sample.Admitted = false;
                        sample.Enqueue = null;
                    }
                }

                queue.Writer.TryComplete();
            }
            catch (Exception failure)
            {
                Fail(failure);
            }
        })
        {
            IsBackground = true,
            Name = "fixed-open-loop-generator"
        };
        consumer.Start();
        generator.Start();
        Wait(absoluteCutoff, token);
        stop.Cancel();
        var generatorJoined = generator.Join(2000);
        var consumerJoined = consumer.Join(2000);
        if (!generatorJoined || !consumerJoined || error is not null)
            return new("INCOMPLETE", error?.GetType().Name ?? "WORKER_JOIN_BOUND", mode, config, cutoff, digest, clock, null, []);
        return new("COMPLETE", "", mode, config, cutoff, digest, clock, Analyze.Complete(records, cutoff, config), records)
        {
            WarmupPlanned = warmupPlanned,
            WarmupCompleted = warmupCompleted
        };
    }

    private static bool Wait(long target, CancellationToken token)
    {
        while (Stopwatch.GetTimestamp() < target)
        {
            if (token.IsCancellationRequested)
                return false;
            if (target - Stopwatch.GetTimestamp() > Stopwatch.Frequency / 500)
                Thread.Sleep(1);
            else
                Thread.SpinWait(32);
        }

        return !token.IsCancellationRequested;
    }
}
