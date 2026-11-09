using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
namespace TailEvidence;

public sealed record Configuration(int Count=5000,int PeriodUs=100,int Capacity=64,int RawCapacity=100000,uint Seed=20261109,int LatenessBudgetUs=2000,int DrainUs=20000,int DeadlineUs=2000,int WarmupCount=100)
{
    public void Validate()
    {
        if(Count is <1 or >200000 || PeriodUs is <1 or >1000000 || Capacity is <1 or >4096 || RawCapacity is <1 or >200000 || LatenessBudgetUs is <0 or >5000000 || DrainUs is <0 or >5000000 || DeadlineUs is <1 or >10000000 || WarmupCount is <0 or >10000)throw new ArgumentOutOfRangeException(nameof(Configuration));
        if((long)(Count-1)*PeriodUs+DrainUs>30000000)throw new ArgumentException("Nominal profile exceeds 30 seconds.");
    }
}
public sealed class Sample(int index,long intended,int workUnits,bool plannedFailure)
{
    public int Index {get;}=index;
    public long Intended {get;}=intended;
    public int WorkUnits {get;}=workUnits;
    public bool PlannedFailure {get;}=plannedFailure;
    public long? Observed {get;set;}
    public long? ActualSend {get;set;}
    public long? Enqueue {get;set;}
    public long? ServiceStart {get;set;}
    public long? Completion {get;set;}
    public bool Admitted {get;set;}
}
public sealed record Counts(int Planned,int GeneratorMissed,int Attempted,int Admitted,int Rejected,int CompletedAtCutoff,int CensoredAtCutoff,int Success,int Failure,int GeneratorLate,int CompletedDeadlineExceeded,int NotCompletedDeadlineExpired);
public sealed record Percentiles(long? P50,long? P95,long? P99,long? P999,int Samples,string P999Policy);
public sealed record Statistics(Counts Counts,Percentiles IntendedToCompletion,Percentiles Queue,Percentiles Service);
public sealed record ClockObservation(long Frequency,bool IsHighResolution,long? MinimumPositiveReadDelta,int ZeroReadDeltas,int Samples);
public sealed record Result(string Status,string Reason,string Mode,Configuration Configuration,long CutoffTicks,string OfferedScheduleSha256,ClockObservation Clock,Statistics? Statistics,Sample[] Records)
{
    public int WarmupPlanned {get;init;}
    public int WarmupCompleted {get;init;}
}

public static class Time
{
    public static long Ticks(int microseconds)
    {
        var value=checked((long)((Int128)microseconds*Stopwatch.Frequency/1000000));
        if(microseconds>0 && value==0)throw new InvalidOperationException("Clock cannot represent requested interval.");
        return value;
    }
    public static ClockObservation Observe()
    {
        long? min=null;var zeros=0;var previous=Stopwatch.GetTimestamp();
        for(var i=0;i<1000;i++){var now=Stopwatch.GetTimestamp();var delta=now-previous;if(delta>0)min=min is null?delta:Math.Min(min.Value,delta);else zeros++;previous=now;}
        return new(Stopwatch.Frequency,Stopwatch.IsHighResolution,min,zeros,1000);
    }
}
public static class Schedule
{
    public static Sample[] Create(Configuration config)
    {
        var period=Time.Ticks(config.PeriodUs);var values=new Sample[config.Count];
        for(var i=0;i<values.Length;i++)
        {
            var mixed=unchecked((uint)i*1103515245u+config.Seed);
            values[i]=new Sample(i,checked(i*period),(int)(mixed%4)+1,unchecked((uint)i+config.Seed)%97==0);
        }
        return values;
    }
    public static string Digest(IEnumerable<Sample> samples,int periodUs)
    {
        using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach(var s in samples)
        {
            var line=string.Create(CultureInfo.InvariantCulture,$"{s.Index},{checked((long)s.Index*periodUs)},{s.WorkUnits},{(s.PlannedFailure?1:0)}\n");
            hash.AppendData(Encoding.ASCII.GetBytes(line));
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}
public static class Analyze
{
    public static long? NearestRank(IEnumerable<long> values,int numerator,int denominator,int floor=1)
    {
        if(numerator<1 || denominator<numerator || floor<1)throw new ArgumentException("Quantile policy.");
        var ordered=values.Order().ToArray();if(ordered.Length<floor)return null;
        var rank=checked((int)(((Int128)ordered.Length*numerator+denominator-1)/denominator));
        return ordered[rank-1];
    }
    private static Percentiles Quantiles(long[] values)=>new(NearestRank(values,1,2),NearestRank(values,95,100),NearestRank(values,99,100),NearestRank(values,999,1000,100000),values.Length,"p99.9 suppressed below 100000 completions; display policy, not a confidence guarantee.");
    public static Statistics Complete(Sample[] values,long cutoff,Configuration config)
    {
        var attempted=values.Count(v=>v.ActualSend.HasValue);var admitted=values.Count(v=>v.Admitted);var completed=values.Where(v=>v.Completion.HasValue).ToArray();
        foreach(var s in values)
        {
            if(s.Observed is long visited && visited<s.Intended)throw new InvalidOperationException("Observed visit precedes intended.");
            if(s.ActualSend.HasValue && s.Observed!=s.ActualSend)throw new InvalidOperationException("Actual send must have its observed issue stamp.");
            if(s.ActualSend is long sent && sent<s.Intended)throw new InvalidOperationException("Actual send precedes intended.");
            if(s.Admitted!=(s.Enqueue.HasValue) || (!s.Admitted && (s.ServiceStart.HasValue || s.Completion.HasValue)))throw new InvalidOperationException("Admission chronology.");
            if(s.Enqueue is long enqueue && (s.ActualSend is null || enqueue<s.ActualSend.Value))throw new InvalidOperationException("Enqueue chronology.");
            if(s.ServiceStart is long service && (s.Enqueue is null || service<s.Enqueue.Value || service>cutoff))throw new InvalidOperationException("Start chronology.");
            if(s.Completion is long end && (s.ServiceStart is null || end<s.ServiceStart.Value || end>cutoff))throw new InvalidOperationException("Completion chronology.");
        }
        var failed=completed.Count(v=>v.PlannedFailure);
        var counts=new Counts(values.Length,values.Length-attempted,attempted,admitted,attempted-admitted,completed.Length,admitted-completed.Length,completed.Length-failed,failed,
            values.Count(v=>v.Observed is long at && at-v.Intended>Time.Ticks(config.LatenessBudgetUs)),
            completed.Count(v=>v.Completion!.Value-v.Intended>Time.Ticks(config.DeadlineUs)),
            values.Count(v=>!v.Completion.HasValue && cutoff-v.Intended>Time.Ticks(config.DeadlineUs)));
        return new(counts,Quantiles(completed.Select(v=>v.Completion!.Value-v.Intended).ToArray()),Quantiles(completed.Select(v=>v.ServiceStart!.Value-v.Enqueue!.Value).ToArray()),Quantiles(completed.Select(v=>v.Completion!.Value-v.ServiceStart!.Value).ToArray()));
    }
}
