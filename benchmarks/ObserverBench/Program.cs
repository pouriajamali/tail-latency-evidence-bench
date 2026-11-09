using System.Diagnostics;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
// Explicitly opt out before any benchmark process starts. Never change the host power plan.
var config=ManualConfig.Create(DefaultConfig.Instance).AddJob(Job.ShortRun.DontEnforcePowerPlan().WithId("ObserverOnlyNoPowerChange"));
if(args.Length!=1 || Directory.Exists(args[0]) || File.Exists(args[0]))throw new ArgumentException("Pass a NEW artifacts directory; run from this benchmark project directory.");
config=config.WithArtifactsPath(Path.GetFullPath(args[0]));
var summary=BenchmarkRunner.Run<ObserverOverhead>(config);
if(summary.Reports.Count()!=2 || summary.Reports.Any(report=>!report.Success || report.ResultStatistics is null))return 2;
return 0;
[MemoryDiagnoser]
public class ObserverOverhead
{
    private readonly long[] stamps=new long[1024];private int index;
    [Benchmark(Baseline=true)] public long ReadClock()=>Stopwatch.GetTimestamp();
    [Benchmark] public long ReadAndStorePreallocated(){var value=Stopwatch.GetTimestamp();stamps[index++&1023]=value;return value;}
}
