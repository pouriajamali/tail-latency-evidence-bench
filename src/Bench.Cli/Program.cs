using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TailEvidence;

var options=new JsonSerializerOptions{WriteIndented=true,PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
options.Converters.Add(new LongAsString());
try
{
    var version=Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
    if(args.Length==1 && args[0] is "--help" or "--version")
    {
        Console.WriteLine(JsonSerializer.Serialize(new{version,usage="Offline synthetic open-loop evidence: demo NEW_DIRECTORY | run healthy|slow NEW_DIRECTORY [COUNT PERIOD_US CAPACITY RAW_CAPACITY SEED] | raw-cap-demo NEW_DIRECTORY. No exchange/wire latency claim."}));return 0;
    }
    if(args.Length==2 && args[0]=="demo")
    {
        var root=Fresh(args[1]);var records=new List<object>();var allComplete=true;
        for(var repeat=1;repeat<=3;repeat++)
        {
            foreach(var mode in new[]{"healthy","slow"})
            {
                var result=Runner.Run(new Configuration(),mode);var dir=Fresh(Path.Combine(root,$"{repeat}-{mode}"));
                Save(dir,result,version);allComplete &= result.Status=="COMPLETE";records.Add(new{repeat,mode,result.Status,result.OfferedScheduleSha256,result.Statistics});
            }
        }
        File.WriteAllText(Path.Combine(root,"DEMO.json"),JsonSerializer.Serialize(new{status=allComplete?"RECORDED_VERIFY_WITH_ORACLE":"INCOMPLETE",runs=records,warning="Completed-only quantiles exclude missing work. Compare offered counts, rejections and censoring; no speed-improvement or hardware/wire claim."},options),new UTF8Encoding(false));
        Console.WriteLine(JsonSerializer.Serialize(new{status=allComplete?"DEMO_RECORDED_NOT_INDEPENDENTLY_VERIFIED":"INCOMPLETE",runs=6,directory=root}));return allComplete?0:4;
    }
    if(args.Length==2 && args[0]=="raw-cap-demo")
    {
        var result=Runner.Run(new Configuration(Count:100,RawCapacity:16),"healthy");Save(Fresh(args[1]),result,version);Console.WriteLine(JsonSerializer.Serialize(new{status=result.Status,reason=result.Reason}));return result.Status=="INCOMPLETE"?4:2;
    }
    if(args.Length is 3 or 8 && args[0]=="run")
    {
        var config=args.Length==8?new Configuration(Count:Int(args[3]),PeriodUs:Int(args[4]),Capacity:Int(args[5]),RawCapacity:Int(args[6]),Seed:uint.Parse(args[7],CultureInfo.InvariantCulture)):new Configuration();
        var result=Runner.Run(config,args[1]);Save(Fresh(args[2]),result,version);Console.WriteLine(JsonSerializer.Serialize(new{status=result.Status,counts=result.Statistics?.Counts,mode=result.Mode}));return result.Status=="COMPLETE"?0:4;
    }
    throw new ArgumentException("USAGE");
}
catch(Exception error) when(error is ArgumentException or OverflowException or FormatException or IOException or InvalidOperationException)
{Console.WriteLine(JsonSerializer.Serialize(new{status="FAILED_CLOSED",error=error.GetType().Name}));return 2;}

int Int(string value)=>int.Parse(value,CultureInfo.InvariantCulture);
string Fresh(string value)
{
    var path=Path.GetFullPath(value);if(Directory.Exists(path) || File.Exists(path))throw new IOException("Output exists.");Directory.CreateDirectory(path);return path;
}
void Save(string directory,Result result,string? version)
{
    var file=Path.Combine(directory,"raw.csv");
    using(var writer=new StreamWriter(new FileStream(file,FileMode.CreateNew),new UTF8Encoding(false)))
    {
        writer.WriteLine("index,intended,work_units,planned_failure,observed,actual_send,enqueue,service_start,completion,admitted");
        foreach(var sample in result.Records)
        {
            static string Tick(long? tick)=>tick?.ToString(CultureInfo.InvariantCulture)??"";
            writer.WriteLine(string.Create(CultureInfo.InvariantCulture,$"{sample.Index},{sample.Intended},{sample.WorkUnits},{(sample.PlannedFailure?1:0)},{Tick(sample.Observed)},{Tick(sample.ActualSend)},{Tick(sample.Enqueue)},{Tick(sample.ServiceStart)},{Tick(sample.Completion)},{(sample.Admitted?1:0)}"));
            if(writer.BaseStream.Position>64*1024*1024)throw new IOException("Bounded raw-byte cap; no COMPLETE summary written.");
        }
    }
    var summary=new{schema=1,result.Status,result.Reason,result.Mode,result.Configuration,result.CutoffTicks,result.OfferedScheduleSha256,result.Clock,result.WarmupPlanned,result.WarmupCompleted,result.Statistics,environment=new{runtime=RuntimeInformation.FrameworkDescription,os=RuntimeInformation.OSDescription,architecture=RuntimeInformation.ProcessArchitecture.ToString(),logicalProcessors=Environment.ProcessorCount,gcServer=System.Runtime.GCSettings.IsServerGC,version},sampleBoundary="One local process, one monotonic clock. Relative ticks; completed-only empirical nearest-rank quantiles. No cross-host, NIC/wire or exchange time."};
    File.WriteAllText(Path.Combine(directory,"summary.json"),JsonSerializer.Serialize(summary,options),new UTF8Encoding(false));
}
public sealed class LongAsString:JsonConverter<long>
{
    public override long Read(ref Utf8JsonReader reader,Type type,JsonSerializerOptions options)=>reader.TokenType==JsonTokenType.String?long.Parse(reader.GetString()!,CultureInfo.InvariantCulture):reader.GetInt64();
    public override void Write(Utf8JsonWriter writer,long value,JsonSerializerOptions options)=>writer.WriteStringValue(value.ToString(CultureInfo.InvariantCulture));
}
