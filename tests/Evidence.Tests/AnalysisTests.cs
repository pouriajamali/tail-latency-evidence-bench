using System.Diagnostics;
using System.Numerics;
using TailEvidence;
using Xunit;
public class AnalysisTests
{
    [Fact]
    public void EightHandWorkedRequestsHaveDisjointAccounting()
    {
        var rows=Enumerable.Range(0,8).Select(i=>new Sample(i,i*10,1,i==3)).ToArray();
        // Two missed; one rejected; five admitted; three completed, one failure.
        foreach(var i in new[]{1,2,3,4,5,6}){rows[i].ActualSend=i*10+1;rows[i].Observed=i*10+1;}
        foreach(var i in new[]{2,3,4,5,6}){rows[i].Admitted=true;rows[i].Enqueue=i*10+2;}
        foreach(var i in new[]{2,3,4}){rows[i].ServiceStart=i*10+3;rows[i].Completion=i*10+7;}
        rows[5].ServiceStart=55;
        var result=Analyze.Complete(rows,100,new Configuration(Count:8));
        Assert.Equal(new[]{8,2,6,5,1,3,2,2,1},new[]{result.Counts.Planned,result.Counts.GeneratorMissed,result.Counts.Attempted,result.Counts.Admitted,result.Counts.Rejected,result.Counts.CompletedAtCutoff,result.Counts.CensoredAtCutoff,result.Counts.Success,result.Counts.Failure});
        Assert.Equal(7,result.IntendedToCompletion.P50);Assert.Null(result.IntendedToCompletion.P999);
    }
    [Theory]
    [InlineData(1,2,4)] [InlineData(95,100,8)] [InlineData(99,100,8)]
    public void NearestRankMatchesRationalOrderStatistic(int numerator,int denominator,long expected)
    {
        var input=new long[]{8,1,7,2,6,3,5,4};
        var rank=(int)BigInteger.Divide(new BigInteger(input.Length)*numerator+denominator-1,denominator);
        Assert.Equal(expected,input.Order().ElementAt(rank-1));Assert.Equal(expected,Analyze.NearestRank(input,numerator,denominator));
    }
    [Fact] public void NoSamplesNeverMeansZeroLatency()=>Assert.Null(Analyze.NearestRank([],1,2));
    [Fact]
    public void P999DisplayFloorIsNotAConfidenceClaim()
    {
        Assert.Null(Analyze.NearestRank(Enumerable.Repeat(9L,99999),999,1000,100000));
        Assert.Equal(9,Analyze.NearestRank(Enumerable.Repeat(9L,100000),999,1000,100000));
    }
    [Fact]
    public void PreflightRecordCapIsIncompleteWithoutQuantilesOrLostSamples()
    {
        var result=Runner.Run(new Configuration(Count:100,RawCapacity:16),"healthy");
        Assert.Equal("INCOMPLETE",result.Status);Assert.Equal("RAW_RECORD_CAP_BEFORE_START",result.Reason);Assert.Null(result.Statistics);Assert.Empty(result.Records);
    }
    [Fact]
    public void OfferedScheduleDoesNotDependOnConsumer()
    {
        var config=new Configuration(Count:100);var a=Schedule.Create(config);var b=Schedule.Create(config);
        Assert.Equal(Schedule.Digest(a,config.PeriodUs),Schedule.Digest(b,config.PeriodUs));Assert.NotEqual(Schedule.Digest(a,config.PeriodUs),Schedule.Digest(Schedule.Create(config with {Seed=config.Seed+1}),config.PeriodUs));
        Assert.All(a,s=>Assert.Equal(new BigInteger(s.Index)*Time.Ticks(config.PeriodUs),new BigInteger(s.Intended)));
    }
    [Fact]
    public void ImpossibleChronologyIsRejected()
    {
        var row=new Sample(0,10,1,false){ActualSend=9};
        Assert.Throws<InvalidOperationException>(()=>Analyze.Complete([row],100,new Configuration(Count:1)));
    }
    [Fact]
    public void CompletedAfterCutoffIsRejected()
    {
        var row=new Sample(0,0,1,false){Observed=1,ActualSend=1,Enqueue=2,Admitted=true,ServiceStart=3,Completion=101};
        Assert.Throws<InvalidOperationException>(()=>Analyze.Complete([row],100,new Configuration(Count:1)));
    }
    [Theory] [InlineData(0)] [InlineData(200001)]
    public void InvalidCountDoesNotRun(int count)=>Assert.Throws<ArgumentOutOfRangeException>(()=>Runner.Run(new Configuration(Count:count),"healthy"));
    [Fact] public void UnboundedNominalDurationDoesNotRun()=>Assert.Throws<ArgumentException>(()=>Runner.Run(new Configuration(Count:200000,PeriodUs:1000000),"slow"));
    [Fact]
    public void DeadlineFlagsRemainOrthogonalToTerminalSuccessFailure()
    {
        var failed=new Sample(0,0,1,true){Observed=0,ActualSend=0,Enqueue=0,Admitted=true,ServiceStart=0,Completion=Time.Ticks(20)};
        var good=new Sample(1,0,1,false){Observed=0,ActualSend=0,Enqueue=0,Admitted=true,ServiceStart=0,Completion=Time.Ticks(5)};
        var missed=new Sample(2,Time.Ticks(10),1,false);
        var counts=Analyze.Complete([failed,good,missed],Time.Ticks(30),new Configuration(Count:3,DeadlineUs:10)).Counts;
        Assert.Equal(2,counts.CompletedAtCutoff);Assert.Equal(1,counts.Success);Assert.Equal(1,counts.Failure);Assert.Equal(1,counts.CompletedDeadlineExceeded);Assert.Equal(1,counts.NotCompletedDeadlineExpired);
    }
    [Fact]
    public void BoundedRealSchedulerChecksAccountingOnly()
    {
        var result=Runner.Run(new Configuration(Count:100,PeriodUs:1000,WarmupCount:0,DrainUs:10000),"slow");
        Assert.Equal("COMPLETE",result.Status);var c=result.Statistics!.Counts;
        Assert.Equal(c.Planned,c.GeneratorMissed+c.Attempted);Assert.Equal(c.Attempted,c.Admitted+c.Rejected);Assert.Equal(c.Admitted,c.CompletedAtCutoff+c.CensoredAtCutoff);Assert.Equal(c.CompletedAtCutoff,c.Success+c.Failure);
        // No timing/performance threshold is asserted on shared or virtualized hosts.
    }
}
