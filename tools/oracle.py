"""Independent integer/Fraction oracle over bounded raw samples; no timing pass threshold."""
import argparse,csv,hashlib,io,json
from fractions import Fraction
from pathlib import Path

HEADER=['index','intended','work_units','planned_failure','observed','actual_send','enqueue','service_start','completion','admitted']
def require(condition,message):
    if not condition:raise ValueError(message)
def integer(value):
    require(type(value) in [int,str],'Integer field required')
    result=int(value)
    if isinstance(value,str):require(str(result)==value,'Canonical integer string required')
    return result
def bounded(path,cap):
    require(path.is_file() and not path.is_symlink(),'Regular input required')
    with path.open('rb') as source:data=source.read(cap+1)
    require(len(data)<=cap,'Evidence input exceeds cap');return data
def nearest(values,p,q,floor=1):
    if len(values)<floor:return None
    rank=Fraction(len(values)*p,q).__ceil__();return sorted(values)[rank-1]
def validate(directory,expect_incomplete=False):
    directory=Path(directory);summary=json.loads(bounded(directory/'summary.json',2*1024*1024).decode('utf-8'))
    require(summary['schema']==1,'Schema');reader=csv.DictReader(io.StringIO(bounded(directory/'raw.csv',64*1024*1024).decode('ascii')))
    require(reader.fieldnames==HEADER,'Raw schema');rows=list(reader);require(len(rows)<=200000,'Raw record cap')
    if expect_incomplete:
        require(summary['status']=='INCOMPLETE' and summary['reason']=='RAW_RECORD_CAP_BEFORE_START' and not rows and summary['statistics'] is None,'Incomplete cap must not invent samples/quantiles')
        return {'status':'PASS_INCOMPLETE_CAP_NO_STATISTICAL_RESULT','records':0,'quantiles':None}
    require(summary['status']=='COMPLETE','Incomplete run has no complete accounting/quantile claim')
    config=summary['configuration'];frequency=integer(summary['clock']['frequency']);count=integer(config['count']);cutoff=integer(summary['cutoffTicks'])
    require(frequency>0 and count==len(rows) and count<=integer(config['rawCapacity']),'Declared record/accounting cap')
    period=integer(config['periodUs'])*frequency//1000000;late=integer(config['latenessBudgetUs'])*frequency//1000000;deadline=integer(config['deadlineUs'])*frequency//1000000;seed=integer(config['seed'])
    require(period>0 and cutoff==(count-1)*period+integer(config['drainUs'])*frequency//1000000,'Clock/cutoff convention')
    require(integer(summary['warmupPlanned'])==min(count,integer(config['warmupCount'])) and 0<=integer(summary['warmupCompleted'])<=integer(summary['warmupPlanned']),'Separate warmup boundary')
    counters=dict.fromkeys(['planned','generatorMissed','attempted','admitted','rejected','completedAtCutoff','censoredAtCutoff','success','failure','generatorLate','completedDeadlineExceeded','notCompletedDeadlineExpired'],0)
    e2e=[];queue=[];service=[];schedule=hashlib.sha256()
    for index,row in enumerate(rows):
        require(set(row)==set(HEADER) and None not in row.values(),'Raw framing')
        data={key:(None if value=='' else integer(value)) for key,value in row.items()}
        require(data['index']==index and data['intended']==index*period,'Planned identity/order')
        mixed=(index*1103515245+seed)&0xffffffff;units=mixed%4+1;failure=1 if ((index+seed)&0xffffffff)%97==0 else 0
        require(data['work_units']==units and data['planned_failure']==failure and data['admitted'] in [0,1],'Immutable offered work')
        schedule.update(f'{index},{index*integer(config["periodUs"])},{units},{failure}\n'.encode('ascii'));counters['planned']+=1
        intended=data['intended'];observed=data['observed'];send=data['actual_send'];enqueued=data['enqueue'];started=data['service_start'];completed=data['completion'];admitted=bool(data['admitted'])
        if observed is not None:require(observed>=intended,'Observed visit chronology')
        if send is None:
            counters['generatorMissed']+=1;require(enqueued is None and started is None and completed is None and not admitted,'Unattempted sample has downstream stage')
        else:
            counters['attempted']+=1;require(observed==send and intended<=send<=cutoff and send-intended<=late,'Actual-send convention')
            counters['admitted' if admitted else 'rejected']+=1
        require(admitted==(enqueued is not None),'Admission stamp')
        if enqueued is not None:require(send is not None and send<=enqueued<=cutoff,'Enqueue chronology')
        if started is not None:require(enqueued is not None and enqueued<=started<=cutoff,'Service chronology')
        if completed is not None:
            require(started is not None and started<=completed<=cutoff,'Completion chronology');counters['completedAtCutoff']+=1;counters['failure' if failure else 'success']+=1
            e2e.append(completed-intended);queue.append(started-enqueued);service.append(completed-started)
            if completed-intended>deadline:counters['completedDeadlineExceeded']+=1
        elif admitted:counters['censoredAtCutoff']+=1
        if observed is not None and observed-intended>late:counters['generatorLate']+=1
        if completed is None and cutoff-intended>deadline:counters['notCompletedDeadlineExpired']+=1
    require(schedule.hexdigest()==summary['offeredScheduleSha256'],'Offered schedule hash')
    actual=summary['statistics'];require(all(type(v) is int for v in actual['counts'].values()),'Integer counters required');require(counters==actual['counts'],'Independent disjoint and orthogonal counts')
    require(counters['planned']==counters['generatorMissed']+counters['attempted'] and counters['attempted']==counters['admitted']+counters['rejected'] and counters['admitted']==counters['completedAtCutoff']+counters['censoredAtCutoff'] and counters['completedAtCutoff']==counters['success']+counters['failure'],'Conservation identities')
    for name,values in [('intendedToCompletion',e2e),('queue',queue),('service',service)]:
        result=actual[name];require(integer(result['samples'])==len(values),'Completed-only sample set')
        for key,p,q,floor in [('p50',1,2,1),('p95',95,100,1),('p99',99,100,1),('p999',999,1000,100000)]:
            expected=nearest(values,p,q,floor);observed=None if result[key] is None else integer(result[key]);require(observed==expected,'Independent exact rank '+name+'/'+key)
    return {'status':'PASS','mode':summary['mode'],'records':len(rows),'configuration':config,'sourceVersion':summary['environment']['version'],'offeredScheduleSha256':schedule.hexdigest(),'counts':counters,'frequency':frequency,'completedOnlyE2eTicks':{key:actual['intendedToCompletion'][key] for key in ['p50','p95','p99','p999']},'warning':'Missing work excluded from completed-only ranks. No statistical confidence/speed/wire/exchange claim.'}

def main():
    p=argparse.ArgumentParser(description=__doc__);group=p.add_mutually_exclusive_group(required=True);group.add_argument('--run',type=Path);group.add_argument('--demo',type=Path);p.add_argument('--expect-incomplete',action='store_true');p.add_argument('--out',type=Path,required=True);a=p.parse_args();require(not a.out.exists(),'Receipt exists')
    if a.demo:
        require(not a.expect_incomplete,'Demo requires six complete datasets');results=[validate(a.demo/(str(repeat)+'-'+mode)) for repeat in [1,2,3] for mode in ['healthy','slow']]
        require(len({x['offeredScheduleSha256'] for x in results})==1 and len({x['sourceVersion'] for x in results})==1,'Same offered schedule and executable across all cases')
        require(len({json.dumps(x['configuration'],sort_keys=True) for x in results})==1,'Admission, cutoff and deadline settings must stay identical')
        receipt={'status':'PASS','runs':results,'runCount':6,'boundary':'Native local-process observations. CI correctness checks no performance threshold. Healthy/slow labels are controlled service settings, not guaranteed measured ordering.'}
    else:receipt=validate(a.run,a.expect_incomplete)
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8');print(json.dumps({'status':receipt['status'],'runCount':receipt.get('runCount',1),'receipt':str(a.out)}))
if __name__=='__main__':main()
