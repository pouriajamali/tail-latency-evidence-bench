"""Run this exact native CLI, then independently verify all raw accounting/ranks."""
import argparse,json,os,subprocess,sys
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cli',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False);cli=a.cli.resolve();tools=Path(__file__).resolve().parent
    def run(args,code=0):
        result=subprocess.run(list(map(str,args)),cwd=cli.parent,capture_output=True,text=True,timeout=90)
        if result.returncode!=code:raise ValueError('Unexpected native process result '+str(result.returncode)+' '+result.stderr[-1000:])
        return result.stdout
    run([cli,'demo',out/'runs']);run([sys.executable,tools/'oracle.py','--demo',out/'runs','--out',out/'oracle.json'])
    run([sys.executable,tools/'test_oracle.py','--valid-run',out/'runs/1-healthy','--out',out/'oracle-regressions'])
    run([cli,'raw-cap-demo',out/'rawcap'],code=4);run([sys.executable,tools/'oracle.py','--run',out/'rawcap','--expect-incomplete','--out',out/'rawcap-oracle.json'])
    run([sys.executable,tools/'environment.py','--out',out/'environment.json'])
    validated=json.loads((out/'oracle.json').read_text());regression=json.loads((out/'oracle-regressions/receipt.json').read_text())
    if validated['status']!='PASS' or validated['runCount']!=6 or regression['run']!=8 or regression['failures'] or regression['errors']:raise ValueError('Native evidence mismatch')
    receipt={'status':'PASS_ACCOUNTING_NOT_A_PERFORMANCE_THRESHOLD','os':os.name,'runs':6,'recordsEach':5000,'independentOracleRegressions':8,'rawCap':'INCOMPLETE_WITHOUT_STATISTICS','offeredScheduleSha256':validated['runs'][0]['offeredScheduleSha256'],'sourceVersion':validated['runs'][0]['sourceVersion'],'scope':'One native process/monotonic clock. Healthy/slow settings share offered inputs; all drops, censoring, failures and lateness retained. No wire/exchange or speed-improvement claim.'}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8');print(json.dumps(receipt))
if __name__=='__main__':main()
