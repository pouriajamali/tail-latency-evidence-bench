"""Counterexamples against the independent raw-data oracle, using an actual run."""
import argparse,csv,json,shutil,unittest
from pathlib import Path
import oracle

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--valid-run',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    class Cases(unittest.TestCase):
        def setUp(self):
            self.path=a.out/self._testMethodName;self.path.mkdir();shutil.copy2(a.valid_run/'summary.json',self.path/'summary.json');shutil.copy2(a.valid_run/'raw.csv',self.path/'raw.csv')
        def edit_summary(self,action):
            file=self.path/'summary.json';data=json.loads(file.read_text());action(data);file.write_text(json.dumps(data))
        def test_real_run_passes(self):self.assertEqual('PASS',oracle.validate(self.path)['status'])
        def test_missing_raw_record_is_not_silently_ignored(self):
            file=self.path/'raw.csv';lines=file.read_text().splitlines();file.write_text('\n'.join(lines[:-1])+'\n')
            with self.assertRaises(ValueError):oracle.validate(self.path)
        def test_boolean_counter_is_not_an_integer(self):
            self.edit_summary(lambda d:d['statistics']['counts'].__setitem__('planned',True))
            with self.assertRaises(ValueError):oracle.validate(self.path)
        def test_false_disjoint_counts_fail(self):
            self.edit_summary(lambda d:d['statistics']['counts'].__setitem__('rejected',d['statistics']['counts']['rejected']+1))
            with self.assertRaises(ValueError):oracle.validate(self.path)
        def test_invented_p999_below_floor_fails(self):
            self.edit_summary(lambda d:d['statistics']['intendedToCompletion'].__setitem__('p999','1'))
            with self.assertRaises(ValueError):oracle.validate(self.path)
        def test_wrong_nearest_rank_fails(self):
            self.edit_summary(lambda d:d['statistics']['intendedToCompletion'].__setitem__('p50',str(int(d['statistics']['intendedToCompletion']['p50'] or 0)+1)))
            with self.assertRaises(ValueError):oracle.validate(self.path)
        def test_wrong_offered_schedule_fails(self):
            self.edit_summary(lambda d:d.__setitem__('offeredScheduleSha256','0'*64))
            with self.assertRaises(ValueError):oracle.validate(self.path)
        def test_completion_after_cutoff_fails(self):
            raw=list(csv.DictReader((self.path/'raw.csv').open(newline='')));summary=json.loads((self.path/'summary.json').read_text());row=next((r for r in raw if r['completion']),raw[0])
            if not row['actual_send']:row.update(observed=row['intended'],actual_send=row['intended'],enqueue=row['intended'],service_start=row['intended'],admitted='1')
            if not row['enqueue']:row.update(enqueue=row['actual_send'],service_start=row['actual_send'],admitted='1')
            if not row['service_start']:row['service_start']=row['enqueue']
            row['completion']=str(int(summary['cutoffTicks'])+1)
            with (self.path/'raw.csv').open('w',newline='') as stream:
                writer=csv.DictWriter(stream,fieldnames=oracle.HEADER);writer.writeheader();writer.writerows(raw)
            with self.assertRaises(ValueError):oracle.validate(self.path)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases));receipt={'status':'PASS' if result.wasSuccessful() else 'FAIL','run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors)};(a.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');raise SystemExit(0 if result.wasSuccessful() else 1)
if __name__=='__main__':main()
