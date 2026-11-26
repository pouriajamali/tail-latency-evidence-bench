"""Counterexamples against the independent raw-data oracle, using an actual run."""
import argparse,csv,json,shutil,unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import oracle

CAP_HEADER = (
    b'index,intended,work_units,planned_failure,observed,actual_send,'
    b'enqueue,service_start,completion,admitted'
)


class PreflightCases(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.summary = {
            'schema': 1, 'status': 'INCOMPLETE', 'reason': 'RAW_RECORD_CAP_BEFORE_START',
            'configuration': {'count': 100, 'periodUs': 100, 'capacity': 64,
                              'rawCapacity': 99, 'seed': 20261109,
                              'latenessBudgetUs': 2000, 'drainUs': 20000,
                              'deadlineUs': 2000, 'warmupCount': 100},
            'cutoffTicks': '0', 'offeredScheduleSha256': '',
            'warmupPlanned': 0, 'warmupCompleted': 0, 'statistics': None,
        }
        self.raw = CAP_HEADER + b'\n'

    def validate(self):
        (self.path / 'summary.json').write_text(json.dumps(self.summary), encoding='utf-8')
        (self.path / 'raw.csv').write_bytes(self.raw)
        return oracle.validate(self.path, expect_incomplete=True)

    def test_valid_preflight_preserves_receipt_on_both_line_endings(self):
        expected = {'status': 'PASS_INCOMPLETE_CAP_NO_STATISTICAL_RESULT',
                    'records': 0, 'quantiles': None}
        for newline in (b'\n', b'\r\n'):
            with self.subTest(newline=newline):
                self.raw = CAP_HEADER + newline
                self.assertEqual(expected, self.validate())

    def test_cap_equal_to_count_n01(self):
        self.summary['configuration']['rawCapacity'] = 100
        with self.assertRaises(ValueError):
            self.validate()

    def test_cap_above_count_n02(self):
        self.summary['configuration']['rawCapacity'] = 101
        with self.assertRaises(ValueError):
            self.validate()

    def test_zero_count_n03(self):
        self.summary['configuration']['count'] = 0
        with self.assertRaises(ValueError):
            self.validate()

    def test_zero_cap_n04(self):
        self.summary['configuration']['rawCapacity'] = 0
        with self.assertRaises(ValueError):
            self.validate()

    def test_count_above_limit_n05(self):
        self.summary['configuration']['count'] = 200001
        with self.assertRaises(ValueError):
            self.validate()

    def test_nonzero_cutoff_n06(self):
        self.summary['cutoffTicks'] = '1'
        with self.assertRaises(ValueError):
            self.validate()

    def test_started_schedule_n07(self):
        self.summary['offeredScheduleSha256'] = '0' * 64
        with self.assertRaises(ValueError):
            self.validate()

    def test_planned_warmup_n08(self):
        self.summary['warmupPlanned'] = 1
        with self.assertRaises(ValueError):
            self.validate()

    def test_existing_negative_controls(self):
        for field, value in (('statistics', {}), ('status', 'COMPLETE'),
                             ('reason', 'WORKER_JOIN_BOUND'), ('warmupCompleted', 1)):
            with self.subTest(field=field):
                original = self.summary[field]
                self.summary[field] = value
                with self.assertRaises(ValueError):
                    self.validate()
                self.summary[field] = original
        for data in (b'0,0,1,0,0,0,0,0,0,1\n', b'\n'):
            with self.subTest(data=data):
                self.raw = CAP_HEADER + b'\n' + data
                with self.assertRaises(ValueError):
                    self.validate()

    def test_invalid_json_types(self):
        for field, value in (('schema', True), ('cutoffTicks', 0.0), ('warmupPlanned', False)):
            with self.subTest(field=field):
                original = self.summary[field]
                self.summary[field] = value
                with self.assertRaises(ValueError):
                    self.validate()
                self.summary[field] = original
        self.summary['configuration']['rawCapacity'] = '99'
        with self.assertRaises(ValueError):
            self.validate()

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
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                               for case in (Cases, PreflightCases))
    result=unittest.TextTestRunner(verbosity=2).run(suite);receipt={'status':'PASS' if result.wasSuccessful() else 'FAIL','run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors)};(a.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');raise SystemExit(0 if result.wasSuccessful() else 1)
if __name__=='__main__':main()
