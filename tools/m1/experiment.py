"""Project11 private future executor. SOURCE PREPARATION ONLY; attachment required."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
import preflight_witness as witness

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
OUT = ROOT / "outputs" / HERE.name
PIN = "6158f7f8a9a8e4fd7c12ed575f427d7117b89801"
BASE = "4003f255078bf2f1af5badead0dd81972c307260"
PROTOCOL_SHA256 = "9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b"
DEADLINE = None
FINGERPRINT = "SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU"

def require(ok, message):
    if not ok:
        raise ValueError(message)

def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1048576), b""):
            h.update(block)
    return h.hexdigest()

def read_json(path, cap=262144):
    return json.loads(witness.bounded(path, cap), object_pairs_hook=witness.no_duplicates)

def fresh_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, indent=2)
        f.write("\n")

def under(path, root):
    p, r = Path(path).resolve(strict=True), Path(root).resolve(strict=True)
    require(p == r or r in p.parents, "path outside admitted root")
    # Disallow links at every component below the root.
    q = Path(path).absolute()
    while q != r and r in q.parents:
        require(not q.is_symlink(), "linked input")
        q = q.parent
    return p

def attach(args):
    import support
    a=support.load_frame(args.attachment,args.attachment_sha,phase=('case' if args.phase=='cap99-supplement' else args.phase),rid=args.rid)
    require(a["runtimeCommit"]==PIN and a["legacyException"]=="PRIVATE_6158_10.0.14_ONLY","legacy runtime binding")
    require(digest(HERE/"case-plan.json")==a["casePlanSha256"],"case plan")
    require(a["oracle"][args.rid]["sha256"]=="82c6998225f6bd38d1df941ceb49e13d3adcfb16678780a6a25da17e56ebe1bf","frozen oracle")
    for name,sha in a["sourceHashes"].items():
        require(digest(HERE/name)==sha,"source changed")
    global DEADLINE
    DEADLINE=a["executionWindow"]["deadlineUnix"]-30
    return a,read_json(HERE/"case-plan.json")

def profile(a,args):
    import support
    return support.actual_profile(a,args.rid)

def admitted_input(a, rid):
    data = a["inputs"][rid]
    expected = next(x for x in read_json(HERE / "input-bindings.json")["archives"]
                    if x["rid"] == rid)
    require(data["archiveSha256"] == expected["sha256"], "wrong archive")
    cli = under(data["cliPath"], HERE / "inputs")
    require(digest(cli) == data["cliSha256"], "CLI bytes")
    receipt = under(data["verificationReceipt"]["path"], HERE / "inputs")
    require(digest(receipt) == data["verificationReceipt"]["sha256"], "input receipt bytes")
    v = read_json(receipt)
    require(v["status"] == "PASS_ARCHIVE_KEY_MANIFEST" and v["rid"] == rid and
            v["archiveSha256"] == expected["sha256"] and v["trustedFingerprint"] == FINGERPRINT and
            v["safeArchiveMembers"] is True and v["runtimeCommit"] == PIN, "unverified package")
    package = under(data["packageRoot"], HERE / "inputs")
    require(package.is_dir() and package in cli.parents, "CLI outside exact package")
    inventory = under(data["memberInventory"]["path"], HERE / "inputs")
    require(digest(inventory) == data["memberInventory"]["sha256"], "member inventory changed")
    require(v["memberInventorySha256"] == data["memberInventory"]["sha256"],
            "archive verification did not bind this extracted inventory")
    members = read_json(inventory, 2097152)
    require(type(members) is list and 1 <= len(members) <= 512, "bounded package members")
    expected_paths, total = set(), 0
    for member in members:
        name = member["relativePath"]
        require(type(name) is str and name and "\\" not in name and ":" not in name and
                not name.startswith("/") and all(p not in ("", ".", "..") for p in name.split("/")),
                "unsafe inventory path")
        require(name not in expected_paths, "duplicate member")
        expected_paths.add(name)
        path = under(package / name, package)
        require(path.is_file() and type(member["bytes"]) is int and member["bytes"] >= 0 and
                path.stat().st_size == member["bytes"] and digest(path) == member["sha256"],
                "extracted member changed")
        total += member["bytes"]
    require(total <= 402653184, "inflated package byte cap")
    actual_paths = set()
    for path in package.rglob("*"):
        require(not path.is_symlink(), "linked package entry")
        if path.is_file():
            actual_paths.add(path.relative_to(package).as_posix())
    require(actual_paths == expected_paths, "missing or extra extracted member")
    return cli, data["cliSha256"]

def expected_config(cap):
    return {"count": 100, "periodUs": 100, "capacity": 64, "rawCapacity": cap,
            "seed": 20261109, "latenessBudgetUs": 2000, "drainUs": 20000,
            "deadlineUs": 2000, "warmupCount": 100}

def bounded_child(argv):
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd=str(HERE), env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    output, errors = [], []
    total, lock = [0], threading.Lock()
    overflow = threading.Event()
    def drain(stream, chunks):
        size = 0
        while True:
            block = stream.read(4096)
            if not block:
                return
            size += len(block)
            with lock:
                total[0] += len(block)
                exceeded = total[0] > 262144
            if exceeded:
                overflow.set()
                child.kill()
                return
            chunks.append(block)
    threads = [threading.Thread(target=drain, args=x, daemon=True)
               for x in ((child.stdout, output), (child.stderr, errors))]
    for t in threads:
        t.start()
    try:
        child.wait(timeout=max(0.001, min(45, DEADLINE - time.time())))
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)
        raise ValueError("native timeout; original attempt retained, no retry")
    for t in threads:
        t.join(timeout=2)
        require(not t.is_alive(), "log thread terminal")
    require(not overflow.is_set(), "native output byte cap")
    return child.returncode, b"".join(output).decode("utf-8", "replace"), b"".join(errors).decode("utf-8", "replace")

def native_case(a, args, proof):
    require(args.mode == "normal" and args.cap in (99, 100, 101), "native case allowance")
    ridroot = OUT / args.rid
    # Exclusive durable intent: failure/timeout cannot be retried under the same case identity.
    attempt = ridroot / ("attempt-cap-" + str(args.cap) + ".json")
    cli, cli_hash = admitted_input(a, args.rid)
    out = ridroot / ("cap-" + str(args.cap))
    require(not out.exists(), "native output exists")
    previous = {99: None, 100: 99, 101: 100}[args.cap]
    if previous is not None:
        read_json(ridroot / ("result-cap-" + str(previous) + ".json"))
    tail = ["run", "healthy", str(out), "100", "100", "64", str(args.cap), "20261109"]
    intent = {"rid": args.rid, "cap": args.cap, "argvTail": tail, "cliSha256": cli_hash,
              "outputDirectory": str(out), "profile": proof, "status": "ATTEMPT_RESERVED_NO_RETRY"}
    fresh_json(attempt, intent)
    code, stdout, stderr = bounded_child([str(cli)] + tail)
    require((out / "summary.json").stat().st_size <= 32768, "summary cap")
    require((out / "raw.csv").stat().st_size <= 65536, "raw cap")
    result = {**intent, "returncode": code, "stdout": stdout, "stderr": stderr,
              "rawSha256": digest(out / "raw.csv"), "summarySha256": digest(out / "summary.json"),
              "status": "ACTUAL_PROCESS_EXIT_RECORDED_NOT_VALIDATED"}
    fresh_json(ridroot / ("result-cap-" + str(args.cap) + ".json"), result)
    require(code == (4 if args.cap == 99 else 0), "unexpected native exit; no retune/retry")

def load_oracle(a, rid):
    p = Path(a["oracle"][rid]["path"])
    require(digest(p) == a["oracle"][rid]["sha256"], "shipped oracle changed")
    spec = importlib.util.spec_from_file_location("tail11_frozen_oracle", p)
    module = importlib.util.module_from_spec(spec)
    sys.modules["tail11_frozen_oracle"] = module
    spec.loader.exec_module(module)
    return module

def supplemental_cap99(a,args,proof):
    require(args.rid=='win-x64' and args.cap==99 and args.mode=='normal','FIXED_SINGLE_CAP99_SUPPLEMENT')
    authority=a['supplementalCap99'];require(digest(authority['path'])==authority['sha256'],'SUPPLEMENT_AUTHORITY_BYTES');permit=read_json(authority['path'])
    require(permit['schema']=='tail11-one-cap99-owner-supplement/v1' and permit['allowedNativeCalls']==1 and permit['cap']==99 and permit['frozenCasePlanSHA256']==a['casePlanSha256'] and permit['Actions']==0 and permit['sameCeilings'] is True,'EXACT_OWNER_SUPPLEMENT_SCOPE')
    cli,cli_hash=admitted_input(a,args.rid);root=OUT/'win-x64-supplement-cap99-20261119';out=root/'cap-99'
    require(not root.exists(),'SUPPLEMENT_ALREADY_RESERVED_NO_RETRY');tail=['run','healthy',str(out),'100','100','64','99','20261109']
    intent={'schema':'tail11-owner-authorized-cap99-supplement/v1','rid':'win-x64','cap':99,'argvTail':tail,'outputDirectory':str(out),'cliSha256':cli_hash,'profile':proof,'authoritySHA256':authority['sha256'],'originalCaseNotReplaced':True,'maximumNativeCalls':1}
    fresh_json(root/'attempt.json',intent);code,stdout,stderr=bounded_child([str(cli)]+tail)
    result={**intent,'returncode':code,'stdout':stdout,'stderr':stderr,'rawSha256':digest(out/'raw.csv'),'summarySha256':digest(out/'summary.json'),'originalNativeWaitReturned':True,'status':'ACTUAL_OWNER_SUPPLEMENT_RECORDED'}
    fresh_json(root/'result.json',result);require(code==4,'SUPPLEMENT_NATIVE_EXIT')
    strict=witness.validate(out,expected_config(99),result)
    fresh_json(root/'strict-witness.json',{'status':'PASS_OWNER_CAP99_SUPPLEMENT_DATA_ONLY','result':strict,'nativeCalls':1,'oldWrapperHOLDNotRelabelled':True,'requiresSeparateNaturalJobTerminal':True})

def mutate(number, data, raw, row):
    d = copy.deepcopy(data)
    if number == 1: d["configuration"]["rawCapacity"] = 100
    elif number == 2: d["configuration"]["rawCapacity"] = 101
    elif number == 3: d["configuration"]["count"] = 0
    elif number == 4: d["configuration"]["rawCapacity"] = 0
    elif number == 5: d["configuration"]["count"] = 200001
    elif number == 6: d["cutoffTicks"] = "1"
    elif number == 7: d["offeredScheduleSha256"] = "0" * 64
    elif number == 8: d["warmupPlanned"] = 1
    elif number == 9: d["statistics"] = {}
    elif number == 10: raw += row
    elif number == 11: d["status"] = "COMPLETE"
    elif number == 12: d["reason"] = "WORKER_JOIN_BOUND"
    else: raise ValueError("unallowlisted mutation")
    return d, raw

def validators(a, args, proof):
    oracle = load_oracle(a, args.rid)
    ridroot = OUT / args.rid
    outputs, invocations = {}, {}
    for cap in (99, 100, 101):
        inv = read_json(ridroot / ("result-cap-" + str(cap) + ".json"))
        out = ridroot / ("cap-" + str(cap))
        require(digest(out / "raw.csv") == inv["rawSha256"] and
                digest(out / "summary.json") == inv["summarySha256"], "native dataset changed")
        require(inv["returncode"] == (4 if cap == 99 else 0), "native exit")
        witness.configuration(witness.summary(out)["configuration"], expected_config(cap))
        answer = oracle.validate(out, expect_incomplete=(cap == 99))
        if cap == 99:
            strict = witness.validate(out, expected_config(cap), inv)
        else:
            d = witness.summary(out)
            require(d["environment"]["version"] == "0.1.0-preview.1+" + PIN, "runtime source version")
            require(answer["records"] == 100, "missing complete rows")
            for key in ("intendedToCompletion", "queue", "service"):
                require(d["statistics"][key]["p999"] is None, "invented p999")
            strict = {"status": "EXTERNAL_FIXED_CONFIG_MATCH_COMPLETE_ACCOUNTING_BY_ORACLE"}
        outputs[str(cap)] = {"originalOracle": answer, "independentWitness": strict}
        invocations[cap] = inv
    same = [outputs[str(c)]["originalOracle"]["offeredScheduleSha256"] for c in (100, 101)]
    require(same[0] == same[1], "offered schedule changed")
    base = ridroot / "cap-99"
    raw = witness.bounded(base / "raw.csv", 65536)
    first_row = witness.bounded(ridroot / "cap-100" / "raw.csv", 65536).splitlines(keepends=True)[1]
    data = witness.summary(base)
    controls = []
    for n in range(1, 13):
        folder = ridroot / "negative-controls" / ("N" + str(n).zfill(2))
        altered, raw_altered = mutate(n, data, raw, first_row)
        encoded = (json.dumps(altered, indent=2) + "\n").encode()
        if args.mode == "normal":
            folder.mkdir(parents=True, exist_ok=False)
            with (folder / "summary.json").open("xb") as f: f.write(encoded)
            with (folder / "raw.csv").open("xb") as f: f.write(raw_altered)
        require(witness.bounded(folder / "summary.json", 32768) == encoded and
                witness.bounded(folder / "raw.csv", 65536) == raw_altered, "mutation identity")
        answers = {}
        for name, function in (
            ("originalOracle", lambda: oracle.validate(folder, expect_incomplete=True)),
            ("independentWitness", lambda: witness.validate(folder, expected_config(99), invocations[99]))):
            try:
                answers[name] = {"accepted": True, "value": function()}
            except (ValueError, KeyError, TypeError) as error:
                answers[name] = {"accepted": False, "error": type(error).__name__, "message": str(error)}
        require(not answers["independentWitness"]["accepted"], "strict witness false-positive")
        controls.append({"id": "N" + str(n).zfill(2), **answers})
    receipt = {"status": "RECORDED_ACCOUNTING_AND_PREFLIGHT_FINDINGS_NOT_SPEED",
               "rid": args.rid, "mode": args.mode, "nativeRunsReplayed": 0,
               "positiveCases": outputs, "negativeControls": controls, "profile": proof,
               "falsePositiveIds": [x["id"] for x in controls if x["originalOracle"]["accepted"]],
               "limitations": "Original oracle false positives preserved; no shipped code fix; no speed/security claim."}
    fresh_json(ridroot / ("validators-" + args.mode + ".json"), receipt)

def storage_guard():
    require(DEADLINE is None or time.time() < DEADLINE, "phase deadline exceeded")
    total = evidence = count = 0
    for base in (HERE, OUT):
        if not base.exists():
            continue
        for path in base.rglob("*"):
            require(not path.is_symlink(), "linked scratch/output")
            if path.is_file():
                count += 1
                size = path.stat().st_size
                total += size
                if base == OUT:
                    evidence += size
    require(count <= 4096 and total <= 1073741824 and evidence <= 8388608,
            "scratch/evidence budget")

def support_guard(a):
    import support
    support.verify_current_modules(a)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--attachment", type=Path, required=True)
    p.add_argument("--attachment-sha", required=True)
    p.add_argument("--rid", choices=["win-x64", "linux-x64"], required=True)
    p.add_argument("--phase", choices=["probe", "case", "validate", "cap99-supplement"], required=True)
    p.add_argument("--cap", type=int, choices=[99, 100, 101])
    p.add_argument("--mode", choices=["normal", "optimized"], required=True)
    args = p.parse_args()
    a, plan = attach(args)
    storage_guard()
    support_guard(a)
    proof = profile(a, args)
    # All target phases require the same source-bound actual controller admission.
    if args.phase == "probe":
        fresh_json(OUT / args.rid / "held-child-actual-profile.json", proof)
        time.sleep(2)
        return
    probe = a["actualControllerAdmission"][args.rid]
    require(probe["status"] == "PASS_HELD_CHILD_TERMINAL_AND_IDENTITY_DENIAL" and
            digest(probe["path"]) == probe["sha256"], "controller admission unresolved")
    if args.phase == 'cap99-supplement':
        supplemental_cap99(a,args,proof)
    elif args.phase == "case":
        native_case(a, args, proof)
    else:
        validators(a, args, proof)
    storage_guard()

if __name__ == "__main__":
    main()
