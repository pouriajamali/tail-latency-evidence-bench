"""One local causal/identity-negative group; no target, socket or provider scan."""
import argparse,ast,copy,json,os,sys
from pathlib import Path
import support as s
import qualifier as q
def main():
 p=argparse.ArgumentParser();p.add_argument("--attachment",required=True);p.add_argument("--attachment-sha",required=True);args=p.parse_args()
 a=s.load_frame(args.attachment,args.attachment_sha,rid="win-x64");profile=s.actual_profile(a,"win-x64")
 t=s.read(s.ticket_path());checks=[]
 def rejected(call,label):
  try:call()
  except (s.Hold,q.Hold):checks.append(label);return
  raise s.Hold("NEGATIVE_CONTROL_ACCEPTED")
 bad=copy.deepcopy(t);bad["execution"]="UNKNOWN"
 rejected(lambda:s.validate_ticket(bad,int(__import__("time").time())),"unknown_execution_denied")
 bad=copy.deepcopy(t);bad["casePlanSha256"]="0"*64
 rejected(lambda:s.validate_ticket(bad,int(__import__("time").time())),"wrong_case_identity_denied")
 bad=copy.deepcopy(t);bad["nonce"]="0"*32
 rejected(lambda:s.lane_guard(bad,a),"wrong_actual_canonical_owner_denied")
 rejected(lambda:q.require(q.os_base_provider(Path("C:/Windows/System32/UNADMITTED_TEST_PROVIDER.dll")),"UNEXPECTED_OS_PROVIDER"),"unknown_system32_provider_denied")
 rejected(lambda:q.require(q.os_base_provider(Path("C:/Temp/kernel32.dll")),"UNEXPECTED_OS_PROVIDER"),"wrong_root_known_basename_denied")
 rejected(lambda:q.require(q.os_base_provider(Path("C:/Windows/System32/PROPSYS.dll")),"UNEXPECTED_OS_PROVIDER"),"propsys_not_silently_admitted")
 s.need(q.os_base_provider(Path("C:/Windows/System32/kernel32.dll")),"ORIGINAL_OS_BASE_BROKEN");checks.append("original_predicate_preserved")
 for n in ("aggregate_worker.py","experiment.py"):
  tree=ast.parse((s.HERE/n).read_text())
  s.need(not any(isinstance(x,ast.Import) and any(y.name=="platform" for y in x.names) for x in tree.body),"UNNECESSARY_WMI_IMPORT");checks.append(n+"_no_global_platform")
 s.fresh(s.OUT/"public/local-causal-controls.json",{"status":"PASS_ONE_LOCAL_CAUSAL_GROUP","checks":checks,"profile":profile,"nativeCalls":0,"providerSnapshots":0,"healthyReplay":0})
