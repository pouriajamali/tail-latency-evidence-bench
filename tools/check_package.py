"""Inspect every archive byte/license and execute the actual native CLI safely."""
import argparse,hashlib,json,os,platform,subprocess,sys
from pathlib import Path,PurePosixPath

def require(condition,message):
    if not condition:raise ValueError(message)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package',type=Path,required=True);p.add_argument('--commit',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();package=a.package.resolve();a.out.parent.mkdir(parents=True,exist_ok=True);require(not a.out.exists(),'Receipt exists')
    manifest=json.loads((package/'BUILD-MANIFEST.json').read_text());require(manifest['sourceCommit']==a.commit,'Commit');expected=set();checks=[]
    for item in manifest['files']:
        relative=PurePosixPath(item['path']);require(not relative.is_absolute() and '..' not in relative.parts and item['path'] not in expected,'Manifest path');expected.add(item['path']);file=package/relative
        require(file.is_file() and not file.is_symlink() and file.stat().st_size==item['bytes'] and hashlib.sha256(file.read_bytes()).hexdigest()==item['sha256'],'File content')
    require({p.relative_to(package).as_posix() for p in package.rglob('*') if p.is_file()}==expected|{'BUILD-MANIFEST.json'},'File set');checks.append('exact-payload-set-size-sha256')
    dependencies=json.loads((package/'DEPENDENCIES.json').read_text())['packages'];bom=json.loads((package/'SBOM.spdx.json').read_text());require(len(dependencies)==1 and len(bom['packages'])==2,'BCL runtime-only shipped graph')
    dep=dependencies[0];require(dep['id']=='Microsoft.NETCore.App.Runtime.'+manifest['rid'] and dep['version']=='10.0.14','Pinned actual runtime')
    license_file=package/dep['licenseFile'];require(license_file.stat().st_size>=300 and hashlib.sha256(license_file.read_bytes()).hexdigest()==dep['licenseSha256'],'Full runtime license');require((package/dep['copyrightFile']).read_text(encoding='utf-8').strip()==dep['copyright'],'Original copyright')
    require(any('THIRD-PARTY-NOTICES' in p.name.upper() for p in (package/'licenses').iterdir()),'Original runtime third-party notices');checks.extend(['full-runtime-license-copyright-thirdparty-notices','actual-bcl-runtime-graph'])
    item=next(i for i in bom['packages'] if i['name']==dep['id']);require(item['checksums']==[{'algorithm':'SHA512','checksumValue':dep['rawSignedNupkgSha512']}],'Raw signed archive checksum');checks.append('raw-archive-sha512-distinct-from-nuget-lock-identity')
    app=package/('tail-evidence.exe' if os.name=='nt' else 'tail-evidence')
    for flag in ['--help','--version']:
        result=subprocess.run([str(app),flag],cwd=package,capture_output=True,text=True,check=True,timeout=20);reply=json.loads(result.stdout);require(a.commit in reply['version'] and 'Offline synthetic' in reply['usage'],'Actual app source')
    checks.append('actual-native-help-version-source')
    work=a.out.parent/(a.out.stem+'-private-checks');work.mkdir(exist_ok=False)
    invalid=subprocess.run([str(app),'run','invalid-mode',str(work/'invalid')],capture_output=True,text=True,timeout=20);require(invalid.returncode==2 and json.loads(invalid.stdout)['status']=='FAILED_CLOSED' and not (work/'invalid').exists(),'Unknown mode rejected before output');checks.append('invalid-mode-rejected-before-output')
    cap=subprocess.run([str(app),'raw-cap-demo',str(work/'cap')],capture_output=True,text=True,timeout=20);require(cap.returncode==4 and json.loads(cap.stdout)['status']=='INCOMPLETE','Raw record cap must not pass')
    subprocess.run([sys.executable,str(package/'tools/oracle.py'),'--run',str(work/'cap'),'--expect-incomplete','--out',str(work/'cap-oracle.json')],check=True,capture_output=True,timeout=20);checks.append('actual-record-cap-no-statistics-quantiles')
    receipt={'status':'PASS','os':platform.system(),'sourceCommit':a.commit,'rid':manifest['rid'],'payloadFiles':len(expected),'checks':checks,'checkCount':len(checks),'shippedComponents':1};a.out.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8');print(json.dumps(receipt))
if __name__=='__main__':main()
