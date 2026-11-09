"""Read bounded platform/CPU/power metadata; never alter host configuration."""
import argparse,json,os,platform,subprocess
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    if a.out.exists():raise ValueError('Evidence exists')
    cpu='UNKNOWN';power='UNKNOWN';virtualization='UNKNOWN'
    if os.name=='nt':
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:cpu=winreg.QueryValueEx(key,'ProcessorNameString')[0].strip()
        result=subprocess.run(['powercfg','/GETACTIVESCHEME'],capture_output=True,text=True,timeout=10)
        if result.returncode==0:power=result.stdout.strip()[:512]
    else:
        cpuinfo=Path('/proc/cpuinfo')
        if cpuinfo.is_file():
            for line in cpuinfo.read_text().splitlines():
                if line.startswith('model name'):cpu=line.split(':',1)[1].strip();break
        if 'microsoft' in platform.release().lower():virtualization='WSL2 virtual machine; not an independent physical fault domain or native bare-metal benchmark'
        governor=Path('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor')
        if governor.is_file():power='cpu0 governor='+governor.read_text().strip()
    data={'os':platform.system(),'release':platform.release(),'architecture':platform.machine(),'cpuModel':cpu,'logicalProcessors':os.cpu_count(),'virtualization':virtualization,'powerConfigurationReadOnly':power,'scope':'Missing metadata is UNKNOWN. No hostname/account/workspace path; no changes to power, timer resolution, security, affinity or system settings.'}
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8');print(json.dumps({'status':'RECORDED_READ_ONLY','os':data['os'],'virtualization':virtualization}))
if __name__=='__main__':main()
