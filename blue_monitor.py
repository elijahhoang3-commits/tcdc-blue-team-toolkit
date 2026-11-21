#!/usr/bin/env python3
"""Read-only blue team monitoring toolkit. Python 3.10+, standard library only."""
import argparse
import collections
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import urllib.request

DEFAULT_CONFIG = Path(__file__).with_name('config.json')

def run(command):
    try:
        p = subprocess.run(command, capture_output=True, text=True, timeout=12, check=False)
        return p.stdout if p.returncode == 0 else f'ERROR ({p.returncode}): {p.stderr.strip()}'
    except (OSError, subprocess.TimeoutExpired) as e:
        return f'UNAVAILABLE: {e}'

def load_config(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def health(config):
    results=[]
    for s in config.get('services', []):
        name=s['name']; host=s.get('host','127.0.0.1'); port=int(s['port']); protocol=s.get('protocol','tcp')
        try:
            if protocol == 'http':
                url=s.get('url',f'http://{host}:{port}/')
                with urllib.request.urlopen(url,timeout=3) as response:
                    code=response.status
                ok=200<=code<400
                detail=f'HTTP {code}'
            elif protocol == 'dns':
                # DNS UDP request for A record example.com; checks response transaction ID and response flag.
                domain=s.get('domain','example.com')
                qid=os.urandom(2)
                question=b''.join(bytes([len(part)])+part.encode('ascii') for part in domain.rstrip('.').split('.'))+b'\x00\x00\x01\x00\x01'
                packet=qid+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+question
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                    sock.settimeout(3);sock.sendto(packet,(host,port)); reply,_=sock.recvfrom(4096)
                ok=len(reply)>=12 and reply[:2]==qid and bool(reply[2]&0x80) and (reply[3]&15)==0
                detail='DNS response OK' if ok else 'Invalid or error DNS response'
            else:
                with socket.create_connection((host,port),timeout=3) as sock:
                    if protocol=='ssh':
                        sock.settimeout(3); banner=sock.recv(128)
                        ok=banner.startswith(b'SSH-');detail=banner.decode('ascii','replace').strip()[:100]
                    elif protocol=='ftp':
                        sock.settimeout(3); banner=sock.recv(128)
                        ok=banner.startswith(b'220');detail=banner.decode('ascii','replace').strip()[:100]
                    else:
                        ok=True;detail='TCP port reachable (not application-verified)'
            results.append({'service':name,'host':host,'port':port,'ok':ok,'detail':detail})
        except Exception as e:
            results.append({'service':name,'host':host,'port':port,'ok':False,'detail':str(e)})
    return results

def auth(config):
    paths=config.get('auth_logs',[])
    pattern=re.compile(r'(failed password|authentication failure|invalid user|login failed|failed login|failure audit)',re.I)
    ip_pattern=re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
    counts=collections.Counter(); examples=[]; unavailable=[]
    for filename in paths:
        try:
            with open(filename,encoding='utf-8',errors='replace') as f:
                lines=collections.deque(f,maxlen=int(config.get('auth_tail_lines',3000)))
            for line in lines:
                if pattern.search(line):
                    match=ip_pattern.search(line); source=match.group() if match else 'unknown'
                    counts[source]+=1
                    if len(examples)<8:examples.append(line.strip()[:240])
        except (OSError,PermissionError) as e:
            unavailable.append(f'{filename}: {e}')
    return {'failed_login_counts':dict(counts.most_common(20)),'alert_threshold':config.get('auth_alert_threshold',5),'alerts':[ip for ip,n in counts.items() if n>=config.get('auth_alert_threshold',5)],'examples':examples,'unavailable_logs':unavailable,'note':'Counts matching lines in recent log tails, not a time-window or unique-event correlation. Windows event logs are not parsed.'}

def sha256(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(65536),b''):h.update(chunk)
    return h.hexdigest()

def integrity(config, baseline_path, initialize=False):
    paths=config.get('watch_files',[])
    current={}; errors={}
    for filename in paths:
        p=Path(filename)
        try:
            if p.is_file():current[str(p)]=sha256(p)
            elif p.is_dir():
                for child in sorted(p.rglob('*')):
                    if child.is_file() and not child.is_symlink():
                        try:current[str(child)]=sha256(child)
                        except OSError as e:errors[str(child)]=str(e)
            else:errors[str(p)]='missing or not a regular file/directory'
        except OSError as e:errors[str(p)]=str(e)
    baseline=Path(baseline_path)
    if initialize:
        if baseline.exists():raise ValueError(f'Baseline already exists: {baseline}. Refusing overwrite.')
        baseline.write_text(json.dumps({'created':dt.datetime.now(dt.timezone.utc).isoformat(),'hashes':current},indent=2),encoding='utf-8')
        return {'initialized':str(baseline),'tracked':len(current),'errors':errors}
    if not baseline.exists():return {'error':'No baseline. Run integrity --init-baseline first.','errors':errors}
    old=json.loads(baseline.read_text(encoding='utf-8'))['hashes']
    return {'added':sorted(set(current)-set(old)),'removed':sorted(set(old)-set(current)),'modified':sorted(k for k in set(current)&set(old) if current[k]!=old[k]),'errors':errors}

def users():
    if os.name=='nt':
        return {'platform':'windows','users':run(['net','user']),'administrators':run(['net','localgroup','Administrators']),'note':'Local account inventory only; not an Active Directory audit.'}
    users=[]
    try:
        for line in Path('/etc/passwd').read_text().splitlines():
            fields=line.split(':')
            if len(fields)>=7:users.append({'name':fields[0],'uid':int(fields[2]),'gid':int(fields[3]),'shell':fields[6]})
    except OSError as e:return {'error':str(e)}
    return {'platform':'linux','accounts':users,'uid0_accounts':[u['name'] for u in users if u['uid']==0], 'sudo_group':run(['getent','group','sudo']),'wheel_group':run(['getent','group','wheel']),'note':'Review unexpected entries manually. Do not delete competition users.'}

def ports(config, baseline_path, initialize=False):
    if os.name=='nt':output=run(['netstat','-ano','-p','tcp'])
    else:output=run(['ss','-lntup'])
    lines=sorted(set(line.strip() for line in output.splitlines() if line.strip()))
    baseline=Path(baseline_path)
    if initialize:
        if baseline.exists():raise ValueError(f'Baseline already exists: {baseline}. Refusing overwrite.')
        baseline.write_text(json.dumps({'created':dt.datetime.now(dt.timezone.utc).isoformat(),'lines':lines},indent=2),encoding='utf-8')
        return {'initialized':str(baseline),'entries':len(lines),'note':'Baseline includes transient process IDs; expect some noise.'}
    if not baseline.exists():return {'current':lines,'note':'Create a baseline with ports --init-baseline to compare changes.'}
    old=set(json.loads(baseline.read_text(encoding='utf-8'))['lines']);now=set(lines)
    return {'new_lines':sorted(now-old),'missing_lines':sorted(old-now),'note':'Text comparison can include process ID changes and header lines; investigate before acting.'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',default=str(DEFAULT_CONFIG))
    sub=parser.add_subparsers(dest='command',required=True)
    for name in ('health','auth','integrity','users','ports'):
        p=sub.add_parser(name)
        if name in ('integrity','ports'):
            p.add_argument('--init-baseline',action='store_true')
            p.add_argument('--baseline',default=f'{name}_baseline.json')
    args=parser.parse_args()
    try:
        cfg=load_config(args.config)
        if args.command=='health':result=health(cfg)
        elif args.command=='auth':result=auth(cfg)
        elif args.command=='users':result=users()
        elif args.command=='integrity':result=integrity(cfg,args.baseline,args.init_baseline)
        else:result=ports(cfg,args.baseline,args.init_baseline)
        print(json.dumps(result,indent=2))
    except (OSError,ValueError,KeyError,json.JSONDecodeError) as e:
        print(f'ERROR: {e}',file=sys.stderr);sys.exit(1)
if __name__=='__main__':main()
