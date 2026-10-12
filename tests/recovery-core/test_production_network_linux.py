"""Disposable Linux namespace + synthetic Docker metadata, never Harbor runtime."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from test_production_recovery import NetworkFixture, BRIDGE, NID
import harbor_recovery_host as h


def command(args):
    return subprocess.run(args, check=True, capture_output=True, timeout=10).stdout


@unittest.skipUnless(os.environ.get('FDS_RECOVERY_NETNS_TEST') == '1', 'explicit disposable Linux CI only')
class KernelNetworkTests(unittest.TestCase):
    def test_stopped_running_stopped_with_kernel_links_routes_and_namespace_fd(self):
        self.assertEqual(sys.platform, 'linux'); self.assertEqual(os.geteuid(), 0)
        ip = str(Path(shutil.which('ip')).resolve())
        enter = str(Path(shutil.which('nsenter')).resolve())
        read = lambda args: json.loads(command([ip, *args]))
        # The CI step itself must enter an empty network namespace first.
        self.assertEqual({r['ifname'] for r in read(['-j','link','show'])}, {'lo'})
        command([ip,'link','set','lo','up'])
        command([ip,'link','add','ens33','type','dummy'])
        command([ip,'link','set','ens33','up'])
        command([ip,'address','add','192.0.2.2/24','dev','ens33'])
        command([ip,'route','add','default','via','192.0.2.1','dev','ens33'])
        command([ip,'link','add',BRIDGE,'type','bridge'])
        command([ip,'link','set',BRIDGE,'address','02:00:00:00:00:03'])
        command([ip,'address','add','172.18.0.1/16','dev',BRIDGE])
        command([ip,'link','set',BRIDGE,'up'])
        # Pin this disposable bridge's static address explicitly. Production
        # must supply its own reviewed projection; these values cannot enroll it.
        command([ip,'-6','address','add','fe80::ff:fe00:3/64','dev',BRIDGE,'nodad'])
        child = None
        with tempfile.TemporaryDirectory(prefix='recovery-net-',dir='/root') as directory:
            try:
                f = NetworkFixture(running=[]); p = deepcopy(f.policy)
                old = p['directory']; p['directory'] = directory
                p['files'] = {key.replace(old,directory):value for key,value in p['files'].items()}
                p['compose_files'] = [s.replace(old,directory) for s in p['compose_files']]
                p['env_file'] = p['env_file'].replace(old,directory)
                for name,path in [('ip',ip),('nsenter',enter)]:
                    p['tools'][name] = path
                    p['files'][path] = dict(mode=stat.S_IMODE(Path(path).stat().st_mode),gid=0,
                        selinux='synthetic_t',sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest())
                # Wait only for the disposable physical dummy's own DAD; the
                # transition below does not wait for the new veth's DAD.
                until=time.monotonic()+5
                while any(a.get('tentative') for r in read(['-j','-6','address','show','dev','ens33']) for a in r['addr_info']):
                    self.assertLess(time.monotonic(),until);time.sleep(.02)
                original_links = {r['ifname']:h.production_link_projection(r,bridge=r['ifname']==BRIDGE)
                    for r in read(['-j','-d','link','show'])}
                p['network']['interfaces'] = {name:h.digest(row) for name,row in original_links.items()}
                routes = read(['-j','route','show','table','all'])
                for row in routes:
                    if row.get('dev') == BRIDGE:row['flags'] = [v for v in row.get('flags',[]) if v != 'linkdown']
                p['network']['routes_sha256'] = h.digest(sorted(routes,key=h.digest))
                actual = h.LinuxReadOnly()
                provider = h.host_provider(p,f.engine,io=actual,network_reader=f.reader)
                # Ubuntu CI has no SELinux labels. All executable path, owner,
                # mode, hash, fd passing and namespace checks remain real.
                getxattr=os.getxattr
                def labels(target,name,**kwargs):
                    return b'synthetic_t' if name == 'security.selinux' else getxattr(target,name,**kwargs)
                with patch.object(h.os,'getxattr',side_effect=labels):
                    provider._network(time.monotonic()+15)
                    child = subprocess.Popen(['unshare','--net','--','sleep','90'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                    until=time.monotonic()+5
                    while os.stat(f'/proc/{child.pid}/ns/net').st_ino == os.stat('/proc/self/ns/net').st_ino:
                        self.assertLess(time.monotonic(),until);self.assertIsNone(child.poll());time.sleep(.01)
                    command([ip,'link','add','ha0','type','veth','peer','name','hc0'])
                    command([ip,'link','set','ha0','master',BRIDGE])
                    command([ip,'link','set','hc0','netns',str(child.pid)])
                    Path('/proc/sys/net/ipv6/conf/ha0/dad_transmits').write_text('4')
                    command([ip,'link','set','ha0','up'])
                    command([enter,'-t',str(child.pid),'-n','--',ip,'link','set','hc0','up'])
                    peers=actual.peer_links(child.pid,p,time.monotonic()+5)
                    peer=next(r for r in peers if r['ifname']=='hc0')
                    f.running(['log']); row=f.engine.rows['log'];row['State']['Pid']=child.pid
                    row['NetworkSettings']['Networks']['harbor_harbor']['MacAddress']=peer['address']
                    f.network['Containers'][row['Id']]['MacAddress']=peer['address']
                    pending=read(['-j','-6','address','show','dev','ha0'])
                    self.assertTrue(any(a.get('tentative') for r in pending for a in r['addr_info']))
                    def changes(before,after,prefix=''):
                        if isinstance(before,dict) and isinstance(after,dict):
                            return [d for key in set(before)|set(after) for d in changes(before.get(key),after.get(key),prefix+'/'+key)]
                        return [] if before==after else [(prefix,before,after)]
                    for link in read(['-j','-d','link','show']):
                        if link['ifname'] in original_links:
                            self.assertEqual(changes(original_links[link['ifname']],h.production_link_projection(link,bridge=link['ifname']==BRIDGE)),[])
                    provider._network(time.monotonic()+15)
                    until=time.monotonic()+8
                    while any(a.get('tentative') for r in read(['-j','-6','address','show','dev','ha0']) for a in r['addr_info']):
                        self.assertLess(time.monotonic(),until);time.sleep(.05)
                    provider._network(time.monotonic()+15)
                    command([ip,'-6','route','add','fe80::dead/128','dev','ha0'])
                    with self.assertRaisesRegex(ValueError,'NETWORK_DYNAMIC_ROUTE'):
                        provider._network(time.monotonic()+15)
                    command([ip,'-6','route','del','fe80::dead/128','dev','ha0'])
                    command([ip,'link','delete','ha0']);f.running([])
                    provider._network(time.monotonic()+15)
                    command([ip,'route','replace','default','via','192.0.2.254','dev','ens33'])
                    with self.assertRaisesRegex(ValueError,'PRODUCTION_ROUTE_DRIFT'):
                        provider._network(time.monotonic()+15)
                self.assertEqual(f.engine.posts,[])
            finally:
                if child is not None:
                    child.terminate();child.wait(timeout=5);child.stderr.close()

