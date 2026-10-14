#!/usr/bin/env python3
"""Disposable dockerd restart test. Refuses non-CI/nonempty namespaces.

Real: Docker 29.8.2 storage/reload, optional kernel bridge recreation, Engine
start/health, core/executor and POSIX Store. Synthetic: Harbor workload, host
identity, Compose/systemd/AC04/SELinux inputs and installation gate. No production
service or default Docker socket is accessed. No claim of production H3/AC.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'scripts/recovery'), str(ROOT/'tests/recovery-core')]
import harbor_recovery_docker as d
import harbor_recovery_host as h
import harbor_recovery_core as c
from harbor_recovery_store import Store
from harbor_recovery_executor import Executor
from test_host_provider import policy as synthetic_policy, FakeIO
from test_daemon_lifecycle_contract import DNS

def command(args, *, data=None, timeout=60):
    return subprocess.run(args, input=data, check=True, capture_output=True, timeout=timeout).stdout

def wait_for(check, *, seconds=40):
    deadline = time.monotonic()+seconds
    while True:
        if check(): return
        if time.monotonic() >= deadline: raise TimeoutError("DISPOSABLE_WAIT")
        time.sleep(.1)

def main():
    assert sys.platform == 'linux' and os.geteuid() == 0
    assert os.environ.get('FDS_DISPOSABLE_DOCKER_TEST') == '1'
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    assert os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino
    assert json.loads(command(['ip', '-j', 'link', 'show']))[0]['ifname'] == 'lo'
    assert len(json.loads(command(['ip', '-j', 'link', 'show']))) == 1
    binaries = Path(os.environ['FDS_DOCKER_BIN']).resolve()
    assert command([str(binaries/'dockerd'), '--version']).decode().split()[2].rstrip(',') == '29.8.2'
    workload = Path(os.environ['FDS_WORKLOAD']).resolve()
    assert workload.is_file()
    # These addresses live only inside this empty CI namespace.
    command(['ip', 'link', 'set', 'lo', 'up'])
    command(['ip', 'link', 'add', 'ens33', 'type', 'dummy'])
    command(['ip', 'address', 'add', '192.0.2.2/24', 'dev', 'ens33'])
    command(['ip', 'link', 'set', 'ens33', 'up'])
    mode = os.environ.get('FDS_LIFECYCLE_CASE', 'daemon')
    assert mode in ('daemon', 'bridge-recreate')
    version = 4 if mode == 'bridge-recreate' else 3
    daemon = None; log_stream = None
    # /root ensures Store ancestors are trusted. Unique socket/data/exec roots.
    directory = Path(tempfile.mkdtemp(prefix='h3-daemon-ci-', dir='/root'))
    os.chmod(directory, 0o700)
    sock = str(directory/'engine.sock')
    config = directory/'daemon.json'; config.write_text('{}')
    env = dict(os.environ, PATH=str(binaries)+os.pathsep+os.environ['PATH'])
    generation = [uuid.uuid4().hex]
    log_stream = (directory/'dockerd.log').open('wb')
    argv = [str(binaries/'dockerd'), '--config-file', str(config), '--host', 'unix://'+sock,
            '--data-root', str(directory/'data'), '--exec-root', str(directory/'exec'),
            '--pidfile', str(directory/'dockerd.pid'), '--storage-driver', 'overlay2',
            '--iptables=false', '--ip6tables=false', '--ip-forward=false', '--ip-masq=false',
            '--userland-proxy=true']
    cli = lambda *args: command([str(binaries/'docker'), '--host', 'unix://'+sock, *args])
    engine = d.UnixEngine('1.53', socket_path=sock)
    def launch():
        nonlocal daemon
        daemon = subprocess.Popen(argv, stdout=log_stream, stderr=subprocess.STDOUT, env=env)
        def ready():
            assert daemon.poll() is None, 'DISPOSABLE_DOCKER_EXIT'
            try: engine.profile(time.monotonic()+2); return True
            except (OSError, ValueError): return False
        wait_for(ready)
    def stop():
        assert daemon is not None and daemon.poll() is None
        daemon.send_signal(signal.SIGTERM)
        assert daemon.wait(timeout=45) == 0, 'DISPOSABLE_DOCKER_STOP'
    try:
        launch()
        # Offline scratch rootfs; no registry, fixture image has no shell/secrets.
        rootfs = io.BytesIO()
        with tarfile.open(fileobj=rootfs, mode='w') as tar:
            data = workload.read_bytes(); entry = tarfile.TarInfo('workload')
            entry.mode = 0o755; entry.size = len(data); entry.mtime = 0
            tar.addfile(entry, io.BytesIO(data))
        command([str(binaries/'docker'), '--host', 'unix://'+sock, 'import', '--change',
                 'HEALTHCHECK --interval=1s --timeout=1s --retries=3 CMD ["/workload", "health"]',
                 '-', 'h3-fixture:local'],
                data=rootfs.getvalue())
        network_id = cli('network', 'create', '--driver', 'bridge', '--subnet', '172.19.0.0/16',
                         '--opt', 'com.docker.network.bridge.name=br-harbor', 'harbor_harbor').decode().strip()
        ids = {}
        for name in ('log', *c.ORDER):
            args = ['create', '--name', 'ci-'+name, '--network', 'harbor_harbor',
                    '--label', 'com.docker.compose.project=harbor',
                    '--label', 'com.docker.compose.service='+name,
                    '--restart', 'always' if name == 'log' else 'no']
            if name == 'log': args += ['--publish', '127.0.0.1:1514:1514']
            else: args += ['--log-driver', 'syslog', '--log-opt', 'syslog-address='+c.ENDPOINT]
            if name in ('proxy','portal'): args += ['--stop-signal', 'SIGQUIT']
            args += ['h3-fixture:local', '/workload', 'log' if name == 'log' else 'app']
            ids[name] = cli(*args).decode().strip()
        for cid in ids.values(): cli('start', cid)
        def rows(): return {n: engine.inspect(cid, time.monotonic()+5) for n,cid in ids.items()}
        wait_for(lambda: all(r['State']['Health']['Status']=='healthy' for r in rows().values()))
        before_rows = rows()
        policy = synthetic_policy(); policy['version'] = version; policy['socket'] = sock
        old_directory = policy['directory']; policy['directory'] = str(directory)
        policy['files'] = {key.replace(old_directory,str(directory)): value for key,value in policy['files'].items()}
        policy['compose_files'] = [p.replace(old_directory,str(directory)) for p in policy['compose_files']]
        policy['env_file'] = policy['env_file'].replace(old_directory,str(directory))
        policy['engine_profile'] = h.engine_profile(engine.profile(time.monotonic()+10))
        actual = h.LinuxReadOnly()
        ip = str(Path(shutil.which('ip')).resolve()); nsenter = str(Path(shutil.which('nsenter')).resolve())
        for name, path in [('ip',ip), ('nsenter',nsenter)]:
            policy['tools'][name] = path
            policy['files'][path] = dict(mode=stat.S_IMODE(Path(path).stat().st_mode), gid=0,
                selinux='synthetic_t', sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest())
        read = lambda args: json.loads(command([ip,*args]))
        network_reader = h.ProductionNetworkReader(dict(policy, network={'bridges': {network_id: {}}}))
        initial_network = network_reader.read(network_id, time.monotonic()+10)
        initial_default = network_reader.read('bridge', time.monotonic()+10)
        links = h._net_link_projection(read(['-j','-d','link','show']))
        endpoints = {cid: ep['MacAddress'] for cid, ep in initial_network['Containers'].items()}
        peers = {r['Id']: json.loads(command([nsenter, '-t', str(r['State']['Pid']), '-n',
                                             '--', ip, '-j','-d','link','show'])) for r in before_rows.values()}
        owned = h._net_owned_links(links, endpoints, peers, bridge='br-harbor')
        wait_for(lambda: not any(a.get('tentative') for r in read(['-j','-6','address','show'])
                                 for a in r.get('addr_info',[])))
        stable = h._net_route_projection(read(['-j','route','show','table','all']), owned)
        for row in stable:
            if row.get('dev') in ('docker0','br-harbor') and 'flags' in row:
                row['flags'] = [f for f in row['flags'] if f != 'linkdown']
        addresses = read(['-j','-6','address','show'])
        modes = {name: ('eui64' if any(r['ifname']==name and r.get('addr_info') for r in addresses)
                        else 'absent') for name in ('docker0','br-harbor')}
        if version == 4:
            stable = h.production_bridge_route_projection(stable,links,addresses,modes)
        policy['network'] = dict(
            physical_interfaces=['ens33'],
            interfaces={r['ifname']:d.digest(h.production_link_projection(r,
                        bridge=r['ifname'] in ('docker0','br-harbor'),version=version)) for r in links if r['ifname'] not in owned},
            routes_sha256=d.digest(sorted(stable,key=d.digest)), ids=ids,
            bridges={network_id:dict(name='harbor_harbor', bridge='br-harbor',
                                     sha256=d.digest(h._net_network_projection(initial_network)))},
            default_bridge=dict(name='bridge',bridge='docker0',
                                sha256=d.digest(h.default_bridge_projection(initial_default))))
        if version == 4:policy['network']['bridge_ipv6']=modes
        fake = FakeIO(policy)
        fake.physical_interfaces = lambda:['ens33']
        # All IP and netns calls are real. Only workstation-unavailable file
        # SELinux pins are simulated; peer_links retains owner/hash/fd checks.
        fake.peer_links = lambda pid,p,deadline: actual.peer_links(pid,p,deadline)
        normal = fake.run
        def run(argv,cwd,deadline):
            if argv[0] == ip: return command(argv)
            output = normal(argv,cwd,deadline)
            if 'systemctl' in argv[0]:
                output = output.replace(('InvocationID='+'a'*32).encode(),
                                        ('InvocationID='+generation[0]).encode())
            return output
        fake.run = run
        host = h.host_provider(policy,engine,io=fake,network_reader=network_reader)
        plan = c.Plan(ids,{n:d.project(r,n,r['Id'],'harbor',fingerprint_version=2).fingerprint
                         for n,r in before_rows.items()}, {n:60 for n in c.ORDER},
                      max_age_seconds=30,
                      execution_binding=d.execution_binding(host.binding,'harbor',engine.binding,fingerprint_version=2))
        store_dir = directory/'store'; store_dir.mkdir(mode=0o700)
        store = Store(str(store_dir)); core = c.Controller(plan)
        backend = d.DockerBackend(plan,engine,host,host.binding,'harbor',fingerprint_version=2)
        # FakeIO policy has a real engine profile; its other inputs are fixtures.
        getxattr = os.getxattr
        from unittest.mock import patch
        def labels(target,name,**kwargs):
            return b'synthetic_t' if name=='security.selinux' else getxattr(target,name,**kwargs)
        with patch.object(h.os,'getxattr',side_effect=labels):
            before = backend.observe()
            with store.locked():
                store.initialize()
                state = core.arm(c.State(), before, time.monotonic()).state
                assert state.desired == 'RUN', state.reason
                store.save(state)
            stop()
            if mode == 'bridge-recreate':
                # Disposable CI namespace only. Docker metadata/IDs persist;
                # remove kernel bridges as a real OS reboot would, not Docker networks.
                stopped = read(['-j','-d','link','show'])
                assert {r['ifname'] for r in stopped} == {'lo','ens33','docker0','br-harbor'}
                for name in ('docker0','br-harbor'):
                    command([ip,'link','delete',name,'type','bridge'])
                fake.stamp['boot'] = str(uuid.uuid4())  # boot observation is synthetic in this test.
            generation[0] = uuid.uuid4().hex; launch()
            wait_for(lambda: rows()['log']['State']['Health']['Status']=='healthy')
            reloaded = rows()
            assert all(reloaded[n]['State']['Status']=='exited' for n in c.ORDER)
            current_default = network_reader.read('bridge',time.monotonic()+10)
            assert current_default['Id'] != initial_default['Id'], 'DEFAULT_BRIDGE_NOT_RECREATED'
            assert current_default['Created'] != initial_default['Created']
            assert network_reader.read(network_id,time.monotonic()+10)['Id'] == network_id
            if mode == 'bridge-recreate':
                after_links={r['ifname']:r for r in read(['-j','-d','link','show'])}
                for row in links:
                    if row['ifname'] in ('docker0','br-harbor'):
                        assert row['address'] != after_links[row['ifname']]['address'], 'BRIDGE_MAC_NOT_RECREATED'
            after = backend.observe()
            assert before.daemon != after.daemon
            if mode == 'bridge-recreate':assert before.boot != after.boot
            assert {n:r.fingerprint for n,r in before.containers.items()} == {
                n:r.fingerprint for n,r in after.containers.items()}
            calls = []; original = engine.start
            def start(cid,deadline):
                result = original(cid,deadline); calls.append((cid,result)); return result
            engine.start = start
            executor = Executor(core,store,backend,gate=lambda:None); executor.open()
            deadline = time.monotonic()+240
            while True:
                executor.tick()
                with store.locked(): state=store.load()
                assert state.desired == 'RUN', state.reason
                if len(calls)==9 and state.pending is None and state.health_wait is None: break
                assert time.monotonic()<deadline, 'DISPOSABLE_RECOVERY_TIMEOUT'
                time.sleep(.2)
            assert calls == [(ids[n],'ok') for n in c.ORDER], 'START_ORDER_OR_DUPLICATE'
            for _ in range(3): executor.tick()
            # New process-equivalent Store/Executor opening cannot issue again.
            reopened = Store(str(store_dir))
            follow = Executor(core,reopened,backend,gate=lambda:None); follow.open(); follow.tick()
            assert len(calls)==9
            assert all(r['State']['Health']['Status']=='healthy' for r in rows().values())
            with reopened.locked():
                final = reopened.load()
                assert final.desired == 'RUN' and final.pending is None and final.health_wait is None
            assert len(list(store_dir.glob('intent-*.json')))==9
            assert not list(store_dir.glob('*.pending'))
            dns_changes = {n:[k for k in DNS if before_rows[n]['HostConfig'][k] != reloaded[n]['HostConfig'][k]]
                           for n in ids}
            print(json.dumps(dict(status='PASS',scope='DISPOSABLE_DOCKER_INTEGRATION_NOT_PRODUCTION_AC',
                docker=policy['engine_profile']['version'],lifecycle_case=mode,host_version=version,
                real_vm_reboot=False,kernel_bridges_recreated=mode=='bridge-recreate',
                default_id_changed=True,custom_id_preserved=True,
                dns_representation_changes=dns_changes,starts=9,claims=9,pending=0,healthy=10,
                store_reopen_duplicate_starts=0),sort_keys=True))
    except Exception:
        # CI fixture log only; contains no Harbor/private data.
        log_stream.flush()
        print((directory/'dockerd.log').read_text(errors='replace')[-6000:],file=sys.stderr)
        raise
    finally:
        if daemon is not None and daemon.poll() is None:
            daemon.send_signal(signal.SIGTERM)
            daemon.wait(timeout=45)
        log_stream.close()
        # Preserve data/claims in the disposable job; runner teardown removes it.
        print('Disposable evidence preserved at '+str(directory),file=sys.stderr)

if __name__ == '__main__': main()

