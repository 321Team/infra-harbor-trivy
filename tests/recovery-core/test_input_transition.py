"""Synthetic transactions plus real Linux temporary-file operations; no guest."""
from contextlib import contextmanager, redirect_stdout
from copy import deepcopy
from dataclasses import asdict
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_boot_bridge_contract as boot_fixture
from test_host_provider import BOOT, LABEL
from harbor_recovery_bundle import bound_host_digest
from harbor_recovery_core import Controller, Plan, State, ORDER
from harbor_recovery_docker import execution_binding, UnixEngine
from harbor_recovery_store import encode

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.util.spec_from_file_location('input_transition_subject',
    ROOT / 'scripts/preparation/harbor_input_transition.py')
x = importlib.util.module_from_spec(loader); loader.loader.exec_module(x)


class MemoryFS:
    """No claims about OS metadata or SELinux; Linux tests cover real syscalls."""
    def __init__(self):
        self.dirs, self.data, self.fdkeys = {}, {}, {}
        self.next, self.operations = 10, []
        self.after = lambda step: None
        self.locked = False
        self.replaced = None

    @contextmanager
    def directory(self, path, spec, deadline):
        if path not in self.dirs:
            self.next += 1; self.dirs[path] = self.next
        yield self.dirs[path] + (1000 if self.replaced == path else 0)

    def key(self, path):
        return self.dirs[str(PurePosixPath(path).parent)], PurePosixPath(path).name

    def absent(self, fd, name):
        if (fd, name) in self.data:
            raise ValueError('EXISTING_TARGET')

    @contextmanager
    def create(self, fd, name, context):
        self.absent(fd, name)
        self.next += 1; fileno = self.next
        self.fdkeys[fileno] = (fd, name); self.data[(fd, name)] = bytearray()
        yield fileno

    @contextmanager
    def locks(self, fd, context):
        if self.locked:
            raise BlockingIOError('busy')
        self.locked = True
        try: yield lambda:None
        finally: self.locked = False

    def names(self, fd):
        return {name for parent, name in self.data if parent == fd}

    def metadata(self, *args): pass

    def write_all(self, fd, raw, deadline):
        self.data[self.fdkeys[fd]].extend(raw)

    def payload(self, fd, entry, raw, deadline):
        self.absent(fd, PurePosixPath(entry['target']).name)
        self.data[self.key(entry['target'])] = raw
        self.operations.append(entry['file']); self.after(entry['file'])

    def read(self, fd, entry, deadline):
        raw = self.data[(fd, PurePosixPath(entry['target']).name)]
        if len(raw) != entry['bytes'] or x.check.sha(raw) != entry['sha256']:
            raise ValueError('FILE_CHANGED')
        return bytes(raw)

    def verify(self, fd, entry, raw, deadline):
        if self.read(fd, entry, deadline) != raw:
            raise ValueError('FILE_CHANGED')

    def preserve(self, fd, entry, destination, deadline):
        self.absent(fd, destination)
        self.read(fd, entry, deadline)
        self.data[(fd, destination)] = self.data.pop((fd, PurePosixPath(entry['target']).name))
        self.operations.append('preserve'); self.after('preserve')

    def fstat(self, fd):
        return SimpleNamespace(st_dev=1, st_ino=fd)

    def stat(self, name, *, dir_fd, **kwargs):
        fd = next(fd for fd, key in self.fdkeys.items() if key == (dir_fd, name))
        return self.fstat(fd)

    def journal(self):
        rows = [v for (fd, name), v in self.data.items() if name.endswith('.jsonl')]
        return [json.loads(line) for line in bytes(rows[0]).splitlines()] if rows else []


class Fixture:
    def setUp(self):
        self.builder = boot_fixture.BootPackageTests().fixture()
        self.old, _ = self.builder.prepare()
        self.builder.obj['host_policy']['nft_sha256'] = '9' * 64
        self.builder.obj['store']['path'] = '/var/lib/fds-harbor-recovery/instances/' + 'e' * 32
        self.builder.runtime['bundle_path'] = '/etc/fds-harbor-recovery/bundles/new.json'
        self.rebuild()
        self.fs = MemoryFS(); self.wall = 150; self.now = 0; self.calls = 0
        self.before = lambda count: None
        a, b, ea, eb = x.packages(self.old, self.old_sha, self.new, self.new_sha)
        self.a, self.b, self.ea, self.eb = a, b, ea, eb
        self.state = State(desired='HOLD', reason='OPERATOR_HOLD', boot=BOOT, daemon='d'*32,
            plan_digest=Controller(Plan(**a['plan'])).plan_digest())
        state_raw = encode(self.state)
        self.sealed = {'manager.lock':b'', 'controller.lock':b'', 'state.json':state_raw,
                       'intent-00000000000000000001.json':b'preserved original claim'}
        journal = '/var/lib/fds-harbor-recovery/install-receipts/' + 'c'*32 + '.jsonl'
        parents = {str(PurePosixPath(e['target']).parent) for e in (*ea.values(), *eb.values())}
        parents.update((a['store']['path'], b['store']['path'], str(PurePosixPath(journal).parent)))
        self.r = dict(schema='fds.harbor.input-transition-request.v1', operation='SAME_CODE_NFT_INPUT_ONLY',
            old_plan_sha256=self.old_sha, new_plan_sha256=self.new_sha, hostname=a['host_policy']['hostname'],
            product_uuid=a['host_policy']['product_uuid'], boot_id=BOOT, daemon_invocation_id='d'*32,
            not_before_epoch=100, expires_epoch=200, receipt_path=journal, receipt_context=LABEL,
            preserved_launch_path='/etc/fds-harbor-recovery/launch.'+'f'*32+'.preserved.json',
            directories={p:dict(mode=0o700, gid=0, selinux=LABEL) for p in parents},
            old_store_files={n:dict(bytes=len(v), sha256=x.check.sha(v)) for n,v in self.sealed.items()},
            containers={n:dict(pid=100+i, started_at='2026-01-01T00:00:00Z', restart_count=0)
                        for i,n in enumerate(a['plan']['ids'])})
        for p in parents:
            with self.fs.directory(p, {}, 50): pass
        for name, entry in ea.items():
            self.fs.data[self.fs.key(entry['target'])] = self.old[name]
        for name, raw in self.sealed.items():
            self.fs.data[(self.fs.dirs[a['store']['path']], name)] = raw
        self.original = deepcopy(self.fs.data)

    def rebuild(self):
        obj = self.builder.obj; p = obj['host_policy']
        obj['plan']['execution_binding'] = execution_binding(bound_host_digest(obj), 'harbor',
            UnixEngine(p['api_version'], socket_path=p['socket']).binding, fingerprint_version=2)
        self.new, _ = self.builder.prepare()
        self.old_sha = x.check.sha(self.old['INSTALL_PLAN.json'])
        self.new_sha = x.check.sha(self.new['INSTALL_PLAN.json'])

    def execute(self, **kw):
        def preflight(r, deadline):
            self.calls += 1; self.before(self.calls)
        raw = x.base.encode(self.r)
        options = dict(execute=True, fs=self.fs, preflight=preflight,
                       clock=lambda:self.now, wall=lambda:self.wall)
        options.update(kw)
        with patch.object(x.os, 'fstat', side_effect=self.fs.fstat), \
             patch.object(x.os, 'stat', side_effect=self.fs.stat), patch.object(x.os, 'fsync'), \
             patch.object(x.check, 'stamp', side_effect=lambda row:(row.st_dev,row.st_ino)):
            return x.transition(self.old, self.old_sha, self.new, self.new_sha, raw,
                                x.check.sha(raw), 50, **options)

    def keep_originals(self):
        for key, value in self.original.items():
            if key != self.fs.key(x.LAUNCH):
                self.assertEqual(self.fs.data[key], value)


class ContractTests(Fixture, unittest.TestCase):
    def test_valid_same_code_packages_verified_independently(self):
        x.packages(self.old,self.old_sha,self.new,self.new_sha)
        with self.assertRaisesRegex(ValueError,'PLAN_HASH'):
            x.packages(self.old,'0'*64,self.new,self.new_sha)
        with self.assertRaisesRegex(ValueError,'PLAN_HASH'):
            x.packages(self.old,self.old_sha,self.new,'0'*64)

    def test_unchanged_nft_or_store_and_changed_budget_or_label_rejected(self):
        original=deepcopy(self.builder.obj)
        changes=[lambda o:o['host_policy'].update(nft_sha256=self.a['host_policy']['nft_sha256']),
                 lambda o:o['store'].update(path=self.a['store']['path']),
                 lambda o:o['plan'].update(start_seconds=61),
                 lambda o:o['store'].update(file_context='system_u:object_r:other_t:s0')]
        for change in changes:
            self.builder.obj=deepcopy(original);change(self.builder.obj);self.rebuild()
            with self.subTest(change=change),self.assertRaises(ValueError):
                x.packages(self.old,self.old_sha,self.new,self.new_sha)

    def test_code_change_cannot_hide_in_valid_rehashed_package(self):
        name='harbor_recovery_core.py'
        self.builder.sources[name]+=b'\n# different source\n'
        value=x.check.sha(self.builder.sources[name]);obj=self.builder.obj
        obj['source']['files'][name]=value
        obj['host_policy']['files'][obj['source']['directory']+'/'+name]['sha256']=value
        self.rebuild()
        with self.assertRaisesRegex(ValueError,'CODE_CHANGED'):
            x.packages(self.old,self.old_sha,self.new,self.new_sha)

    def test_missing_explicit_execution_no_mutation(self):
        with self.assertRaisesRegex(ValueError,'EXPLICIT'):self.execute(execute=False)
        self.assertEqual(self.original,self.fs.data)

    def test_request_rejects_extra_scope_bad_identity_window_paths_and_seal(self):
        cases=[lambda r:r.update(operation='START'),lambda r:r.update(extra=1),
            lambda r:r.update(old_plan_sha256='0'*64),lambda r:r.update(daemon_invocation_id='bad'),
            lambda r:r.update(boot_id='bad'),lambda r:r.update(not_before_epoch=True),
            lambda r:r.update(expires_epoch=149),lambda r:r.update(receipt_path='/root/file'),
            lambda r:r.update(preserved_launch_path='/etc/another'),
            lambda r:r['old_store_files'].update({'../escape':dict(bytes=0,sha256='0'*64)}),
            lambda r:r['old_store_files']['state.json'].update(bytes=-1),
            lambda r:r['old_store_files'].pop('manager.lock'),
            lambda r:r['containers']['log'].update(pid=0),
            lambda r:r['directories'].pop(self.a['store']['path'])]
        original=deepcopy(self.r)
        for change in cases:
            self.r=deepcopy(original);change(self.r)
            with self.subTest(change=change),self.assertRaises(ValueError):self.execute()
            self.assertEqual(self.original,self.fs.data)


P2_ROW = {'dst': '10.20.0.0/16', 'gateway': '10.1.93.51', 'dev': 'ens160', 'flags': []}
OTHER_ROW = {'dst': '10.1.93.0/24', 'dev': 'ens160', 'protocol': 'kernel', 'scope': 'link',
             'prefsrc': '10.1.93.54', 'flags': []}


class RouteContractTests(Fixture, unittest.TestCase):
    """infra-rosa#12 C3: nft + routes digest input change for the fixed P2 return route only."""
    def route_change(self, value='7' * 64):
        self.builder.obj['host_policy']['network']['routes_sha256'] = value
        self.rebuild()

    def route_request(self, change='ADD_P2_RETURN'):
        self.r.update(operation=x.NFT_ROUTE, route_change=change, new_plan_sha256=self.new_sha)

    def test_route_digest_change_is_rejected_by_nft_only_operation(self):
        self.route_change()
        with self.assertRaisesRegex(ValueError, 'SCOPE_CHANGED'):
            x.packages(self.old, self.old_sha, self.new, self.new_sha)

    def test_nft_route_operation_accepts_only_nft_and_routes_digest(self):
        self.route_change()
        x.packages(self.old, self.old_sha, self.new, self.new_sha, x.NFT_ROUTE)

    def test_nft_route_operation_requires_a_routes_change(self):
        with self.assertRaisesRegex(ValueError, 'NEW_ROUTE_INPUT_REQUIRED'):
            x.packages(self.old, self.old_sha, self.new, self.new_sha, x.NFT_ROUTE)

    def test_nft_route_operation_still_rejects_any_other_change(self):
        changes = [lambda o: o['plan'].update(start_seconds=61),
                   lambda o: o['host_policy']['network'].update(physical_interfaces=['ens999']),
                   lambda o: o['store'].update(file_context='system_u:object_r:other_t:s0')]
        original = deepcopy(self.builder.obj)
        for change in changes:
            self.builder.obj = deepcopy(original)
            self.builder.obj['host_policy']['network']['routes_sha256'] = '7' * 64
            change(self.builder.obj)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.rebuild()
                x.packages(self.old, self.old_sha, self.new, self.new_sha, x.NFT_ROUTE)

    def test_unknown_operation_is_rejected_before_package_comparison(self):
        with self.assertRaisesRegex(ValueError, 'REQUEST_SCOPE'):
            x.packages(self.old, self.old_sha, self.new, self.new_sha, 'SAME_CODE_ANY_INPUT')

    def test_route_transaction_writes_only_inputs_and_reports_route_unchanged(self):
        self.route_change(); self.route_request()
        result = self.execute()
        self.assertEqual(result['status'], 'INPUT_FILES_TRANSITIONED_ONLY')
        self.assertEqual((result['operation'], result['route'], result['firewall']),
                         (x.NFT_ROUTE, 'NOT_CHANGED', 'NOT_CHANGED'))
        self.assertEqual(self.fs.operations, ['bundle.json', 'preserve', 'launch.json'])
        self.keep_originals()

    def test_route_request_field_rules(self):
        self.route_change()
        cases = [lambda r: r.update(operation=x.NFT_ROUTE),                       # route_change missing
                 lambda r: r.update(operation=x.NFT_ROUTE, route_change='ADD_ANY'),
                 lambda r: r.update(operation=x.NFT_ROUTE, route_change=['ADD_P2_RETURN']),
                 lambda r: r.update(route_change='ADD_P2_RETURN'),                # NFT_ONLY + extra field
                 lambda r: r.update(operation=x.NFT_ONLY)]                         # routes changed, wrong op
        original = deepcopy(self.r)
        for change in cases:
            self.r = deepcopy(original); self.r.update(new_plan_sha256=self.new_sha); change(self.r)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.execute()
            self.assertEqual(self.original, self.fs.data)


class P2RouteCheckTests(unittest.TestCase):
    def test_add_accepts_exactly_the_fixed_route(self):
        x.p2_route_check([OTHER_ROW, P2_ROW], 'ADD_P2_RETURN')
        x.p2_route_check([OTHER_ROW, dict(P2_ROW, table='main', type='unicast')], 'ADD_P2_RETURN')

    def test_add_rejects_missing_duplicate_or_different_route(self):
        cases = [[OTHER_ROW], [P2_ROW, dict(P2_ROW, metric=100)],
                 [dict(P2_ROW, gateway='10.1.93.254')], [dict(P2_ROW, dev='docker0')],
                 [dict(P2_ROW, table='local')], [dict(P2_ROW, type='blackhole')],
                 [dict(P2_ROW, nexthops=[{'gateway': '10.1.93.51'}])], 'not-a-list', [P2_ROW, 'row']]
        for routes in cases:
            with self.subTest(routes=routes), self.assertRaises(ValueError):
                x.p2_route_check(routes, 'ADD_P2_RETURN')

    def test_wider_or_other_destination_is_not_the_p2_route(self):
        with self.assertRaisesRegex(ValueError, 'P2_ROUTE_SET'):
            x.p2_route_check([dict(P2_ROW, dst='10.20.0.0/15')], 'ADD_P2_RETURN')

    def test_remove_requires_absence(self):
        x.p2_route_check([OTHER_ROW], 'REMOVE_P2_RETURN')
        with self.assertRaisesRegex(ValueError, 'P2_ROUTE_PRESENT'):
            x.p2_route_check([OTHER_ROW, P2_ROW], 'REMOVE_P2_RETURN')

    def test_unknown_change_is_rejected(self):
        with self.assertRaises(ValueError):
            x.p2_route_check([P2_ROW], 'REPLACE_P2_RETURN')


class TransactionTests(Fixture, unittest.TestCase):
    def test_only_two_new_inputs_preserve_launch_and_all_old_claims(self):
        with patch('builtins.exec',side_effect=AssertionError('candidate import')):
            result=self.execute()
        self.assertEqual(result['status'],'INPUT_FILES_TRANSITIONED_ONLY')
        self.assertEqual(self.fs.operations,['bundle.json','preserve','launch.json'])
        self.assertEqual(self.fs.data[self.fs.key(self.r['preserved_launch_path'])],self.old['launch.json'])
        self.keep_originals()
        self.assertEqual(self.fs.names(self.fs.dirs[self.b['store']['path']]),set())
        self.assertEqual(self.fs.journal()[-1]['stage'],'INPUT_FILES_TRANSITIONED_ONLY')
        self.assertTrue(all(result[k]=='NOT_RUN' for k in ('runtime','service_lifecycle','store_initialization')))

    def test_running_manager_preflight_failure_no_writes(self):
        self.before=lambda n:(_ for _ in ()).throw(ValueError('MANAGER_NOT_DISABLED_STOPPED'))
        with self.assertRaisesRegex(ValueError,'MANAGER'):self.execute()
        self.assertEqual(self.original,self.fs.data)

    def test_busy_old_store_no_writes(self):
        self.fs.locked=True
        with self.assertRaises(BlockingIOError):self.execute()
        self.assertEqual(self.original,self.fs.data)

    def test_changed_claim_missing_file_and_populated_new_store_block(self):
        for kind in ('changed','missing','new'):
            self.fs.data=deepcopy(self.original)
            if kind=='new':self.fs.data[(self.fs.dirs[self.b['store']['path']],'state.json')]=b'x'
            else:
                key=(self.fs.dirs[self.a['store']['path']],'intent-00000000000000000001.json')
                if kind=='changed':self.fs.data[key]=b'changed'
                else:del self.fs.data[key]
            before=deepcopy(self.fs.data)
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.execute()
            self.assertEqual(before,self.fs.data)

    def test_valid_seal_of_run_state_still_blocks(self):
        self.state.desired='RUN';self.state.last_now=1
        raw=encode(self.state)
        self.r['old_store_files']['state.json']=dict(bytes=len(raw),sha256=x.check.sha(raw))
        self.fs.data[(self.fs.dirs[self.a['store']['path']],'state.json')]=raw
        with self.assertRaisesRegex(ValueError,'NOT_HELD'):self.execute()
        self.assertEqual(self.fs.operations,[])

    def test_error_hold_and_unsettled_pending_are_not_operator_hold(self):
        self.state.reason='START_FAILED'
        raw=encode(self.state)
        self.r['old_store_files']['state.json']=dict(bytes=len(raw),sha256=x.check.sha(raw))
        self.fs.data[(self.fs.dirs[self.a['store']['path']],'state.json')]=raw
        with self.assertRaisesRegex(ValueError,'NOT_HELD'):self.execute()
        self.setUp()
        self.r['old_store_files']['state-'+'a'*32+'.pending']=dict(bytes=0,sha256=x.check.sha(b''))
        with self.assertRaisesRegex(ValueError,'STORE_ENTRY'):self.execute()
        self.assertEqual(self.fs.operations,[])

    def test_each_mutation_failure_keeps_partial_and_stops_without_next_step(self):
        for step,expected in [('bundle.json',['bundle.json']),('preserve',['bundle.json','preserve']),
                             ('launch.json',['bundle.json','preserve','launch.json'])]:
            self.setUp()
            def fail(actual):
                if actual==step:raise OSError('injected failure')
            self.fs.after=fail
            with self.subTest(step=step),self.assertRaises(OSError):self.execute()
            self.assertEqual(self.fs.operations,expected);self.keep_originals()
            self.assertEqual(self.fs.journal()[-1]['stage'],'STOP_PRESERVE_PARTIAL')
            if step=='preserve':self.assertNotIn(self.fs.key(x.LAUNCH),self.fs.data)

    def test_window_and_monotonic_deadline_after_bundle_prevent_preserve(self):
        for kind in ('wall','monotonic'):
            self.setUp()
            def expire(step):
                if kind=='wall':self.wall=200
                else:self.now=50
            self.fs.after=expire
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.execute()
            self.assertEqual(self.fs.operations,['bundle.json']);self.keep_originals()
            self.assertEqual(self.fs.data[self.fs.key(x.LAUNCH)],self.old['launch.json'])

    def test_post_bundle_host_drift_prevents_launch_change(self):
        self.before=lambda count:(_ for _ in ()).throw(ValueError('HOST_DRIFT')) if count==3 else None
        with self.assertRaisesRegex(ValueError,'HOST_DRIFT'):self.execute()
        self.assertEqual(self.fs.operations,['bundle.json']);self.keep_originals()

    def test_store_mutation_after_preserve_prevents_new_launch(self):
        def change(step):
            if step=='preserve':self.fs.data[(self.fs.dirs[self.a['store']['path']],'manager.lock')]=b'x'
        self.fs.after=change
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual(self.fs.operations,['bundle.json','preserve'])
        self.assertNotIn(self.fs.key(x.LAUNCH),self.fs.data)

    def test_parent_replacement_after_bundle_prevents_preserve(self):
        self.fs.after=lambda step:setattr(self.fs,'replaced','/etc/fds-harbor-recovery')
        with self.assertRaisesRegex(ValueError,'DIRECTORY_REPLACED'):self.execute()
        self.assertEqual(self.fs.operations,['bundle.json'])

    def test_existing_receipt_bundle_or_preserved_name_not_overwritten(self):
        for path in (self.r['receipt_path'],self.eb['bundle.json']['target'],self.r['preserved_launch_path']):
            self.fs.data=deepcopy(self.original);self.fs.data[self.fs.key(path)]=b'existing'
            before=deepcopy(self.fs.data)
            with self.subTest(path=path),self.assertRaises(ValueError):self.execute()
            self.assertEqual(self.fs.data,before)

    def test_success_cannot_replay(self):
        self.execute();before=deepcopy(self.fs.data)
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual(before,self.fs.data)

    def test_cli_sanitizes_failure(self):
        out=io.StringIO()
        with patch.object(x.check,'read_package',side_effect=ValueError('PRIVATE_SECRET')),redirect_stdout(out):
            rc=x.main(['--old-package','old','--old-plan-sha256','a'*64,'--package','new',
                '--plan-sha256','b'*64,'--request','r','--request-sha256','c'*64,'--timeout','60','--execute'])
        self.assertEqual(rc,2);self.assertNotIn('PRIVATE',out.getvalue())


class PreflightTests(unittest.TestCase):
    def fixture(self):
        f=boot_fixture.BootFixture(running=(*ORDER,'log'))
        for row in f.engine.rows.values():
            row['State'].update(StartedAt='2026-01-01T00:00:00Z');row['RestartCount']=0
        plan=f.plan();stamp=f.read()
        bundle=dict(host_policy=f.policy,plan=asdict(plan),manager=dict(fragment='unused',dropins=[]))
        request=dict(boot_id=stamp.boot,daemon_invocation_id=stamp.daemon,containers={
            n:dict(pid=row['State']['Pid'],started_at=row['State']['StartedAt'],restart_count=0)
            for n,row in f.engine.rows.items()})
        probe=x.Preflight(bundle,clock=lambda:10,engine=f.engine,host=f.host,stopped=lambda _:None,probe=lambda _:True)
        return f,request,probe

    def test_real_projector_full_host_checks_are_get_only(self):
        f,r,p=self.fixture();p(r,100);self.assertEqual(f.engine.posts,[])

    def test_pid_start_count_policy_health_fingerprint_and_nft_drift_block(self):
        changes=[lambda f:f.engine.rows['postgresql']['State'].update(Pid=999),
            lambda f:f.engine.rows['postgresql']['State'].update(StartedAt='later'),
            lambda f:f.engine.rows['postgresql'].update(RestartCount=1),
            lambda f:f.engine.rows['postgresql']['HostConfig']['RestartPolicy'].update(Name='always'),
            lambda f:f.engine.rows['postgresql']['State']['Health'].update(Status='unhealthy'),
            lambda f:f.engine.rows['postgresql']['Config'].update(User='changed'),
            lambda f:f.io.outputs.update(nft=b'{"nftables":[]}')]
        for change in changes:
            f,r,p=self.fixture();change(f)
            with self.subTest(change=change),self.assertRaises(ValueError):p(r,100)
            self.assertEqual(f.engine.posts,[])

    def route_fixture(self, sequence):
        f, r, p = self.fixture()
        reads = iter(sequence)
        p.routes = lambda deadline: next(reads)
        r.update(operation=x.NFT_ROUTE, route_change='ADD_P2_RETURN')
        return f, r, p

    def test_nft_route_preflight_checks_route_at_first_and_last_host_read(self):
        f, r, p = self.route_fixture([[P2_ROW], [P2_ROW]])
        p(r, 100)
        self.assertEqual(f.engine.posts, [])

    def test_route_missing_or_changed_during_preflight_blocks(self):
        for sequence in ([[]], [[P2_ROW], []], [[P2_ROW], [dict(P2_ROW, gateway='10.1.93.1')]]):
            f, r, p = self.route_fixture(sequence)
            with self.subTest(sequence=sequence), self.assertRaises(ValueError):
                p(r, 100)
            self.assertEqual(f.engine.posts, [])

    def test_nft_only_preflight_does_not_read_routes(self):
        f, r, p = self.fixture()
        p.routes = lambda deadline: self.fail('routes read for NFT_ONLY')
        p(r, 100)

    def test_wrong_boot_or_daemon_blocks(self):
        for field in ('boot_id','daemon_invocation_id'):
            f,r,p=self.fixture();r[field]='wrong'
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'GENERATION'):p(r,100)

    def test_app_restart_during_last_host_probe_is_not_freshened(self):
        f,r,p=self.fixture();normal=p.host;calls=[]
        def host(end):
            stamp=normal(end);calls.append(1)
            if len(calls)==2:f.engine.rows['redis']['RestartCount']=1
            return stamp
        p.host=host
        with self.assertRaisesRegex(ValueError,'APP_GENERATION'):p(r,100)
        self.assertEqual(f.engine.posts,[])


@unittest.skipUnless(sys.platform=='linux','real Linux descriptors and renameat2')
class LinuxFilesTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.fd=os.open(self.tmp.name,os.O_RDONLY|os.O_DIRECTORY);self.addCleanup(os.close,self.fd)
        self.fs=x.TransitionFiles(uid=os.getuid(),gid=os.getgid())
        self.fs.attrs=lambda *args:None  # SELinux remains a separate actual-host requirement.
        self.end=time.monotonic()+10
        self.raw=b'old launch\n';self.entry=dict(target='/synthetic/launch.json',mode=0o400,
            selinux=LABEL,bytes=len(self.raw),sha256=x.check.sha(self.raw))
        self.fs.payload(self.fd,self.entry,self.raw,self.end)

    def test_preserves_exact_inode_and_bytes_without_overwrite(self):
        before=os.stat('launch.json',dir_fd=self.fd)
        self.fs.preserve(self.fd,self.entry,'preserved.json',self.end)
        self.assertEqual(os.stat('preserved.json',dir_fd=self.fd).st_ino,before.st_ino)
        self.assertEqual(self.fs.read(self.fd,dict(self.entry,target='/synthetic/preserved.json'),self.end),self.raw)
        self.assertFalse((Path(self.tmp.name)/'launch.json').exists())

    def test_existing_preserved_target_keeps_both_files(self):
        (Path(self.tmp.name)/'preserved.json').write_bytes(b'existing')
        with self.assertRaises(ValueError):self.fs.preserve(self.fd,self.entry,'preserved.json',self.end)
        self.assertEqual((Path(self.tmp.name)/'launch.json').read_bytes(),self.raw)

    def test_hardlink_symlink_wrong_mode_and_wrong_digest_rejected(self):
        os.link(Path(self.tmp.name)/'launch.json',Path(self.tmp.name)/'hard')
        with self.assertRaises(ValueError):self.fs.read(self.fd,self.entry,self.end)
        os.unlink('hard',dir_fd=self.fd)
        os.symlink('launch.json',Path(self.tmp.name)/'link')
        with self.assertRaises(OSError):self.fs.read(self.fd,dict(self.entry,target='/synthetic/link'),self.end)
        with self.assertRaises(ValueError):self.fs.read(self.fd,dict(self.entry,sha256='0'*64),self.end)
        os.chmod('launch.json',0o600,dir_fd=self.fd)
        with self.assertRaises(ValueError):self.fs.read(self.fd,self.entry,self.end)

    def test_real_lock_contention_without_creation_or_bytes_change(self):
        for name in ('manager.lock','controller.lock'):
            path=Path(self.tmp.name)/name;path.write_bytes(b'');path.chmod(0o600)
        with self.fs.locks(self.fd,LABEL):
            with self.assertRaises(BlockingIOError):
                with self.fs.locks(self.fd,LABEL):pass
        self.assertEqual((Path(self.tmp.name)/'manager.lock').read_bytes(),b'')

    def test_lock_path_replacement_detected_even_when_bytes_unchanged(self):
        for name in ('manager.lock','controller.lock'):
            path=Path(self.tmp.name)/name;path.write_bytes(b'');path.chmod(0o600)
        with self.fs.locks(self.fd,LABEL) as verify:
            verify()
            os.rename('manager.lock','old-lock',src_dir_fd=self.fd,dst_dir_fd=self.fd)
            replacement=Path(self.tmp.name)/'manager.lock';replacement.write_bytes(b'');replacement.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'LOCK_CHANGED'):verify()

    def test_wrong_inherited_label_preserves_empty_new_file(self):
        self.fs.attrs=lambda *args:(_ for _ in ()).throw(ValueError('LABEL'))
        with self.assertRaisesRegex(ValueError,'LABEL'):
            self.fs.payload(self.fd,dict(self.entry,target='/synthetic/new'),self.raw,self.end)
        self.assertEqual((Path(self.tmp.name)/'new').read_bytes(),b'')

    def test_rename_failure_has_no_fallback_or_source_removal(self):
        with patch.object(x.ctypes,'CDLL',side_effect=OSError('unsupported')):
            with self.assertRaises(OSError):self.fs.preserve(self.fd,self.entry,'preserved.json',self.end)
        self.assertEqual((Path(self.tmp.name)/'launch.json').read_bytes(),self.raw)
        self.assertFalse((Path(self.tmp.name)/'preserved.json').exists())

    def test_destination_appearing_after_absent_check_is_not_overwritten(self):
        normal=self.fs.absent
        def race(fd,name):
            normal(fd,name)
            if name=='preserved.json':(Path(self.tmp.name)/name).write_bytes(b'other writer')
        self.fs.absent=race
        with self.assertRaises(OSError):self.fs.preserve(self.fd,self.entry,'preserved.json',self.end)
        self.assertEqual((Path(self.tmp.name)/'preserved.json').read_bytes(),b'other writer')
        self.assertEqual((Path(self.tmp.name)/'launch.json').read_bytes(),self.raw)


@unittest.skipUnless(sys.platform=='linux','full transaction in private Linux temporary directories')
class LinuxTransactionTests(Fixture,unittest.TestCase):
    def test_full_transaction_real_files_receipt_and_replay_barrier(self):
        with tempfile.TemporaryDirectory() as folder:
            class Files(x.TransitionFiles):
                def __init__(self,paths):
                    super().__init__(uid=os.getuid(),gid=os.getgid())
                    self.paths=paths
                    self.attrs=lambda *args:None  # Explicitly no actual SELinux claim.
                @contextmanager
                def directory(self,path,spec,deadline):
                    fd=os.open(self.paths[path],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                    try:yield fd
                    finally:os.close(fd)
            paths={p:Path(folder)/str(i) for i,p in enumerate(self.r['directories'])}
            for p in paths.values():p.mkdir(mode=0o700)
            def path(logical):
                p=PurePosixPath(logical);return paths[str(p.parent)]/p.name
            for name,e in self.ea.items():
                p=path(e['target']);p.write_bytes(self.old[name]);p.chmod(e['mode'])
            for name,raw in self.sealed.items():
                p=paths[self.a['store']['path']]/name;p.write_bytes(raw);p.chmod(0o600)
            before={name:(paths[self.a['store']['path']]/name).stat().st_ino for name in self.sealed}
            fs=Files(paths);raw=x.base.encode(self.r)
            def execute():
                return x.transition(self.old,self.old_sha,self.new,self.new_sha,raw,x.check.sha(raw),
                    time.monotonic()+15,execute=True,fs=fs,preflight=lambda *_:None,wall=lambda:150)
            result=execute();self.assertEqual(result['status'],'INPUT_FILES_TRANSITIONED_ONLY')
            self.assertEqual(path(x.LAUNCH).read_bytes(),self.new['launch.json'])
            self.assertEqual(path(self.r['preserved_launch_path']).read_bytes(),self.old['launch.json'])
            self.assertEqual([p.name for p in paths[self.b['store']['path']].iterdir()],[])
            for name,value in self.sealed.items():
                p=paths[self.a['store']['path']]/name
                self.assertEqual(p.stat().st_ino,before[name]);self.assertEqual(p.read_bytes(),value)
            records=[json.loads(line) for line in path(self.r['receipt_path']).read_bytes().splitlines()]
            self.assertEqual(records[-1]['stage'],'INPUT_FILES_TRANSITIONED_ONLY')
            with self.assertRaises(ValueError):execute()


if __name__=='__main__':unittest.main()
