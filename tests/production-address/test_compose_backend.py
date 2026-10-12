"""Synthetic Docker/host data; real Linux pipes/files, NEVER real Docker."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/production'))
import harbor_address_compose as c
import harbor_address_inspect as i
import harbor_address_backend as b
import harbor_address_preservation as mp
import harbor_address_sequence as seq
import harbor_address_journal as journal
import test_preservation as old_mount
import test_sequence as old_seq


def fixture():
    profile, ma = old_mount.fixture()
    before, target_labels, inherited, model_services = {}, {}, {}, {}
    for n, service in enumerate(seq.SERVICES):
        cid = hashlib.sha256(service.encode()).hexdigest()
        ls = {'com.docker.compose.project': 'harbor', 'com.docker.compose.service': service,
              'com.docker.compose.config-hash': 'a'*64, 'com.docker.compose.version': '5.5.1',
              'com.docker.compose.project.working_dir': '/synthetic/old',
              'com.docker.compose.project.config_files': '/synthetic/old/compose.yaml',
              'com.docker.compose.depends_on': '', 'owner': 'synthetic'}
        log = {'Type': 'json-file', 'Config': {}} if service == 'log' else {
            'Type': 'syslog', 'Config': {'syslog-address': seq.OLD_ADDRESS, 'tag': service}}
        before[service] = dict(Id=cid, Name='/'+service, Image='sha256:'+f'{n+30:064x}',
            Config=dict(Env=['SECRET=synthetic-$only\nvalue', 'SECOND=yes'], Labels=ls,
                        Hostname=cid[:12], Image='synthetic/'+service, Cmd=['serve'], Entrypoint=['/entry'],
                        User='service', Healthcheck={'Test': ['CMD', 'true']}, FutureConfigField={'keep': True}),
            HostConfig=dict(LogConfig=log, RestartPolicy={'Name': 'always', 'MaximumRetryCount': 0},
                            Privileged=False, SecurityOpt=None, PortBindings={}, Binds=[], Mounts=[],
                            ReadonlyRootfs=True, CapDrop=['ALL'], NetworkMode='harbor_default', FutureHostField=7),
            Mounts=deepcopy(ma['before'][service]), MountLabel='', ProcessLabel='',
            NetworkSettings={'Networks': {'harbor_default': dict(NetworkID='b'*64, EndpointID='c'*64,
                IPAMConfig=None, IPAddress=f'172.20.0.{n+2}', IPPrefixLen=16, Gateway='172.20.0.1',
                GlobalIPv6Address='', MacAddress='02:42:ac:14:00:02', Aliases=[service, cid[:12]],
                DNSNames=[service, cid[:12]], DriverOpts=None)}},
            State=dict(Status='running', Health={'Status': 'healthy'}, ExitCode=0, Error='',
                       Running=True, Paused=False, Restarting=False, Dead=False))
        if service != 'log':
            target_labels[service] = dict(ls, **{'com.docker.compose.config-hash': 'd'*64,
                'com.docker.compose.version': '5.6.0', 'com.docker.compose.project.working_dir': '/',
                'com.docker.compose.project.config_files': '-', 'com.docker.compose.replace': service})
            if ma['before'][service]:
                inherited[service] = [dict(Type='volume', Source=m['Name'], Target=m['Destination'], ReadOnly=False)
                                      for m in ma['before'][service]]
        model_services[service] = dict(image='synthetic/'+service, container_name=service,
            restart='always', environment={'SECRET': 'synthetic-$only\nvalue'},
            logging={'driver': log['Type'], 'options': deepcopy(log['Config'])},
            networks={'default': None}, volumes=[dict(type='bind', source='/synthetic/data', target='/data',
                                                     bind={'create_host_path': False})])
    base = dict(name='harbor', services=model_services, networks={'default': {'name': 'harbor_default', 'driver': 'bridge'}})
    candidate = deepcopy(base)
    for s in seq.ORDER:
        candidate['services'][s]['logging']['options']['syslog-address'] = seq.NEW_ADDRESS
    names = {'networks': {'default': 'harbor_default'}, 'volumes': {}}
    model = c.execution_model(base, candidate, resource_names=names)
    full = i.FullPreservation(before, after_labels=target_labels, after_host_mounts=inherited,
                               auto_hostnames=list(seq.ORDER), auto_addresses=list(seq.ORDER))
    plan = old_seq.fixture()
    plan.update(schema=seq.HEALTHY_SCHEMA, binding_sha256='a'*64,
                baseline={s: full.row(s, r, recreated=False, mounts_verified=r['Mounts']) for s, r in before.items()})
    return dict(profile=profile, ma=ma, before=before, target_labels=target_labels, inherited=inherited,
                base=base, candidate=candidate, names=names, model=model, full=full, plan=plan)


def recreated(f, service):
    row = deepcopy(f['before'][service])
    row['Id'] = hashlib.sha256(('after-'+service).encode()).hexdigest()
    row['Config']['Hostname'] = row['Id'][:12]
    row['Config']['Labels'] = deepcopy(f['target_labels'][service])
    row['Config']['Env'].reverse()
    row['HostConfig']['LogConfig'] = seq.logging_candidate(row['HostConfig']['LogConfig'])
    if service in f['inherited']:
        row['HostConfig']['Mounts'] = deepcopy(f['inherited'][service])
        for m in row['Mounts']:
            m['Mode'] = 'z'
    for v in row['NetworkSettings']['Networks'].values():
        v.update(EndpointID='e'*64, IPAddress='172.20.0.222', MacAddress='02:42:ac:14:00:ff',
                 Aliases=[service, row['Id'][:12]], DNSNames=[service, row['Id'][:12]])
    return row


class ModelTests(unittest.TestCase):
    def setUp(self): self.f = fixture()
    def execute(self):
        return c.execution_model(self.f['base'], self.f['candidate'], resource_names=self.f['names'])
    def test_scope_then_external_translation_preserves_all_service_values(self):
        model = self.execute()
        self.assertEqual(model['services'], self.f['candidate']['services'])
        self.assertEqual(model['networks'], {'default': {'external': True, 'name': 'harbor_default', 'ipam': {}}})
        self.assertNotIn('external', self.f['candidate']['networks']['default'])
    def test_external_network_empty_ipam_roundtrip_and_populated_rejection(self):
        model = self.execute()
        rendered = deepcopy(model)
        rendered['networks']['default']['ipam'] = {}
        c.validate_rendered(model, rendered)
        del model['networks']['default']['ipam']
        with self.assertRaisesRegex(ValueError, 'ROUNDTRIP_CHANGED'):
            c.validate_rendered(model, rendered)
        for changed in ({'config': [{'subnet': '172.30.0.0/16'}]}, {'driver': 'default'}):
            rendered['networks']['default']['ipam'] = changed
            with self.assertRaisesRegex(ValueError, 'EXTERNAL_RESOURCES'):
                c.validate_execution_model(rendered)
    def test_extra_address_or_environment_change_refused(self):
        for service in ['core', 'log']:
            self.setUp(); self.f['candidate']['services'][service]['environment']['SECRET'] += 'BAD'
            with self.assertRaisesRegex(ValueError, 'SCOPE'): self.execute()
    def test_missing_wrong_duplicate_resource_identity_refused(self):
        for names in ({'networks': {}, 'volumes': {}}, {'networks': {'default': 'other'}, 'volumes': {}}):
            self.f['names'] = names
            with self.assertRaises(ValueError): self.execute()
    def test_hooks_build_profile_scale_deploy_refused_even_if_in_base(self):
        for key in ('pre_stop', 'post_start', 'build', 'profiles', 'scale', 'deploy', 'use_api_socket', 'volumes_from'):
            self.setUp()
            for version in ('base', 'candidate'): self.f[version]['services']['core'][key] = {}
            with self.assertRaises(ValueError): self.execute()
    def test_bind_creation_and_unknown_named_volume_refused(self):
        for value in (dict(type='bind', source='/synthetic/data', target='/data', bind={'create_host_path': True}),
                      dict(type='volume', source='new', target='/data')):
            self.setUp()
            for version in ('base', 'candidate'): self.f[version]['services']['core']['volumes'] = [value]
            with self.assertRaises(ValueError): self.execute()
    def test_named_volume_reuse_has_exact_existing_external_name(self):
        for version in ('base', 'candidate'):
            self.f[version]['volumes'] = {'data': {'name': 'old_data', 'driver': 'local'}}
            self.f[version]['services']['core']['volumes'] = [dict(type='volume', source='data', target='/data')]
        self.f['names']['volumes']['data'] = 'old_data'
        self.assertEqual(self.execute()['volumes'], {'data': {'external': True, 'name': 'old_data'}})

    def test_direct_consumer_rejects_managed_resource_or_kill_signal(self):
        for kind in ('managed', 'signal'):
            model = deepcopy(self.f['model'])
            if kind == 'managed': model['networks']['default']['external'] = False
            else: model['services']['core']['stop_signal'] = 'SIGKILL'
            with self.assertRaises(ValueError): c.validate_execution_model(model)


class InspectTests(unittest.TestCase):
    def setUp(self): self.f = fixture(); self.service = 'portal'; self.row = recreated(self.f, self.service)
    def check(self):
        return self.f['full'].row(self.service, self.row, recreated=True,
                                  mounts_verified=self.f['ma']['after'][self.service])
    def test_full_result_is_secret_free_and_matches_baseline_projection(self):
        result = self.check()
        self.assertEqual(result['preservation_sha256'], self.f['plan']['baseline']['portal']['preservation_sha256'])
        self.assertNotIn('synthetic-$only', json.dumps(result))
    def test_each_nonmetadata_config_change_refused_including_unknown_fields(self):
        for key, value in [('Env', ['SECRET=changed']), ('Cmd', ['other']), ('Entrypoint', []),
                           ('User', 'root'), ('FutureConfigField', {'keep': False}), ('StopSignal', 'SIGKILL')]:
            self.setUp(); self.row['Config'][key] = value
            with self.assertRaises(ValueError): self.check()
    def test_host_security_ports_binds_and_unknown_fields_not_ignored(self):
        for key, value in [('Privileged', True), ('ReadonlyRootfs', False), ('PortBindings', {'80/tcp': []}),
                           ('Binds', ['/new:/data:rw']), ('SecurityOpt', ['label=disable']), ('FutureHostField', 8)]:
            self.setUp(); self.row['HostConfig'][key] = value
            with self.assertRaisesRegex(ValueError, 'PRESERVATION_CHANGED'): self.check()
    def test_generated_labels_require_exact_reviewed_values(self):
        for key, value in [('com.docker.compose.config-hash', 'f'*64), ('com.docker.compose.version', '5.7.0'),
                           ('owner', 'different'), ('unexpected', 'value')]:
            self.setUp(); self.row['Config']['Labels'][key] = value
            with self.assertRaises(ValueError): self.check()
    def test_duplicate_env_unknown_mount_option_and_new_volume_refused(self):
        self.row['Config']['Env'].append('SECRET=second')
        with self.assertRaisesRegex(ValueError, 'ENV_DUPLICATE'): self.check()
        self.setUp(); self.row['HostConfig']['Mounts'][0]['VolumeOptions'] = {'NoCopy': True}
        with self.assertRaises(ValueError): self.check()
        self.setUp(); self.row['Mounts'][0]['Name'] = 'f'*64
        with self.assertRaisesRegex(ValueError, 'MOUNT_CHANGED'): self.check()
    def test_network_identity_static_options_and_unrelated_alias_refused(self):
        for key, value in [('NetworkID', 'f'*64), ('IPAMConfig', {'IPv4Address': '172.20.0.5'}),
                           ('DriverOpts', {'x': 'y'}), ('Aliases', ['new-name']), ('Gateway', '172.20.0.254')]:
            self.setUp(); self.row['NetworkSettings']['Networks']['harbor_default'][key] = value
            with self.assertRaises(ValueError): self.check()
    def test_untouched_state_config_and_network_are_exact(self):
        for location in ('Config', 'HostConfig', 'NetworkSettings'):
            row = deepcopy(self.f['before']['core']); row[location]['new'] = True
            with self.assertRaises(ValueError): self.f['full'].row('core', row, recreated=False, mounts_verified=row['Mounts'])
    def test_identity_and_state_conflict_refused(self):
        self.row['Id'] = self.f['before']['redis']['Id']
        with self.assertRaises(ValueError): self.check()
        self.setUp(); self.row['State']['Restarting'] = True
        with self.assertRaisesRegex(ValueError, 'STATE_CONFLICT'): self.check()

    def test_auto_hostname_must_follow_exact_new_container_id(self):
        self.row['Config']['Hostname'] = 'arbitrary-host'
        with self.assertRaisesRegex(ValueError, 'HOSTNAME'): self.check()
    def test_before_mutation_does_not_change_private_baseline(self):
        self.f['before']['portal']['Config']['Env'] = ['changed=yes']
        self.check()
    def test_target_label_scope_or_volume_addition_cannot_bless_arbitrary_change(self):
        for key, val in [('owner', 'other'), ('com.docker.compose.project', 'other')]:
            self.setUp(); self.f['target_labels']['portal'][key] = val
            with self.assertRaises(ValueError):
                i.FullPreservation(self.f['before'], after_labels=self.f['target_labels'],
                    after_host_mounts=self.f['inherited'], auto_hostnames=list(seq.ORDER), auto_addresses=list(seq.ORDER))
        with self.assertRaises(ValueError):
            i.validate_inherited([], [{'Type':'volume','Source':'other','Target':'/run','ReadOnly':False}],
                                 self.f['before']['portal']['Mounts'])


class Engine:
    def __init__(self, f): self.rows = deepcopy(f['before']); self.extra = []
    def inventory(self, deadline):
        return [dict(Id=r['Id'], Labels=r['Config']['Labels']) for r in self.rows.values()] + deepcopy(self.extra)
    def inspect(self, cid, deadline): return deepcopy(next(r for r in self.rows.values() if r['Id'] == cid))


class ConnectedTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(); self.engine = Engine(self.f); self.clock = 10.0
        self.calls = []; self.after_render = lambda: None; self.after_write = lambda: None
        self.rc = 0; self.host_drift = False
        outer = self
        class Process:
            def call(self, operation, model, *, deadline, service=None):
                outer.calls.append((operation, service))
                if operation == 'render':
                    outer.after_render()
                    return 0
                else:
                    outer.engine.rows[service] = recreated(outer.f, service)
                    outer.after_write()
                return outer.rc
        self.backend = b.AddressBackend(self.f['plan'], engine=self.engine, host_provider=self.host,
            preservation=self.f['full'], mount_preservation=mp.MountPreservation(self.f['profile']),
            execution_model=self.f['model'], execution_model_sha256=seq.fingerprint(self.f['model']),
            process=Process(), clock=lambda: self.clock)
        self.journal = old_seq.MemoryJournal()
    def host(self, deadline):
        inputs = {k: deepcopy(v) for k, v in self.f['ma'].items() if k not in ('before','after','completed_services','labels')}
        return dict(binding_sha256='f'*64 if self.host_drift else self.f['plan']['binding_sha256'],
            inputs_sha256=self.f['plan']['inputs_sha256'], at=self.clock, logger_ipv4=True,
            model_sha256=seq.fingerprint(self.f['model']), preservation_binding=self.f['full'].binding, mount_inputs=inputs)
    def run_it(self):
        return seq.Sequence(self.f['plan'], self.backend, self.journal, clock=lambda: self.clock,
                            sleep=lambda seconds: setattr(self, 'clock', self.clock+seconds)).run(deadline_mono=500)
    def writes(self): return [s for op,s in self.calls if op == 'recreate']
    def test_nine_services_all_layers_connected(self):
        result = self.run_it()
        self.assertEqual(result['status'], 'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED')
        self.assertEqual(self.writes(), list(seq.ORDER)); self.assertEqual(len(self.calls), 18)
        self.assertFalse(result['runtime_acceptance'])
    def test_guard_drift_after_render_prevents_first_write(self):
        self.after_render = lambda: setattr(self, 'host_drift', True)
        result = self.run_it()
        self.assertEqual(self.writes(), []); self.assertEqual(result['status'], 'STOP_RECOVERY_REQUIRED')
        self.assertEqual(result['reason'], 'RECREATE_OUTCOME_UNKNOWN')
    def test_inspect_drift_after_render_prevents_first_write(self):
        self.after_render = lambda: self.engine.rows['core']['HostConfig'].update(Privileged=True)
        self.run_it(); self.assertEqual(self.writes(), [])
    def test_late_command_partial_state_never_advances(self):
        self.after_write = lambda: setattr(self, 'clock', 20.0)
        result = self.run_it()
        self.assertEqual(self.writes(), ['postgresql']); self.assertEqual(result['status'], 'STOP_RECOVERY_REQUIRED')
        self.assertNotIn('COMPLETE', self.journal.append_calls)
    def test_failed_command_partial_state_spends_backend(self):
        self.rc = 7
        result = self.run_it(); self.assertEqual(self.writes(), ['postgresql'])
        self.assertEqual(result['status'], 'STOP_RECOVERY_REQUIRED')
        with self.assertRaisesRegex(ValueError, 'SPENT'):
            self.backend.recreate(service='postgresql', expected_id=self.f['before']['postgresql']['Id'],
                plan_sha256=seq.fingerprint(self.f['plan']), deadline_mono=100)
    def test_healthy_runtime_mutation_before_next_service_stops(self):
        self.after_write = lambda: self.engine.rows['core']['State'].update(Restarting=True)
        result = self.run_it(); self.assertEqual(self.writes(), ['postgresql'])
        self.assertEqual(result['status'], 'STOP_RECOVERY_REQUIRED')
    def test_duplicate_container_stops_before_commands(self):
        row = self.engine.rows['core']; self.engine.extra = [dict(Id='f'*64, Labels=row['Config']['Labels'])]
        result = self.run_it(); self.assertEqual(self.calls, []); self.assertEqual(result['status'], 'STOP_BEFORE_CHANGE')
    def test_foreign_unlabelled_container_is_not_target(self):
        self.engine.extra = [dict(Id='f'*64, Labels=None)]
        self.assertEqual(self.run_it()['status'], 'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED')
    def test_host_profile_volume_metadata_drift_blocks_initial_run(self):
        next(iter(self.f['ma']['current_metadata'].values()))['mode'] = 0o777
        result = self.run_it(); self.assertEqual(self.calls, []); self.assertEqual(result['status'], 'STOP_BEFORE_CHANGE')
    def test_post_state_unexpected_environment_stops_after_one(self):
        self.after_write = lambda: self.engine.rows['postgresql']['Config']['Env'].append('ADDED=SECRET')
        result = self.run_it(); self.assertEqual(self.writes(), ['postgresql'])
        self.assertNotIn('SECRET', json.dumps(result))

    def test_changed_cli_render_is_refused_before_guard_or_mutation(self):
        self.backend.transport.process.call = lambda *a, **kw: 8
        self.run_it(); self.assertEqual(self.writes(), [])
        self.assertTrue(self.backend.failed)

    def test_forked_and_out_of_order_backend_refused(self):
        for values in [('redis', self.f['before']['redis']['Id']), ('log', self.f['before']['log']['Id'])]:
            self.setUp()
            with self.assertRaises(ValueError):
                self.backend.recreate(service=values[0], expected_id=values[1],
                    plan_sha256=seq.fingerprint(self.f['plan']), deadline_mono=100)
            self.assertEqual(self.calls, [])
        self.setUp()
        with patch.object(c.os, 'getpid', return_value=-1):
            with self.assertRaises(ValueError): self.backend.observe(100)

    def test_concurrent_backend_request_does_not_enter_transport(self):
        self.backend._writing.acquire()
        try:
            with self.assertRaisesRegex(ValueError, 'BUSY'):
                self.backend.recreate(service='postgresql', expected_id=self.f['before']['postgresql']['Id'],
                    plan_sha256=seq.fingerprint(self.f['plan']), deadline_mono=100)
        finally: self.backend._writing.release()
        self.assertEqual(self.calls, [])


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root local files/processes only')
class LinuxTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='address-compose-test-', dir='/root'))
    def tearDown(self):
        assert self.base.parent == Path('/root') and self.base.name.startswith('address-compose-test-')
        shutil.rmtree(self.base)
    def process(self, code, payload=b'', budget=3):
        return c.run_process([sys.executable, '-I', '-c', code], payload, cwd=str(self.base),
                             env={'LC_ALL': 'C'}, pass_fds=(), deadline=time.monotonic()+budget)
    def test_real_pipes_stdin_stdout_stderr_and_secret_free_receipt(self):
        r = self.process('import sys;sys.stdout.buffer.write(sys.stdin.buffer.read());sys.stderr.write("SECRET")', b'SECRET')
        self.assertEqual((r.rc,r.reason,r.stdout,r.stderr), (0,'COMPLETED',b'SECRET',b'SECRET'))
        self.assertNotIn('SECRET', repr(r)); self.assertNotIn('SECRET', json.dumps(r.diagnostic()))
    def test_deadline_preserves_partial_bytes_without_success(self):
        r = self.process('import time;print("partial",flush=True);time.sleep(30)', budget=0.3)
        self.assertEqual(r.reason, 'COMPOSE_DEADLINE'); self.assertIn(b'partial', r.stdout); self.assertIsNone(r.rc)
    def test_output_overflow_is_bounded_and_not_success(self):
        with patch.object(c, 'MAX_OUTPUT', 100):
            r = self.process('import sys;sys.stdout.write("x"*1000000)')
        self.assertEqual(r.reason, 'COMPOSE_OUTPUT_LIMIT'); self.assertEqual(len(r.stdout), 100)
    def test_broken_input_pipe_is_not_complete(self):
        r = self.process('pass', b'x'*1000000)
        self.assertEqual(r.reason, 'COMPOSE_STDIN_INCOMPLETE'); self.assertIsNone(r.rc)
    def test_descendant_holding_pipe_is_bounded(self):
        r = self.process('import os,time\nif os.fork()==0:time.sleep(30)', budget=0.3)
        self.assertEqual(r.reason, 'COMPOSE_DEADLINE')
    def test_symlink_hardlink_writable_and_unknown_xattr_refused(self):
        f = self.base/'file'; f.write_bytes(b'a'); f.chmod(0o600)
        link = self.base/'link'; link.symlink_to(f)
        with self.assertRaises(OSError):
            with c.protected_path(str(link), directory=False): pass
        link.unlink(); os.link(f, link)
        with self.assertRaises(ValueError):
            with c.protected_path(str(f), directory=False): pass
        link.unlink(); f.chmod(0o666)
        with self.assertRaises(ValueError):
            with c.protected_path(str(f), directory=False): pass
        f.chmod(0o600); os.setxattr(f, 'user.synthetic', b'x')
        with self.assertRaises(ValueError):
            with c.protected_path(str(f), directory=False): pass
    def test_path_replacement_after_use_refused(self):
        f = self.base/'file'; f.write_bytes(b'a'); f.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'REPLACED'):
            with c.protected_path(str(f), directory=False):
                f.rename(self.base/'old'); f.write_bytes(b'a'); f.chmod(0o600)
    def pinned(self):
        binary = self.base/'elf'; shutil.copyfile(Path(sys.executable).resolve(), binary); binary.chmod(0o700)
        context = lambda p: os.getxattr(p, 'security.selinux') if 'security.selinux' in os.listxattr(p) else None
        private = self.base/'config'; private.mkdir(mode=0o700)
        return c.PinnedCompose(binary=str(binary), binary_sha256=c.sha(binary.read_bytes()), binary_context=context(binary),
                               private_directory=str(private), private_context=context(private)), private
    def test_pinned_argv_exact_stdin_environment_and_no_forced_container_timeout(self):
        p, private = self.pinned(); model = fixture()['model']; calls = []
        def fake(argv, payload, **kw):
            calls.append((argv, payload, kw))
            return c.PrivateResult(0, 'COMPLETED', json.dumps(c.expected_model(model)).encode(), b'')
        with patch.object(c, 'run_process', side_effect=fake):
            p.call('render', model, deadline=time.monotonic()+3)
            p.call('recreate', model, service='postgresql', deadline=time.monotonic()+3)
        self.assertEqual(calls[0][1], calls[1][1]); self.assertEqual(calls[1][0][-3:], ['--timeout','-1','postgresql'])
        for argv, payload, kw in calls:
            self.assertNotIn('SECRET', str(argv)); self.assertNotIn('SYNTHETIC_INHERITED', kw['env'])
            self.assertIn('--no-build', calls[1][0]); self.assertNotIn('--remove-orphans', argv)
        self.assertEqual(list(private.iterdir()), []); self.assertEqual(len(p.receipts), 2)
    def test_bad_binary_private_config_and_render_change_block(self):
        p, private = self.pinned(); model = fixture()['model']; p.binary_sha = '0'*64
        with patch.object(c, 'run_process') as call:
            with self.assertRaises(ValueError): p.call('render', model, deadline=time.monotonic()+3)
            call.assert_not_called()
        p, private = self.pinned_again()
        (private/'config.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'DIRECTORY_NOT_EMPTY'):
            p.call('render', model, deadline=time.monotonic()+3)

    def test_render_output_drift_and_wrong_label_block(self):
        p, private = self.pinned(); model = fixture()['model']
        changed = deepcopy(model); changed['services']['core']['environment']['SECRET'] = 'wrong'
        with patch.object(c, 'run_process', return_value=c.PrivateResult(0,'COMPLETED',json.dumps(changed).encode(),b'')):
            with self.assertRaisesRegex(ValueError, 'ROUNDTRIP_CHANGED'):
                p.call('render', model, deadline=time.monotonic()+3)
        self.assertEqual(p.receipts[0]['rc'], 0)  # CLI success != render match
        p.context = b'wrong-context'
        with self.assertRaisesRegex(ValueError, 'CONTEXT'):
            p.call('render', model, deadline=time.monotonic()+3)

    def test_binary_modified_during_call_has_receipt_but_refuses_result(self):
        p, private = self.pinned(); model = fixture()['model']
        def change(*args, **kwargs):
            with open(p.binary, 'ab') as stream: stream.write(b'x')
            return c.PrivateResult(0, 'COMPLETED', json.dumps(model).encode(), b'')
        with patch.object(c, 'run_process', side_effect=change):
            with self.assertRaisesRegex(ValueError, 'EXECUTABLE_CHANGED'):
                p.call('render', model, deadline=time.monotonic()+3)
        self.assertEqual(len(p.receipts), 1)
    def pinned_again(self):
        shutil.rmtree(self.base/'config'); (self.base/'elf').unlink(); return self.pinned()
    def test_connected_sequence_actual_disk_journal_and_reader(self):
        s = ConnectedTests(); s.setUp()
        path = self.base/'journal'; path.mkdir(mode=0o700)
        context = os.getxattr(path, 'security.selinux').rstrip(b'\0') if 'security.selinux' in os.listxattr(path) else None
        s.journal = journal.Journal(str(path), expected_selinux=context)
        self.assertEqual(s.run_it()['status'], 'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED')
        result = journal.inspect_history(str(path), expected_selinux=context, expected_plan_sha256=seq.fingerprint(s.f['plan']))
        self.assertEqual(result['valid_records'],29); self.assertFalse(result['may_resume'])
        self.assertEqual(result['runtime_outcome'], 'NOT_INFERRED')


if __name__ == '__main__': unittest.main()
