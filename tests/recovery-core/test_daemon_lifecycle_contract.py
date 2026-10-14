"""Versioned daemon-reload contract; synthetic inputs, no live host mutation."""
from copy import deepcopy
from dataclasses import replace
import importlib
import unittest
from unittest.mock import patch

from test_production_recovery import NetworkFixture, NID, BRIDGE
from test_host_provider import LABEL, raw
from test_state_executor import MemoryStore
import harbor_recovery_host as h
import harbor_recovery_docker as d
import harbor_recovery_bundle as b
import harbor_recovery_core as c
from harbor_recovery_executor import Executor

DNS = ('Dns', 'DnsOptions', 'DnsSearch')


class LifecycleFixture(NetworkFixture):
    def __init__(self, running=('log',)):
        super().__init__(running)
        self.default = {
            'Id': 'e'*64, 'Created': '2026-01-01T00:00:00Z', 'Name': 'bridge',
            'Driver': 'bridge', 'Scope': 'local', 'Internal': False,
            'IPAM': {'Driver': 'default', 'Config': [{'Subnet': '172.17.0.0/16'}]},
            'Options': {'com.docker.network.bridge.name': 'docker0',
                        'com.docker.network.bridge.default_bridge': 'true'},
            'Containers': {}, 'Status': {'IPAM': {'Subnets': {
                '172.17.0.0/16': {'IPsInUse': 0, 'DynamicIPsAvailable': 65000}}}}}
        self.default_link = {'ifindex': 4, 'ifname': 'docker0', 'address': '02:00:00:00:00:04',
                             'flags': ['BROADCAST', 'UP'], 'operstate': 'DOWN',
                             'linkinfo': {'info_kind': 'bridge'}}
        self.stable.append({'dst': '172.17.0.0/16', 'dev': 'docker0', 'flags': []})
        self.policy['version'] = 3
        self.policy['network']['default_bridge'] = {
            'name': 'bridge', 'bridge': 'docker0',
            'sha256': d.digest(h.default_bridge_projection(self.default))}
        self.policy['network']['interfaces']['docker0'] = d.digest(
            h.production_link_projection(self.default_link, bridge=True))
        self.policy['network']['routes_sha256'] = d.digest(sorted(self.stable, key=d.digest))
        for item in self.engine.rows.values():
            item['HostConfig'].update({key: None for key in DNS})
        self.reader.read = lambda nid, deadline: deepcopy(self.default if nid == 'bridge' else self.network)
        self.running(running)
        self.host = h.host_provider(self.policy, self.engine, io=self.io, clock=lambda: 10,
                                    network_reader=self.reader)

    def running(self, services):
        super().running(services)
        if hasattr(self, 'default_link'):
            self.links.append(deepcopy(self.default_link))

    def plan(self):
        return c.Plan(self.engine.ids, {s: d.project(r, s, r['Id'], 'harbor',
                      fingerprint_version=2).fingerprint for s, r in self.engine.rows.items()},
                      {s: 60 for s in c.ORDER}, execution_binding=d.execution_binding(
                      self.host.binding, 'harbor', self.engine.binding, fingerprint_version=2))

    def reload(self):
        self.default.update(Id='f'*64, Created='2026-01-02T00:00:00Z')
        for item in self.engine.rows.values():
            item['HostConfig'].update({key: [] for key in DNS})
        normal = self.io.run
        self.io.run = lambda argv, cwd, deadline: normal(argv, cwd, deadline).replace(
            ('InvocationID='+'a'*32).encode(), ('InvocationID='+'c'*32).encode()
        ) if 'systemctl' in argv[0] else normal(argv, cwd, deadline)
        self.running(['log'])


class DaemonContractTests(unittest.TestCase):
    def reject(self, f):
        with self.assertRaisesRegex(ValueError, '^HOST_VERIFICATION_FAILED$'):
            f.read()
        self.assertEqual(f.engine.posts, [])

    def test_default_rotation_and_dns_reload_recover_once_in_dependency_order(self):
        f = LifecycleFixture(running=(*c.ORDER, 'log'))
        plan = f.plan(); core = c.Controller(plan); store = MemoryStore()
        backend = d.DockerBackend(plan, f.engine, f.host, f.host.binding, 'harbor',
                                  fingerprint_version=2, clock=lambda: 10, probe=lambda _: True)
        before = backend.observe()
        store.state = core.arm(c.State(), before, 10).state
        f.reload()
        after = backend.observe()
        self.assertNotEqual(before.daemon, after.daemon)
        self.assertEqual({k: r.fingerprint for k, r in before.containers.items()},
                         {k: r.fingerprint for k, r in after.containers.items()})
        running = ['log']; calls = []
        def start(cid, deadline):
            calls.append(cid)
            running.append(next(s for s, i in f.engine.ids.items() if i == cid))
            f.running(running)
            return 'ok'
        f.engine.start = start
        # Same persisted state, new executor as after the manager restart.
        executor = Executor(core, store, backend, clock=lambda: 10, gate=lambda: None)
        executor.open()
        for _ in range(30): executor.tick()
        self.assertEqual(calls, [f.engine.ids[s] for s in c.ORDER])
        self.assertEqual(len(store.claims), 9)
        self.assertEqual(store.state.desired, 'RUN')
        self.assertIsNone(store.state.pending); self.assertIsNone(store.state.health_wait)
        claims = deepcopy(store.claims)
        Executor(core, store, backend, clock=lambda: 10, gate=lambda: None).open()
        for _ in range(10): executor.tick()
        self.assertEqual(len(calls), 9); self.assertEqual(store.claims, claims)

    def test_default_rotation_is_not_custom_network_reenrollment(self):
        f = LifecycleFixture(); f.reload(); f.read()
        f.network['Id'] = 'a'*64
        self.reject(f)

    def test_default_configuration_endpoint_link_and_identity_drift_fail_closed(self):
        changes = [
            lambda f: f.default['IPAM']['Config'][0].update(Subnet='172.19.0.0/16'),
            lambda f: f.default['Options'].update({'com.docker.network.bridge.enable_icc': 'false'}),
            lambda f: f.default['Options'].update({'com.docker.network.bridge.default_bridge': 'false'}),
            lambda f: f.default.update(Driver='overlay'),
            lambda f: f.default.update(Name='other'),
            lambda f: f.default.update(Id=NID),
            lambda f: f.default.update(Id='not-an-id'),
            lambda f: f.default.update(Created=None),
            lambda f: f.default.update(Internal=True),
            lambda f: f.default.update(NewSetting=True),
            lambda f: f.default['Containers'].update({'f'*64: {}}),
            lambda f: f.default['Containers'].update({f.engine.ids['log']: {}}),
            lambda f: f.links[-1].update(master='docker0'),
            lambda f: f.links[-1]['linkinfo'].update(info_kind='dummy'),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                f = LifecycleFixture(); change(f); self.reject(f)

    def test_same_observation_default_generation_change_is_rejected(self):
        f = LifecycleFixture(); normal = f.reader.read; count = 0
        def read(nid, deadline):
            nonlocal count
            row = normal(nid, deadline)
            if nid == 'bridge':
                count += 1
                if count > 1: row['Id'] = 'f'*64
            return row
        f.reader.read = read
        self.reject(f)

    def test_network_reader_allows_only_exact_builtin_name_in_v3(self):
        f = LifecycleFixture(); reader = h.ProductionNetworkReader(f.policy).engine
        for name in ('bridge', NID):
            reader._validate_request('GET', '/networks/'+name, b'')
        for method, name, body in [('POST', 'bridge', b''), ('GET', 'docker0', b''),
                                   ('GET', 'bridge?verbose=true', b''), ('GET', 'e'*64, b''),
                                   ('GET', 'bridge', b'{}')]:
            with self.assertRaisesRegex(ValueError, 'GET_ONLY'):
                reader._validate_request(method, '/networks/'+name, body)
        old = h.ProductionNetworkReader(NetworkFixture().policy).engine
        with self.assertRaisesRegex(ValueError, 'GET_ONLY'):
            old._validate_request('GET', '/networks/bridge', b'')

    def test_missing_default_or_duplicate_name_is_not_a_valid_new_policy(self):
        for kind in ('missing', 'duplicate', 'physical', 'wrong_bridge'):
            f = LifecycleFixture()
            if kind == 'missing': del f.policy['network']['default_bridge']
            elif kind == 'duplicate': f.policy['network']['bridges'][NID]['name'] = 'bridge'
            elif kind == 'physical': f.policy['network']['physical_interfaces'] = ['docker0', 'ens33']
            else: f.policy['network']['default_bridge']['bridge'] = 'other'
            with self.assertRaises(ValueError): h.validate_policy(f.policy)

    def test_dns_equivalence_is_narrow_and_legacy_fingerprints_unchanged(self):
        f = LifecycleFixture(); row = f.engine.rows['postgresql']; cid = row['Id']
        def fp(item, version): return d.project(item, 'postgresql', cid, 'harbor',
                                                 fingerprint_version=version).fingerprint
        old, new = fp(row, 1), fp(row, 2)
        changed = deepcopy(row); changed['HostConfig'].update({k: [] for k in DNS})
        self.assertNotEqual(old, fp(changed, 1)); self.assertEqual(new, fp(changed, 2))
        self.assertNotEqual(old, new)
        self.assertEqual(row['HostConfig']['Dns'], None)  # pure projection
        for key in DNS:
            changed = deepcopy(row); changed['HostConfig'][key] = ['setting']
            self.assertNotEqual(new, fp(changed, 2))
            for bad in ('', {}, False, [1]):
                changed['HostConfig'][key] = bad
                with self.assertRaisesRegex(ValueError, 'DNS_SCHEMA'): fp(changed, 2)
            del changed['HostConfig'][key]
            with self.assertRaisesRegex(ValueError, 'DNS_SCHEMA'): fp(changed, 2)
        for key, value in [('Privileged', True), ('NewSetting', None)]:
            changed = deepcopy(row); changed['HostConfig'][key] = value
            self.assertNotEqual(new, fp(changed, 2))

    def test_binding_rejects_old_fingerprint_contract_and_mutated_adapter(self):
        f = LifecycleFixture(); plan = f.plan()
        with self.assertRaisesRegex(ValueError, 'PLAN_ADAPTER_BINDING'):
            d.DockerBackend(plan, f.engine, f.host, f.host.binding, 'harbor')
        backend = d.DockerBackend(plan, f.engine, f.host, f.host.binding, 'harbor',
                                  fingerprint_version=2, clock=lambda: 10, probe=lambda _: True)
        backend.fingerprint_version = 1
        with self.assertRaisesRegex(ValueError, 'PLAN_ADAPTER_BINDING'): backend.observe()
        for bad in (True, 0, 3, '2'):
            with self.assertRaisesRegex(ValueError, 'FINGERPRINT_VERSION'):
                d.execution_binding(f.host.binding, 'harbor', f.engine.binding, fingerprint_version=bad)

    def test_real_dns_change_after_first_start_holds_without_next_claim(self):
        f = LifecycleFixture(running=(*c.ORDER, 'log')); plan = f.plan(); core = c.Controller(plan)
        store = MemoryStore()
        backend = d.DockerBackend(plan, f.engine, f.host, f.host.binding, 'harbor',
                                  fingerprint_version=2, clock=lambda: 10, probe=lambda _: True)
        store.state = core.arm(c.State(), backend.observe(), 10).state
        f.reload(); calls = []
        def start(cid, deadline):
            calls.append(cid); f.running(['log', 'postgresql'])
            f.engine.rows['redis']['HostConfig']['Dns'] = ['192.0.2.53']
            return 'ok'
        f.engine.start = start
        executor = Executor(core, store, backend, clock=lambda: 10, gate=lambda: None)
        executor.open()
        for _ in range(12): executor.tick()
        self.assertEqual(calls, [f.engine.ids['postgresql']])
        self.assertEqual(len(store.claims), 1); self.assertEqual(store.state.desired, 'HOLD')


class LifecyclePackageTests(unittest.TestCase):
    def fixture(self):
        from test_review_package import PackageTests, x
        from harbor_recovery_service import unit_text
        fixture = PackageTests(); fixture.setUp(); f = LifecycleFixture()
        obj = fixture.obj; obj['schema'] = b.LIFECYCLE_SCHEMA
        p = obj['host_policy']; p['version'] = 3
        p['network'] = deepcopy(f.policy['network']); p['network']['ids'] = deepcopy(obj['plan']['ids'])
        p['tools']['nsenter'] = '/usr/bin/nsenter'
        p['files']['/usr/bin/nsenter'] = deepcopy(f.policy['files']['/usr/bin/nsenter'])
        unit = unit_text(fixture.runtime['python'], '/opt/fds-harbor-recovery/bootstrap/'+x.sha(fixture.boot)+
                         '/harbor_recovery_bootstrap.py', LABEL, startup_seconds=30, shutdown_seconds=90,
                         production=True).encode()
        p['files'][obj['manager']['fragment']]['sha256'] = x.sha(unit)
        obj['plan']['fingerprints'] = f.plan().fingerprints
        obj['plan']['execution_binding'] = d.execution_binding(b.bound_host_digest(obj), 'harbor',
            d.UnixEngine(p['api_version'], socket_path=p['socket']).binding, fingerprint_version=2)
        return fixture

    def test_new_schema_flows_through_package_receipt_bootstrap_installer_and_runtime(self):
        from test_review_package import x
        from test_review_package_check import x as checker
        from test_verified_bootstrap import Reader, x as boot, BUNDLE, clean_project_imports
        from test_approved_bundle import Pins
        from test_file_install import x as install
        from test_host_provider import FakeIO
        fixture = self.fixture(); obj = fixture.obj
        files, plan = fixture.prepare()
        self.assertEqual(checker.verify_bytes(files, x.sha(files['INSTALL_PLAN.json']))['status'],
                         'PACKAGE_BYTES_VERIFIED')
        self.assertIn('network-online.target', files['manager.service'].decode())
        reader = Reader(deepcopy(obj), actual=True)
        code, _ = boot.collect(BUNDLE, reader.sha, LABEL, 30, reader=reader, clock=lambda: 10)
        with clean_project_imports(), boot.VerifiedImporter(code):
            module = importlib.import_module('harbor_recovery_bundle')
            self.assertEqual(module.fingerprint_version(module.parse_bundle(raw(reader.obj))), 2)
        before = install.Preflight(obj, {'external_existing_inputs': {}},
                                   io=FakeIO(obj['host_policy']), clock=lambda: 10)
        self.assertEqual(before.host._policy['version'], 3)
        pins = Pins(obj)
        loaded = b.load_bundle('/etc/bundle.json', pins.sha, LABEL, 30, io=pins, clock=lambda: 10)
        with patch.object(b, 'ProtectedStore', return_value=MemoryStore()):
            components = b.build(loaded, 30, clock=lambda: 10)
        self.assertEqual(components['executor'].backend.fingerprint_version, 2)
        self.assertEqual(components['transition'].backend.fingerprint_version, 2)

    def test_policy_backend_uses_same_projection_and_rejects_switch(self):
        from harbor_recovery_policy_backend import PolicyBackend, PolicyEngine
        from harbor_recovery_transition import TransitionPlan
        f = LifecycleFixture(running=(*c.ORDER, 'log')); plan = f.plan()
        engine = PolicyEngine('1.53', [f.engine.ids[s] for s in c.ORDER])
        plan = replace(plan, execution_binding=d.execution_binding(
            f.host.binding, 'harbor', engine.binding, fingerprint_version=2))
        transition = TransitionPlan(plan, f.host.binding, 'b'*64)
        engine.inventory, engine.inspect = f.engine.inventory, f.engine.inspect
        class Manager:
            binding = 'b'*64
            def __call__(self, deadline): return self.binding
        backend = PolicyBackend(transition, engine, f.host, Manager(), fingerprint_version=2,
                                clock=lambda: 10, probe=lambda _: True)
        before = backend.observe(30)
        for row in f.engine.rows.values(): row['HostConfig'].update({k: [] for k in DNS})
        self.assertEqual(before.fingerprints, backend.observe(30).fingerprints)
        backend.fingerprint_version = 1
        with self.assertRaisesRegex(ValueError, 'POLICY_RECOVERY_BINDING'): backend.observe(30)

    def test_downgrade_mismatch_or_legacy_binding_cannot_prepare_or_load(self):
        from test_approved_bundle import Pins
        fixture = self.fixture(); obj = fixture.obj
        legacy = deepcopy(obj); legacy['schema'] = b.PRODUCTION_SCHEMA
        with self.assertRaisesRegex(ValueError, 'HOST_SCOPE'): b.parse_bundle(raw(legacy))
        obj['plan']['execution_binding'] = d.execution_binding(b.bound_host_digest(obj), 'harbor',
            d.UnixEngine(obj['host_policy']['api_version']).binding)
        with self.assertRaisesRegex(ValueError, 'EXECUTION_BINDING'): fixture.prepare()
        pins = Pins(obj)
        with self.assertRaisesRegex(ValueError, 'EXECUTION_BINDING'):
            b.load_bundle('/etc/bundle.json', pins.sha, LABEL, 30, io=pins, clock=lambda: 10)


if __name__ == '__main__':
    unittest.main()

