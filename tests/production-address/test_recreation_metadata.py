"""Sanitized r3 metadata regression; synthetic values, no Docker or guest I/O."""
from copy import deepcopy
import unittest
from unittest.mock import patch

import test_compose_backend as cb
import test_protected_runtime as pr
import harbor_address_inspect as inspect
import harbor_address_session as session
import harbor_address_compose as compose
import harbor_address_sequence as seq

DNS = ('Dns', 'DnsOptions', 'DnsSearch')
DEPENDS = 'com.docker.compose.depends_on'


class EmptyDnsTests(unittest.TestCase):
    def fixture(self, service='postgresql', before=None, after=None):
        f = cb.fixture()
        f['before'][service]['HostConfig'].update(deepcopy(before or {}))
        full = inspect.FullPreservation(f['before'], after_labels=f['target_labels'],
            after_host_mounts=f['inherited'], auto_hostnames=list(seq.ORDER), auto_addresses=list(seq.ORDER))
        row = cb.recreated(f, service) if service != 'log' else deepcopy(f['before'][service])
        row['HostConfig'].update(deepcopy(after or {}))
        return f, full, row

    def check(self, f, full, row, service='postgresql'):
        return full.row(service, row, recreated=True, mounts_verified=f['ma']['after'][service])

    def test_engine_empty_dns_serialization_both_directions_all_nine(self):
        for service in seq.ORDER:
            for old, new in (([], None), (None, [])):
                with self.subTest(service=service, old=old, new=new):
                    f, full, row = self.fixture(service, dict.fromkeys(DNS, old), dict.fromkeys(DNS, new))
                    raw_before, raw_after = deepcopy(f['before']), deepcopy(row)
                    self.check(f, full, row, service)
                    self.assertEqual(f['before'], raw_before)
                    self.assertEqual(row, raw_after)

    def test_nonempty_dns_values_and_order_remain_exact(self):
        for key in DNS:
            for old, new in (([], ['override']), (None, ['override']), (['override'], []),
                             (['override'], None), (['one'], ['two']), (['one', 'two'], ['two', 'one'])):
                with self.subTest(key=key, old=old, new=new):
                    f, full, row = self.fixture(before={key: old}, after={key: new})
                    with self.assertRaisesRegex(ValueError, 'INSPECT_FULL_PRESERVATION_CHANGED'):
                        self.check(f, full, row)
            f, full, row = self.fixture(before={key: ['one', 'two']}, after={key: ['one', 'two']})
            self.check(f, full, row)

    def test_missing_dns_key_is_not_empty_dns(self):
        for key in DNS:
            for mode in ('removed', 'added'):
                with self.subTest(key=key, mode=mode):
                    f, full, row = self.fixture(before={key: []} if mode == 'removed' else {})
                    if mode == 'removed':
                        del row['HostConfig'][key]
                    else:
                        row['HostConfig'][key] = None
                    with self.assertRaisesRegex(ValueError, 'INSPECT_FULL_PRESERVATION_CHANGED'):
                        self.check(f, full, row)

    def test_malformed_dns_is_rejected_in_baseline_and_current(self):
        for key in DNS:
            for value in ('', {}, False, 0, [None], [1]):
                with self.subTest(key=key, value=value):
                    with self.assertRaisesRegex(ValueError, 'INSPECT_DNS'):
                        self.fixture(before={key: value})
                    f, full, row = self.fixture(before={key: []}, after={key: value})
                    with self.assertRaisesRegex(ValueError, 'INSPECT_DNS'):
                        self.check(f, full, row)

    def test_untouched_rows_keep_raw_dns_equality_including_logger(self):
        for service in seq.SERVICES:
            for key in DNS:
                with self.subTest(service=service, key=key):
                    f, full, _ = self.fixture(service, {key: []})
                    row = deepcopy(f['before'][service])
                    row['HostConfig'][key] = None
                    with self.assertRaisesRegex(ValueError, 'INSPECT_UNTOUCHED_CHANGED'):
                        full.row(service, row, recreated=False, mounts_verified=row['Mounts'])

    def test_dns_normalization_never_masks_other_host_fields(self):
        for key, old, new in (('SecurityOpt', [], None), ('FutureHostField', [], None),
                              ('Privileged', False, True), ('ReadonlyRootfs', True, False)):
            with self.subTest(key=key):
                before = dict.fromkeys(DNS, [])
                after = dict.fromkeys(DNS, None)
                before[key], after[key] = old, new
                f, full, row = self.fixture(before=before, after=after)
                with self.assertRaisesRegex(ValueError, 'INSPECT_FULL_PRESERVATION_CHANGED'):
                    self.check(f, full, row)


class NoDepsLabelTests(unittest.TestCase):
    def package(self):
        package = pr.host_fixture()['package']
        for name in ('base.json', 'candidate.json'):
            package[name]['services']['postgresql']['depends_on'] = {
                'log': {'condition': 'service_started', 'required': True, 'restart': False}}
        package['model.json'] = compose.execution_model(package['base.json'], package['candidate.json'],
            resource_names={'networks': {'default': 'harbor_default'}, 'volumes': {}})
        return package

    def test_single_service_no_deps_label_is_empty_despite_model_dependency(self):
        package = self.package()
        before = deepcopy(package)
        session.assemble(package)
        self.assertEqual(before, package)
        self.assertIn('log', package['model.json']['services']['postgresql']['depends_on'])

    def test_full_model_dependency_label_rejected_before_claim_for_every_app(self):
        for service in seq.ORDER:
            with self.subTest(service=service):
                package = self.package()
                package['preservation.json']['after_labels'][service][DEPENDS] = 'log:service_started:false'
                with self.assertRaisesRegex(ValueError, 'SESSION_NO_DEPS_LABEL'):
                    session.assemble(package)

    def test_missing_generated_dependency_label_rejected(self):
        package = self.package()
        del package['preservation.json']['after_labels']['postgresql'][DEPENDS]
        with self.assertRaisesRegex(ValueError, 'SESSION_NO_DEPS_LABEL'):
            session.assemble(package)

    def test_current_label_remains_exact_not_auto_accepted(self):
        f = cb.fixture()
        row = cb.recreated(f, 'postgresql')
        row['Config']['Labels'][DEPENDS] = 'log:service_started:false'
        with self.assertRaisesRegex(ValueError, 'INSPECT_FULL_PRESERVATION_CHANGED'):
            f['full'].row('postgresql', row, recreated=True, mounts_verified=f['ma']['after']['postgresql'])


class SequenceMetadataTests(unittest.TestCase):
    def connected(self, bad_label=False):
        f = cb.fixture()
        for service in seq.ORDER:
            f['before'][service]['HostConfig'].update(dict.fromkeys(DNS, []))
            f['before'][service]['Config']['Labels'][DEPENDS] = 'log:service_started:false'
        f['full'] = inspect.FullPreservation(f['before'], after_labels=f['target_labels'],
            after_host_mounts=f['inherited'], auto_hostnames=list(seq.ORDER), auto_addresses=list(seq.ORDER))
        f['plan']['baseline'] = {s: f['full'].row(s, r, recreated=False, mounts_verified=r['Mounts'])
                                for s, r in f['before'].items()}
        connected = cb.ConnectedTests()
        with patch.object(cb, 'fixture', return_value=f):
            connected.setUp()
        def actual_metadata():
            service = connected.writes()[-1]
            row = connected.engine.rows[service]
            # Independent observed serializer values; do not copy target DNS/label.
            row['HostConfig'].update(dict.fromkeys(DNS, None))
            row['Config']['Labels'][DEPENDS] = 'unexpected' if bad_label else ''
        connected.after_write = actual_metadata
        return connected

    def test_nine_app_sequence_accepts_only_observed_empty_metadata_deltas(self):
        connected = self.connected()
        result = connected.run_it()
        self.assertEqual(result['status'], 'ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED')
        self.assertEqual(connected.writes(), list(seq.ORDER))
        self.assertFalse(result['runtime_acceptance'])

    def test_unexpected_dependency_label_stops_after_first_app_no_retry(self):
        connected = self.connected(bad_label=True)
        result = connected.run_it()
        self.assertEqual(result['status'], 'STOP_RECOVERY_REQUIRED')
        self.assertEqual(connected.writes(), ['postgresql'])


if __name__ == '__main__':
    unittest.main()
