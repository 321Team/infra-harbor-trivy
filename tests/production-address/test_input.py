"""SYNTHETIC Compose model tests; no env files, guest, Docker or credentials."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('address_input',Path(__file__).resolve().parents[2]/'scripts/production/harbor_address_input.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def fixture():
    return {'name':'synthetic','services':{s:{'image':'synthetic:only','environment':{'FAKE':'literal-$TOKEN-${TOKEN:-x}-$$-end'},
        'volumes':[{'type':'bind','source':'/synthetic/path','target':'/data','read_only':True}]}
        for s in m.SERVICES}}


class InputTests(unittest.TestCase):
    def test_missing_false_explicit_and_original_unchanged(self):
        x=fixture();old=deepcopy(x);r=m.expected_model(x)
        self.assertEqual(x,old)
        self.assertTrue(all(s['volumes'][0]['bind']=={'create_host_path':False} for s in r['services'].values()))

    def test_explicit_values_and_selinux_preserved(self):
        for flag in (False,True):
            x=fixture();x['services']['core']['volumes'][0]['bind']={'create_host_path':flag,'selinux':'z'}
            self.assertEqual(m.expected_model(x)['services']['core']['volumes'],x['services']['core']['volumes'])

    def test_existing_absolute_directory_trailing_slash_preserved(self):
        x=fixture();x['services']['core']['volumes'][0]['source']='/synthetic/path/'
        self.assertEqual(m.expected_model(x)['services']['core']['volumes'][0]['source'],'/synthetic/path/')

    def test_all_string_values_escaped_once_keys_unchanged(self):
        x=fixture();x['services']['core']['labels']={'literal$key':'x$y'}
        r=json.loads(m.encode_stdin(x))
        self.assertEqual(r['services']['core']['environment']['FAKE'],'literal-$$TOKEN-$${TOKEN:-x}-$$$$-end')
        self.assertEqual(r['services']['core']['labels'],{'literal$key':'x$$y'})

    def test_exact_render_matches_but_not_a_runtime_result(self):
        x=fixture();r=m.validate_rendered(x,m.expected_model(x))
        self.assertEqual(r['runtime_apply'],'NOT_PERFORMED')

    def test_no_implicit_true_tolerance_after_render(self):
        x=fixture();r=m.expected_model(x);r['services']['core']['volumes'][0]['bind']['create_host_path']=True
        with self.assertRaisesRegex(ValueError,'ROUNDTRIP'):m.validate_rendered(x,r)

    def test_unresolved_inputs_refused(self):
        for field,value in [('env_file',['/synthetic/env']),('build','/synthetic'),('extends',{'service':'x'}),('secrets',['x']),('configs',['x'])]:
            x=fixture();x['services']['core'][field]=value
            with self.assertRaisesRegex(ValueError,'UNRESOLVED'):m.encode_stdin(x)

    def test_top_level_external_sources_refused(self):
        for key in ('include','secrets','configs'):
            x=fixture();x[key]={'synthetic':{}}
            with self.assertRaisesRegex(ValueError,'EXTERNAL_SOURCE'):m.encode_stdin(x)

    def test_inherited_or_null_environment_refused(self):
        for value in (None,True,5):
            x=fixture();x['services']['core']['environment']['FAKE']=value
            with self.assertRaisesRegex(ValueError,'UNRESOLVED_ENV'):m.encode_stdin(x)

    def test_relative_traversal_duplicate_or_non_boolean_bind_refused(self):
        for source in ('relative','/x/../y','/x//y','/x\0y'):
            x=fixture();x['services']['core']['volumes'][0]['source']=source
            with self.assertRaisesRegex(ValueError,'BIND_SOURCE'):m.encode_stdin(x)
        x=fixture();v=x['services']['core']['volumes'];v.append(deepcopy(v[0]))
        with self.assertRaisesRegex(ValueError,'INPUT_MOUNT'):m.encode_stdin(x)
        x=fixture();x['services']['core']['volumes'][0]['bind']={'create_host_path':1}
        with self.assertRaisesRegex(ValueError,'BIND_OPTIONS'):m.encode_stdin(x)

    def test_changes_to_any_rendered_config_fail_without_sensitive_diagnostics(self):
        x=fixture();r=m.expected_model(x);r['services']['core']['environment']['FAKE']='SYNTHETIC_SECRET_MARKER'
        with self.assertRaisesRegex(ValueError,'^INPUT_ROUNDTRIP_CHANGED$') as ctx:m.validate_rendered(x,r)
        self.assertNotIn('SYNTHETIC_SECRET_MARKER',str(ctx.exception))

    def test_json_type_change_is_not_equal(self):
        x=fixture();r=m.expected_model(x);r['services']['core']['volumes'][0]['read_only']=1
        with self.assertRaisesRegex(ValueError,'ROUNDTRIP'):m.validate_rendered(x,r)

    def test_unknown_service_and_nonfinite_size_refused(self):
        x=fixture();x['services']['other']={}
        with self.assertRaises(ValueError):m.encode_stdin(x)
        x=fixture();x['x-float']=float('nan')
        with self.assertRaisesRegex(ValueError,'JSON'):m.encode_stdin(x)
        x=fixture();x['x-large']='a'*(m.MAX_BYTES+1)
        with self.assertRaisesRegex(ValueError,'SIZE'):m.encode_stdin(x)


if __name__=='__main__':unittest.main()
