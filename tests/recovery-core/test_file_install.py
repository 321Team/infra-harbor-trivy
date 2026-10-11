"""Synthetic request/host/filesystem transactions. No target VM or Docker writes."""
from contextlib import contextmanager, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_review_package as fixtures
from test_host_provider import BOOT, LABEL, FakeIO

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/preparation/harbor_review_package_install.py'
loader = importlib.util.spec_from_file_location('file_install_subject', SCRIPT)
x = importlib.util.module_from_spec(loader)
loader.loader.exec_module(x)


class MemoryFS:
    """Test-only descriptors. Does not pretend to check actual OS/SELinux."""
    def __init__(self):
        self.dirs, self.rows, self.data, self.payloads = {}, {}, {}, []
        self.fail_file = None
        self.on_payload = lambda entry: None
        self.replaced = None
        self.next = 10

    @contextmanager
    def directory(self, path, spec, deadline):
        if path not in self.dirs:
            self.next += 1
            self.dirs[path] = self.next
            self.rows[self.next] = SimpleNamespace(st_dev=1, st_ino=self.next)
        fd = self.dirs[path]
        if self.replaced == path:
            fd += 1000
            self.rows[fd] = SimpleNamespace(st_dev=1, st_ino=fd)
        yield fd

    def absent(self, fd, name):
        if (fd, name) in self.data:
            raise ValueError('INSTALL_EXISTING_TARGET')

    @contextmanager
    def create(self, fd, name, context):
        self.absent(fd, name)
        self.next += 1
        journal = self.next
        self.data[(fd, name)] = bytearray()
        self.rows[journal] = self.data[(fd, name)]
        yield journal

    def write_all(self, fd, raw, deadline):
        self.rows[fd].extend(raw)

    def payload(self, fd, entry, raw, deadline):
        self.absent(fd, Path(entry['target']).name)
        self.data[(fd, Path(entry['target']).name)] = raw
        self.payloads.append(entry['file'])
        self.on_payload(entry)
        if entry['file'] == self.fail_file:
            raise OSError('private disk failure')

    def verify(self, fd, entry, raw, deadline):
        if self.data[(fd, Path(entry['target']).name)] != raw:
            raise ValueError('INSTALL_FINAL_READBACK')

    def journal(self):
        rows = [v for (fd, name), v in self.data.items() if name.endswith('.jsonl')]
        return [json.loads(line) for line in bytes(rows[0]).splitlines()] if rows else []


class Fixture:
    def setUp(self):
        builder = fixtures.PackageTests()
        builder.setUp()
        self.files, self.plan = builder.prepare()
        self.bundle = json.loads(self.files['bundle.json'])
        self.plan_sha = x.receipt.sha(self.files['INSTALL_PLAN.json'])
        parents = {str(Path(e['target']).parent).replace('\\', '/') for e in self.plan['files']}
        journal_parent = '/var/lib/fds-harbor-recovery/install-receipts'
        parents.add(journal_parent)
        self.request = {'schema':'fds.harbor.file-install-request.v1', 'operation':'NEW_FILES_ONLY',
            'plan_sha256':self.plan_sha, 'hostname':'harbor01', 'product_uuid':BOOT,
            'boot_id':BOOT, 'not_before_epoch':100, 'expires_epoch':200,
            'directories':{p:{'mode':0o700, 'gid':0, 'selinux':LABEL} for p in parents},
            'receipt_path':journal_parent+'/'+'c'*32+'.jsonl', 'receipt_context':LABEL}
        self.fs = MemoryFS()
        self.wall = 150
        self.now = 0
        self.preflight = lambda *args, **kwargs: None

    def execute(self, **kwargs):
        raw = x.encode(self.request)
        options = dict(execute=True, fs=self.fs, preflight=self.preflight,
                       clock=lambda:self.now, wall=lambda:self.wall)
        options.update(kwargs)
        with patch.object(x.os, 'fstat', side_effect=lambda fd:self.fs.rows[fd]), \
             patch.object(x.os, 'fsync'):
            return x.install(self.files, self.plan_sha, raw, x.receipt.sha(raw), 50, **options)


class TransactionTests(Fixture, unittest.TestCase):
    def test_full_new_files_only_launch_last_and_durable_receipt(self):
        with patch('builtins.exec', side_effect=AssertionError('candidate executed')):
            result = self.execute()
        self.assertEqual(result['status'], 'FILES_INSTALLED_ONLY')
        self.assertEqual(result['files'], 15)
        self.assertEqual(self.fs.payloads[-1], 'launch.json')
        self.assertEqual(result['runtime'], 'NOT_RUN')
        self.assertEqual(result['policy'], 'NOT_CHANGED')
        self.assertEqual(result['store_initialization'], 'NOT_RUN')
        records = self.fs.journal()
        self.assertEqual(records[0]['stage'], 'BEGIN')
        self.assertEqual(records[-1]['stage'], 'FILES_INSTALLED_ONLY')
        self.assertEqual(len([r for r in records if r['stage']=='CREATE_INTENT']),15)

    def test_explicit_execution_required_before_any_mutation(self):
        with self.assertRaisesRegex(ValueError, 'EXPLICIT'):
            self.execute(execute=False)
        self.assertEqual(self.fs.data, {})

    def test_bad_external_hash_or_changed_request_cannot_enroll_current_host(self):
        raw = x.encode(self.request)
        with self.assertRaisesRegex(ValueError, 'REQUEST_HASH'):
            x.request_bytes(raw, '0'*64, self.plan, self.bundle, wall=lambda:150)
        self.request['product_uuid'] = '00000000-0000-0000-0000-000000000000'
        with self.assertRaisesRegex(ValueError, 'IDENTITY'):
            self.execute()
        self.assertEqual(self.fs.data,{})

    def test_invalid_request_shapes_and_cross_package_binding(self):
        cases = [lambda r:r.update(operation='START'), lambda r:r.update(extra='private'),
                 lambda r:r.update(not_before_epoch=True), lambda r:r.update(expires_epoch=float('inf')),
                 lambda r:r.update(plan_sha256='0'*64), lambda r:r.update(boot_id='unknown'),
                 lambda r:r.update(receipt_path='/root/arbitrary.jsonl'),
                 lambda r:r['directories'].pop(next(iter(r['directories']))),
                 lambda r:r['directories'].update({'/root/extra':{'gid':0,'mode':0o700,'selinux':LABEL}})]
        original = deepcopy(self.request)
        for change in cases:
            self.request = deepcopy(original)
            change(self.request)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.execute()
            self.assertEqual(self.fs.data,{})

    def test_expired_or_not_started_window_stops_without_creating_receipt(self):
        for value in (99,200,201):
            self.wall = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'WINDOW'):
                self.execute()
            self.assertEqual(self.fs.data,{})

    def test_any_existing_target_blocks_all_new_writes_and_keeps_old_bytes(self):
        entry = self.plan['files'][-1]
        parent = str(Path(entry['target']).parent).replace('\\','/')
        with self.fs.directory(parent,{},50) as fd:
            self.fs.data[(fd,Path(entry['target']).name)] = b'ORIGINAL'
        before = deepcopy(self.fs.data)
        with self.assertRaisesRegex(ValueError, 'EXISTING_TARGET'):
            self.execute()
        self.assertEqual(self.fs.data,before)
        self.assertEqual(self.fs.journal(),[])

    def test_existing_receipt_prevents_rerun_even_without_any_payload(self):
        parent = '/var/lib/fds-harbor-recovery/install-receipts'
        with self.fs.directory(parent,{},50) as fd:
            self.fs.data[(fd,'c'*32+'.jsonl')] = b'prior interrupted evidence\n'
        before = deepcopy(self.fs.data)
        with self.assertRaisesRegex(ValueError, 'EXISTING_TARGET'):
            self.execute()
        self.assertEqual(self.fs.data,before)

    def test_partial_write_kept_and_next_write_not_attempted(self):
        self.fs.fail_file = 'harbor_recovery_control.py'
        with self.assertRaises(OSError):
            self.execute()
        self.assertEqual(self.fs.payloads[-1], self.fs.fail_file)
        self.assertNotIn('launch.json',self.fs.payloads)
        rows = self.fs.journal()
        self.assertEqual(rows[-2]['stage'],'CREATE_INTENT')
        self.assertEqual(rows[-1]['stage'],'STOP_PRESERVE_PARTIAL')
        self.assertNotIn(self.fs.fail_file,rows[-1]['verified_files'])

    def test_expiry_or_boot_drift_after_first_write_preserves_partial(self):
        self.fs.on_payload = lambda _:setattr(self,'wall',200)
        with self.assertRaisesRegex(ValueError,'WINDOW'):
            self.execute()
        self.assertEqual(len(self.fs.payloads),1)
        self.assertEqual(self.fs.journal()[-1]['stage'],'STOP_PRESERVE_PARTIAL')

    def test_postflight_failure_does_not_report_success_or_undo_files(self):
        def preflight(*args,**kwargs):
            if len(self.fs.payloads) == 15:
                raise ValueError('generation drift')
        self.preflight = preflight
        with self.assertRaisesRegex(ValueError,'generation drift'):
            self.execute()
        self.assertEqual(len(self.fs.payloads),15)
        self.assertEqual(self.fs.journal()[-1]['stage'],'STOP_PRESERVE_PARTIAL')

    def test_directory_replaced_after_write_blocks_next_and_preserves_original_fd(self):
        self.fs.on_payload = lambda e:setattr(self.fs,'replaced',str(Path(e['target']).parent).replace('\\','/'))
        with self.assertRaisesRegex(ValueError,'DIRECTORY_REPLACED'):
            self.execute()
        self.assertEqual(len(self.fs.payloads),1)

    def test_earlier_file_drift_detected_by_final_readback(self):
        def corrupt(entry):
            if entry['file'] == 'launch.json':
                bundle_name = Path(next(e['target'] for e in self.plan['files']
                                        if e['file']=='bundle.json')).name
                key = next(k for k in self.fs.data if k[1]==bundle_name)
                self.fs.data[key] = b'CHANGED'
        self.fs.on_payload = corrupt
        with self.assertRaisesRegex(ValueError,'FINAL_READBACK'):
            self.execute()
        self.assertEqual(self.fs.journal()[-1]['stage'],'STOP_PRESERVE_PARTIAL')

    def test_no_execute_cli_never_reads_inputs_and_sanitizes_output(self):
        output = io.StringIO()
        with redirect_stdout(output), patch.object(x.receipt,'read_package') as read:
            rc = x.main(['--package','private', '--plan-sha256','0'*64,
                         '--request','private','--request-sha256','0'*64,'--timeout','30'])
        self.assertEqual(rc,2)
        read.assert_not_called()
        self.assertNotIn('private',output.getvalue())


class PreflightTests(Fixture, unittest.TestCase):
    def make(self):
        io = FakeIO(self.bundle['host_policy'])
        run = io.run
        self.row = dict(LoadState='not-found',ActiveState='inactive',SubState='dead',UnitFileState='',
            MainPID='0',ControlPID='0',FragmentPath='',DropInPaths='',NeedDaemonReload='no',
            Job='',TriggeredBy='',Transient='no')
        def manager(argv,cwd,deadline):
            if argv[1:3] == ['show',x.MANAGER]:
                return ''.join(f'{k}={v}\n' for k,v in self.row.items()).encode()
            return run(argv,cwd,deadline)
        io.run = manager
        probe = x.Preflight(self.bundle,self.plan,io=io,clock=lambda:0)
        probe.host.engine = SimpleNamespace(profile=lambda _:self.bundle['host_policy']['engine_profile'])
        return probe, io

    def test_correct_host_isolation_and_external_pins_before_only_read_commands(self):
        probe, io = self.make()
        probe(self.request,50)
        self.assertTrue(set(self.plan['external_existing_inputs']) <= {p for p,k in io.pin_calls})
        self.assertFalse(any(arg in ('start','stop','enable','disable','daemon-reload')
                             for call in io.calls for arg in call))

    def test_wrong_boot_nic_hgfs_enforcing_or_external_pin_stops(self):
        for change in (lambda i:i.stamp.update(boot='00000000-0000-0000-0000-000000000000'),
                       lambda i:i.stamp.update(physical_nics=True),
                       lambda i:i.stamp.update(mountinfo='fuse.vmhgfs-fuse'),
                       lambda i:i.outputs.update(getenforce=b'Permissive')):
            probe, io = self.make()
            change(io)
            with self.subTest(change=change),self.assertRaises(ValueError):
                probe(self.request,50)
        probe, io = self.make()
        io.on_pin = lambda path:(_ for _ in ()).throw(ValueError('pin mismatch'))
        with self.assertRaisesRegex(ValueError,'pin mismatch'):
            probe(self.request,50)

    def test_running_enabled_transient_triggered_or_loaded_old_manager_blocks(self):
        for field,value in (('ActiveState','active'),('MainPID','1'),('UnitFileState','enabled'),
                            ('Transient','yes'),('Job','1'),('TriggeredBy','timer.service'),
                            ('LoadState','loaded'),('DropInPaths','/etc/evil.conf')):
            probe,io = self.make()
            self.row[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                probe(self.request,50)

    def test_only_after_install_accepts_exact_disabled_loaded_unit(self):
        probe,io = self.make()
        self.row.update(LoadState='loaded',UnitFileState='disabled',
                        FragmentPath=self.bundle['manager']['fragment'],NeedDaemonReload='yes')
        with self.assertRaises(ValueError):probe(self.request,50)
        probe(self.request,50,after=True)


@unittest.skipUnless(sys.platform=='linux','descriptor-relative Linux filesystem')
class LinuxFileTests(unittest.TestCase):
    def test_new_payload_exact_readback_and_no_overwrite_symlink_or_hardlink(self):
        with tempfile.TemporaryDirectory() as folder:
            fd = os.open(folder,os.O_RDONLY | os.O_DIRECTORY)
            try:
                fs = x.NewFiles(uid=os.getuid(),gid=os.getgid())
                fs.attrs = lambda *args:None  # No claim of SELinux validation.
                raw = b'approved bytes\n'
                entry = dict(target='/synthetic/file.py',mode=0o444,selinux=LABEL,sha256=x.receipt.sha(raw))
                import time
                deadline=time.monotonic()+10
                fs.payload(fd,entry,raw,deadline)
                fs.verify(fd,entry,raw,deadline)
                with self.assertRaises(FileExistsError):fs.payload(fd,entry,b'other',deadline)
                os.symlink('file.py',Path(folder)/'link')
                os.link(Path(folder)/'file.py',Path(folder)/'hard')
                for name in ('link','hard'):
                    with self.subTest(name=name),self.assertRaises(ValueError):fs.absent(fd,name)
                with self.assertRaisesRegex(ValueError,'METADATA'):fs.verify(fd,entry,raw,deadline)
                self.assertEqual((Path(folder)/'file.py').read_bytes(),raw)
            finally:os.close(fd)

    def test_wrong_inherited_label_stops_before_writing_and_keeps_empty_file(self):
        with tempfile.TemporaryDirectory() as folder:
            fd=os.open(folder,os.O_RDONLY | os.O_DIRECTORY)
            try:
                fs=x.NewFiles(uid=os.getuid(),gid=os.getgid())
                fs.attrs=lambda *args:(_ for _ in ()).throw(ValueError('INSTALL_CONTEXT'))
                with self.assertRaisesRegex(ValueError,'CONTEXT'):
                    fs.payload(fd,dict(target='/synthetic/file',mode=0o600,selinux=LABEL),b'private',1e20)
                self.assertEqual((Path(folder)/'file').read_bytes(),b'')
            finally:os.close(fd)


if __name__ == '__main__':
    unittest.main()
