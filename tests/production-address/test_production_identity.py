"""Bounded kernel UUID read regression; no guest mutation or real Docker."""
import errno
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts/production'),str(ROOT/'scripts/recovery')]
import harbor_address_host as h


class ProductionIdentityTests(unittest.TestCase):
    def read(self,product=b'11111111-1111-1111-1111-111111111111\n',
             boot=b'22222222-2222-2222-2222-222222222222\n',fault=None):
        calls=[]
        class Kernel(io.BytesIO):
            def read(self,count=-1):
                calls.append(count)
                if count>8192:raise OSError(errno.ENOMEM,'bounded kernel read reproduction')
                if fault:raise fault
                return super().read(count)
        payloads={'/sys/class/dmi/id/product_uuid':product,
                  '/proc/sys/kernel/random/boot_id':boot}
        def opened(path,mode):
            self.assertEqual(mode,'rb')
            self.assertIn(path,payloads)  # no mountinfo or NIC enumeration
            return Kernel(payloads[path])
        with patch.object(h.sys,'platform','linux'),patch.object(h.os,'geteuid',return_value=0,create=True),\
             patch.object(h.socket,'gethostname',return_value='harbor01'),patch('builtins.open',side_effect=opened):
            value=h.ProductionReadOnly().identity()
        self.assertEqual(calls,[129,129])
        return value

    def test_small_reads_avoid_reproduced_large_sysctl_enomem(self):
        self.assertEqual(self.read(),dict(hostname='harbor01',
            product_uuid='11111111-1111-1111-1111-111111111111',
            boot='22222222-2222-2222-2222-222222222222'))

    def test_changed_generation_is_returned_not_cached(self):
        self.assertEqual(self.read(boot=b'33333333-3333-3333-3333-333333333333\n')['boot'],
                         '33333333-3333-3333-3333-333333333333')

    def test_missing_malformed_and_overlong_identity_fail_closed(self):
        for raw in (b'',b'not-a-uuid',b'1'*129,b'\xff',b'11111111111111111111111111111111'):
            with self.subTest(raw_length=len(raw)),self.assertRaises((ValueError,UnicodeError)):
                self.read(boot=raw)
        with self.assertRaises(OSError):self.read(fault=OSError(errno.EIO,'synthetic'))

    def test_non_root_or_non_linux_do_not_open_kernel_paths(self):
        for platform,uid in (('win32',0),('linux',1000)):
            with patch.object(h.sys,'platform',platform),patch.object(h.os,'geteuid',return_value=uid,create=True),\
                 patch('builtins.open') as opened,self.assertRaisesRegex(ValueError,'HOST_LINUX_ROOT_REQUIRED'):
                h.ProductionReadOnly().identity()
            opened.assert_not_called()


if __name__=='__main__':unittest.main()
