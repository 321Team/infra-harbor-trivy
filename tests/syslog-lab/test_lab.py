import importlib.util
import socket
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('lab', Path(__file__).resolve().parents[2]/'scripts/verify/syslog-startup-lab.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class Guards(unittest.TestCase):
    def test_only_github_hosted_expected_repository(self):
        env = {'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted',
               'RUNNER_OS':'Linux','GITHUB_REPOSITORY':'321Team/infra-harbor-trivy'}
        self.assertTrue(lab.permitted(env))
        for key in env:
            with self.subTest(key=key):
                self.assertFalse(lab.permitted({**env,key:'other'}))
                self.assertFalse(lab.permitted({k:v for k,v in env.items() if k!=key}))

    def test_cleanup_ownership_requires_full_id_and_exact_label(self):
        obj={'Id':'a'*64,'Config':{'Labels':{lab.LABEL:'run'}}}
        self.assertTrue(lab.owned(obj,'run'))
        self.assertFalse(lab.owned(obj,'foreign'))
        self.assertFalse(lab.owned({**obj,'Id':'a'*12},'run'))
        self.assertFalse(lab.owned({'Id':'a'*64,'Config':{}},'run'))

    def test_api_error_is_not_expected_refusal(self):
        self.assertTrue(lab.refused({'rc':1,'stderr':'failed to initialize logging driver: connection refused'}))
        for rc,err in [(0,'connection refused'),(124,'timeout'),(1,'permission denied'),(1,'connection refused')]:
            self.assertFalse(lab.refused({'rc':rc,'stderr':err}))

    def test_receiver_requires_actual_marker_and_closes(self):
        receiver=lab.Receiver()
        try:
            with socket.create_connection(('127.0.0.1',receiver.port),timeout=1) as client:
                client.sendall(b'FDS_TEST_MARKER\n')
            self.assertTrue(receiver.received('FDS_TEST_MARKER'))
        finally:
            receiver.close()
        self.assertFalse(receiver.thread.is_alive())


if __name__=='__main__': unittest.main()
