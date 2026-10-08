"""Disposable Ubuntu CI parser checks only; never used on the Harbor VM."""
import json
from pathlib import Path
import subprocess
import tempfile
import time

from test_ssh_plan import KEY, renderer


def call(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=True)
    return result.stdout


with tempfile.TemporaryDirectory(prefix='hbr-syntax-') as directory:
    root = Path(directory)
    files = renderer.render('ens192', '00:50:56:30:00:02', KEY, int(time.time()) + 3600)
    nft = root / 'guard.nft'
    nft.write_text(files['hbr-mgmt.nft.candidate'])
    call(['sudo', 'unshare', '--net', '--', '/usr/sbin/nft', '--check', '--file', str(nft)])
    # Throwaway CI host key, not a client or deployment key. Never print or upload it.
    host_key = root / 'host_key'
    call(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(host_key)])
    config = root / 'sshd_config'
    config.write_text('HostKey ' + str(host_key) + '\nUsePAM yes\n' + files['00-hbr-mgmt-sshd.conf.candidate'])
    call(['sudo', '/usr/sbin/sshd', '-t', '-f', str(config)])
    for user, peer in [('hbrctl', '192.168.253.1'), ('server08', '192.168.253.1'),
                       ('root', '192.168.253.1'), ('hbrctl', '192.168.253.3')]:
        text = call(['sudo', '/usr/sbin/sshd', '-T', '-f', str(config), '-C',
                     f'user={user},host=harbor01,addr={peer},laddr=192.168.253.2,lport=22'])
        values = dict(line.split(' ', 1) for line in text.splitlines() if ' ' in line)
        assert values['allowusers'] == 'hbrctl@192.168.253.1'
        assert values['passwordauthentication'] == 'no'
        assert values['disableforwarding'] == 'yes'
        assert values['authenticationmethods'] == 'publickey'
        assert values['forcecommand'] == '/usr/bin/python3 -I /usr/local/libexec/hbr-ssh-readonly.py'
    print(json.dumps({'environment': 'disposable Ubuntu CI', 'nft_check': 'PASS',
                      'sshd_syntax_and_four_contexts': 'PASS', 'guest_runtime': 'NOT_RUN'}))
