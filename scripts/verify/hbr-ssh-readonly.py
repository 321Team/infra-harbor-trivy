#!/usr/bin/env python3
"""Candidate forced SSH command. No shell, sudo, Docker, upload or mutations."""
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import time

POLICY = Path('/etc/ssh/hbr-ssh-policy.json')
COMMANDS = {
    'identity': ['/usr/bin/id'],
    'network': ['/usr/sbin/ip', '-j', 'address', 'show'],
    'services': ['/usr/bin/systemctl', 'show', 'sshd.service', 'docker.service',
                 'NetworkManager.service', 'firewalld.service', '--no-pager',
                 '--property=Id,LoadState,ActiveState,SubState'],
}
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def require(ok):
    if not ok:
        raise ValueError('ACCESS_DENIED')


def load_policy(path=POLICY):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r', encoding='ascii') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                not info.st_mode & 0o022 and info.st_size <= 4096)
        return json.load(stream)


def authorize(policy, environ, username, uid, now):
    require(type(policy) is dict and set(policy) ==
            {'schema', 'host', 'guest', 'port', 'user', 'expires_epoch', 'allowed'})
    require(policy['schema'] == 1 and policy['host'] == '192.168.253.1' and
            policy['guest'] == '192.168.253.2' and policy['port'] == 22 and
            policy['user'] == 'hbrctl' and username == 'hbrctl' and uid != 0)
    require(type(policy['expires_epoch']) is int and now < policy['expires_epoch'])
    require(policy['allowed'] == ['identity', 'network', 'services'])
    connection = environ.get('SSH_CONNECTION', '').split()
    require(len(connection) == 4 and connection[0] == policy['host'] and
            connection[2] == policy['guest'] and connection[3] == '22' and
            connection[1].isdigit() and 0 < int(connection[1]) <= 65535)
    command = environ.get('SSH_ORIGINAL_COMMAND', '')
    require(command in COMMANDS)
    return command, list(COMMANDS[command])


def main():
    try:
        policy = load_policy()
        uid = os.getuid()
        command, argv = authorize(policy, os.environ, pwd.getpwuid(uid).pw_name, uid, time.time())
        # Bound execution at policy expiry too; a long-lived shell is never provided.
        timeout = min(10, policy['expires_epoch'] - time.time())
        require(timeout > 0)
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                env=ENV, cwd='/', timeout=timeout, check=False)
        print(json.dumps({'command': command, 'rc': result.returncode,
                          'observed_epoch': time.time(),
                          'stdout': result.stdout.decode('utf-8', errors='replace'),
                          'stderr': result.stderr.decode('utf-8', errors='replace')}))
        return 0 if result.returncode == 0 else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        print('SSH_READONLY_DENIED_OR_FAILED', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
