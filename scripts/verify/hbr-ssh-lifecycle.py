#!/usr/bin/env python3
"""Reviewed-source candidate: install disconnected; one bounded session; undo disconnected.

No Docker commands, runtime restart, snapshot operations or existing guard changes.
All command output stays in root-private installation receipts.
"""
import argparse
import datetime
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import stat
import subprocess
import sys
import time

ROOT = Path('/var/lib/hbr-ssh-control')
STATE = ROOT / 'state.json'
SELF = Path('/usr/local/libexec/hbr-ssh-lifecycle.py')
UUIDS = {'564d9e38-f024-efe2-b68f-137a5047788a', '389e4d56-24f0-e2ef-b68f-137a5047788a'}
OLD = ('6b9f0643-4a4e-324d-a969-9e5393d7e0bf', '3094c330-0b11-4463-9409-29c11bca6fcb')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
NMCONF = Path('/etc/NetworkManager/conf.d/90-hbr-no-auto-default.conf')
ZONE = Path('/etc/firewalld/zones/hbr-mgmt.xml')
NFT = ROOT / 'hbr-mgmt.nft'
SSHD = Path('/etc/ssh/sshd_config.d/00-hbr-mgmt-sshd.conf')
KEY = Path('/etc/ssh/hbr-mgmt-authorized_keys')
POLICY = Path('/etc/ssh/hbr-ssh-policy.json')
ENDPOINT = Path('/usr/local/libexec/hbr-ssh-readonly.py')
UNIT = Path('/etc/systemd/system/hbr-ssh-session.service')
EXPIRE = Path('/etc/systemd/system/hbr-ssh-expire.service')
TIMER = Path('/etc/systemd/system/hbr-ssh-expire.timer')
FILES = {'90-hbr-no-auto-default.conf.candidate': NMCONF,
         'hbr-mgmt.xml.candidate': ZONE, 'hbr-mgmt.nft.candidate': NFT,
         '00-hbr-mgmt-sshd.conf.candidate': SSHD, 'authorized_keys.candidate': KEY,
         'hbr-ssh-policy.json.candidate': POLICY}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def trusted_parents(path):
    for parent in Path(path).parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
                not info.st_mode & 0o022, 'UNTRUSTED_PARENT')


def read_safe(path, limit=1048576):
    # Fixed system parent directories must also remain root-owned/non-writable.
    trusted_parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                not info.st_mode & 0o022 and info.st_size <= limit, 'UNTRUSTED_FILE')
        return stream.read()


def save(state):
    temporary = ROOT / 'state.new'
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(state, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(STATE)


def run(argv, state=None, check=True):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                            env=ENV, cwd='/', timeout=20, check=False)
    text = result.stdout.decode('utf-8', errors='strict').strip()
    if state is not None:
        state.setdefault('commands', []).append({'argv': argv, 'rc': result.returncode,
             'at': time.time(), 'stdout': text, 'stderr': result.stderr.decode('utf-8', errors='replace')})
        save(state)
    require(not check or result.returncode == 0, 'COMMAND_FAILED: ' + argv[0])
    return result.returncode, text


def physical():
    return sorted(p.name for p in Path('/sys/class/net').iterdir() if (p / 'device').exists())


def identity_guard():
    require(os.geteuid() == 0 and socket.gethostname().split('.')[0] == 'harbor01', 'HOST_OR_UID')
    uuid = Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()
    require(uuid in UUIDS, 'VM_UUID')


def host_guard(disconnected=False):
    identity_guard()
    require(run(['/usr/sbin/getenforce'])[1] == 'Enforcing', 'SELINUX')
    require('hgfs' not in Path('/proc/self/mountinfo').read_text().lower(), 'HGFS_MOUNT')
    if disconnected:
        require(not physical(), 'PHYSICAL_NIC_PRESENT')


def load_state():
    state = json.loads(read_safe(STATE))
    require(state['schema'] == 1 and state['old_profiles'] == list(OLD), 'STATE_SCHEMA')
    return state


def verify_files(state):
    for path, digest in state['files'].items():
        require(sha(read_safe(Path(path))) == digest, 'INSTALLED_FILE_CHANGED: ' + path)


def ssh_guard():
    run(['/usr/sbin/sshd', '-t'])
    expected = {'allowusers': 'hbrctl@192.168.253.1', 'authenticationmethods': 'publickey',
                'pubkeyauthentication': 'yes', 'passwordauthentication': 'no',
                'kbdinteractiveauthentication': 'no', 'permitrootlogin': 'no',
                'authorizedkeysfile': str(KEY), 'authorizedkeyscommand': 'none',
                'trustedusercakeys': 'none', 'disableforwarding': 'yes',
                'permittunnel': 'no', 'permittty': 'no', 'permituserrc': 'no',
                'maxsessions': '1',
                'forcecommand': '/usr/bin/python3 -I ' + str(ENDPOINT)}
    for user, peer in [('hbrctl', '192.168.253.1'), ('root', '192.168.253.1'),
                       ('server08', '192.168.253.1'), ('hbrctl', '192.168.253.3')]:
        context = f'user={user},host=harbor01,addr={peer},laddr=192.168.253.2,lport=22'
        output = run(['/usr/sbin/sshd', '-T', '-C', context])[1]
        values = dict(line.split(' ', 1) for line in output.splitlines() if ' ' in line)
        require(all(values.get(k) == v for k, v in expected.items()), 'SSHD_EFFECTIVE')


def nft_shape(raw):
    # Counters/handles change naturally; chain/rule structure and order must not.
    def clean(value):
        if isinstance(value, dict):
            return {k: ({} if k == 'counter' else clean(v)) for k, v in value.items()
                    if k not in ('handle', 'metainfo')}
        if isinstance(value, list):
            return [clean(v) for v in value]
        return value
    return clean(json.loads(raw))


def current_nft():
    return nft_shape(run(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'hbr_ssh_guard'])[1])


def old_profiles_off():
    for uuid in OLD:
        require(run(['/usr/bin/nmcli', '-g', 'connection.autoconnect', 'connection', 'show', uuid])[1] == 'no',
                'OLD_AUTOCONNECT')


def network_guard(state, active=False):
    plan = state['plan']
    iface = plan['interface']
    require(physical() == [iface], 'NIC_SET')
    require(Path('/sys/class/net', iface, 'address').read_text().strip() == plan['mac'], 'NIC_MAC')
    require(run(['/usr/bin/nmcli', '-g', 'GENERAL.STATE', 'device', 'show', iface])[1].startswith('10 '),
            'NIC_MUST_BE_UNMANAGED')
    rows = json.loads(run(['/usr/sbin/ip', '-j', 'address', 'show'])[1])
    validate_addresses(rows, iface, active)
    require(address_shape(rows, exclude=iface) == state['baseline_addresses'], 'OTHER_ADDRESS_DRIFT')
    for family in ('-4', '-6'):
        routes = json.loads(run(['/usr/sbin/ip', '-j', family, 'route', 'show', 'table', 'all'])[1])
        require(all(r.get('dst') != 'default' and 'gateway' not in r for r in routes), 'DEFAULT_OR_GATEWAY')
        other = [r for r in routes if r.get('dev') != iface]
        require(other == state['baseline_routes'][family], 'OTHER_ROUTE_DRIFT')
        own = [r for r in routes if r.get('dev') == iface]
        allowed = {'192.168.253.0/24', '192.168.253.0', '192.168.253.2', '192.168.253.255'}
        require(all(active and family == '-4' and r.get('dst') in allowed for r in own), 'MGMT_ROUTE_DRIFT')
    old_profiles_off()


def validate_addresses(rows, iface, active):
    targets = [row for row in rows if row['ifname'] == iface]
    require(len(targets) == 1, 'INTERFACE_NOT_FOUND')
    target = targets[0]
    addresses = target.get('addr_info', [])
    require(('UP' in target.get('flags', [])) == active, 'LINK_STATE')
    expected = [('inet', '192.168.253.2', 24)] if active else []
    require([(a['family'], a['local'], a['prefixlen']) for a in addresses] == expected, 'MGMT_ADDRESSES')
    for row in rows:
        for address in row.get('addr_info', []):
            value = address['local']
            require(not value.startswith(('10.', '192.168.10.', '192.168.253.1')), 'FORBIDDEN_ADDRESS')


def address_shape(rows, exclude=None):
    return {r['ifname']: sorted([a['family'], a['local'], a['prefixlen']]
            for a in r.get('addr_info', [])) for r in rows if r['ifname'] != exclude}


def verify_account(state):
    account = pwd.getpwnam('hbrctl')
    require(account.pw_uid == state['uid'] and account.pw_gid == state['gid'] and
            account.pw_dir == '/nonexistent' and account.pw_shell == '/bin/sh', 'ACCOUNT_DRIFT')
    require(os.getgrouplist('hbrctl', account.pw_gid) == [account.pw_gid], 'ACCOUNT_EXTRA_GROUPS')
    return account


def install(bundle, source):
    host_guard(disconnected=True)
    require(not ROOT.exists(), 'INSTALL_ALREADY_ATTEMPTED')
    plan = json.loads(read_safe(bundle / 'plan.json'))
    require(time.time() < plan['expires_epoch'] <= time.time() + 14400, 'EXPIRED')
    # Execute only this exact-source sibling generator, never code from the candidate bundle.
    renderer_path = source / 'render-clone-ssh-plan.py'
    read_safe(renderer_path)
    spec = importlib.util.spec_from_file_location('renderer', renderer_path)
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    line = read_safe(bundle / 'authorized_keys.candidate').decode('ascii')
    key = line.split(' ', 1)[1].strip()
    expected = renderer.render(plan['interface'], plan['mac'], key, plan['expires_epoch'])
    for name, text in expected.items():
        require(read_safe(bundle / name) == text.encode('utf-8'), 'BUNDLE_CONTENT: ' + name)
    try:
        pwd.getpwnam('hbrctl')
        raise ValueError('ACCOUNT_EXISTS')
    except KeyError:
        pass
    try:
        grp.getgrnam('hbrctl')
        raise ValueError('GROUP_EXISTS')
    except KeyError:
        pass
    paths = list(FILES.values()) + [SELF, ENDPOINT, UNIT, EXPIRE, TIMER]
    require(all(not p.exists() and not p.is_symlink() for p in paths), 'INSTALL_PATH_EXISTS')
    require(all(p.parent.is_dir() for p in paths if p != NFT), 'INSTALL_PARENT_MISSING')
    for path in paths:
        if path != NFT:
            trusted_parents(path)
    require(run(['/usr/sbin/nft', 'list', 'tables'])[1].find('hbr_ssh_guard') == -1, 'NFT_TABLE_EXISTS')
    for uuid in OLD:
        require(run(['/usr/bin/nmcli', '-g', 'connection.autoconnect', 'connection', 'show', uuid])[1] == 'yes',
                'OLD_PROFILE_DRIFT')
    for uuid in run(['/usr/bin/nmcli', '-g', 'UUID', 'connection', 'show'])[1].splitlines():
        kind = run(['/usr/bin/nmcli', '-g', 'connection.type', 'connection', 'show', uuid])[1]
        require(kind != '802-3-ethernet' or uuid in OLD, 'UNKNOWN_WIRED_PROFILE')
    run(['/usr/sbin/sshd', '-t'])
    ROOT.mkdir(mode=0o700)
    state = {'schema': 1, 'status': 'INSTALLING', 'old_profiles': list(OLD),
             'plan': plan, 'files': {}, 'commands': [], 'account_attempted': False,
             'old_attempted': [], 'started_epoch': time.time(),
             'source_sha256': {name: sha(read_safe(source / name)) for name in
                ('render-clone-ssh-plan.py', 'hbr-ssh-lifecycle.py', 'hbr-ssh-readonly.py')}}
    save(state)
    try:
        baseline = json.loads(run(['/usr/sbin/ip', '-j', 'address', 'show'], state)[1])
        # JSON round trip gives a stable list representation on initial and later loads.
        state['baseline_addresses'] = json.loads(json.dumps(address_shape(baseline)))
        state['baseline_routes'] = {}
        for family in ('-4', '-6'):
            routes = json.loads(run(['/usr/sbin/ip', '-j', family, 'route', 'show', 'table', 'all'], state)[1])
            require(all(r.get('dst') != 'default' and 'gateway' not in r for r in routes), 'BASELINE_ROUTE')
            state['baseline_routes'][family] = routes
        save(state)
        for uuid in OLD:
            state['old_attempted'].append(uuid)
            save(state)
            run(['/usr/bin/nmcli', 'connection', 'modify', uuid, 'connection.autoconnect', 'no'], state)
        for name, target in FILES.items():
            write_owned(target, expected[name].encode('utf-8'), state)
        for src, target in [(source / 'hbr-ssh-lifecycle.py', SELF), (source / 'hbr-ssh-readonly.py', ENDPOINT)]:
            write_owned(target, read_safe(src), state)
        iface = plan['interface']
        unit = f'''[Unit]
Description=One bounded isolated Harbor SSH session
BindsTo=NetworkManager.service firewalld.service
After=NetworkManager.service firewalld.service sshd.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 -I {SELF} session
ExecStopPost=-/usr/sbin/ip link set dev {iface} down
ExecStopPost=-/usr/bin/python3 -I {SELF} disconnect
KillMode=control-group
TimeoutStopSec=30
Restart=no
'''
        write_owned(UNIT, unit.encode('ascii'), state)
        expire = f'''[Unit]
Description=Disconnect expired Harbor management session
[Service]
Type=oneshot
ExecStart=-/usr/sbin/ip link set dev {iface} down
ExecStart=/usr/bin/systemctl stop hbr-ssh-session.service
ExecStart=/usr/bin/python3 -I {SELF} disconnect
'''
        when = datetime.datetime.fromtimestamp(plan['expires_epoch'], datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        timer = f'''[Unit]
Description=Absolute expiry for Harbor management session
[Timer]
OnCalendar={when}
AccuracySec=1s
RandomizedDelaySec=0
Persistent=false
Unit=hbr-ssh-expire.service
'''
        write_owned(EXPIRE, expire.encode('ascii'), state)
        write_owned(TIMER, timer.encode('ascii'), state)
        run(['/usr/sbin/restorecon', '-F', *[str(p) for p in paths]], state)
        state['account_attempted'] = True
        save(state)
        run(['/usr/sbin/useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent',
             '--shell', '/bin/sh', '--user-group', 'hbrctl'], state)
        state['uid'] = pwd.getpwnam('hbrctl').pw_uid
        state['gid'] = pwd.getpwnam('hbrctl').pw_gid
        save(state)
        run(['/usr/bin/nmcli', 'general', 'reload', 'conf'], state)
        old_profiles_off()
        run(['/usr/bin/firewall-cmd', '--check-config'], state)
        run(['/usr/bin/firewall-cmd', '--reload'], state)
        run(['/usr/sbin/nft', '-c', '-f', str(NFT)], state)
        run(['/usr/sbin/nft', '-f', str(NFT)], state)
        state['nft_shape'] = current_nft()
        save(state)
        ssh_guard()
        run(['/usr/bin/systemctl', 'reload', 'sshd.service'], state)
        run(['/usr/bin/systemctl', 'daemon-reload'], state)
        run(['/usr/bin/systemctl', 'start', 'hbr-ssh-expire.timer'], state)
        host_guard(disconnected=True)
        require(time.time() < plan['expires_epoch'], 'EXPIRED_DURING_INSTALL')
        state['status'] = 'INSTALLED_LINK_DISABLED'
        save(state)
        print(state['status'])
    except BaseException:
        state['status'] = 'INSTALL_FAILED_CONSOLE_ROLLBACK_REQUIRED'
        save(state)
        raise


def write_owned(path, data, state):
    # Record intended ownership before creation so a partial write is visible to recovery.
    state['files'][str(path)] = sha(data)
    save(state)
    with path.open('xb') as stream:
        os.chmod(path, 0o644 if path != NFT else 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def gate_valid(gate, plan, now):
    require(type(gate) is dict and all(type(gate.get(k)) is bool for k in
            ('host_only', 'dhcp', 'nat', 'bridge', 'other_guests', 'host_forwarding')), 'HOST_GATE_TYPES')
    require(gate == {'vmnet': 'VMnet2', 'host_only': True, 'dhcp': False, 'nat': False,
                     'bridge': False, 'other_guests': False, 'host_forwarding': False,
                     'host': '192.168.253.1', 'guest': '192.168.253.2',
                     'mac': plan['mac'], 'interface': plan['interface'],
                     'checked_epoch': gate.get('checked_epoch')}, 'HOST_GATE_FIELDS')
    require(type(gate['checked_epoch']) in (int, float) and
            0 <= now - gate['checked_epoch'] <= 600, 'HOST_GATE_STALE')


def session():
    host_guard()
    state = load_state()
    require(state['status'] == 'INSTALLED_LINK_DISABLED', 'NOT_INSTALLED')
    verify_files(state)
    verify_account(state)
    plan = state['plan']
    require(time.time() < plan['expires_epoch'], 'EXPIRED')
    gate_valid(json.loads(read_safe(ROOT / 'host-gate.json')), plan, time.time())
    network_guard(state)
    require(run(['/usr/bin/systemctl', 'is-active', 'hbr-ssh-expire.timer'])[1] == 'active', 'EXPIRY_TIMER')
    require(current_nft() == state['nft_shape'], 'NFT_CHANGED')
    require(run(['/usr/bin/firewall-cmd', '--get-zone-of-interface=' + plan['interface']])[1] == 'hbr-mgmt',
            'FIREWALL_ZONE')
    ssh_guard()
    with (ROOT / 'session.claim').open('x') as stream:
        stream.write(str(time.time()))
    iface = plan['interface']
    def stop(*_args):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        run(['/usr/sbin/sysctl', '-w', f'net.ipv6.conf.{iface}.disable_ipv6=1'], state)
        run(['/usr/sbin/ip', 'address', 'add', '192.168.253.2/24', 'dev', iface], state)
        run(['/usr/sbin/ip', 'link', 'set', 'dev', iface, 'up'], state)
        state['status'] = 'SESSION_ACTIVE_NOT_ACCEPTED'
        save(state)
        while time.time() < plan['expires_epoch']:
            host_guard()
            network_guard(state, active=True)
            require(current_nft() == state['nft_shape'], 'NFT_CHANGED')
            time.sleep(1)
        state['end_reason'] = 'EXPIRED'
    except BaseException as error:
        state['end_reason'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        state['ended_epoch'] = time.time()
        try:
            save(state)
        finally:
            disconnect(state)


def disconnect(state=None):
    # Security drift/HGFS must never prevent teardown on the identified clone.
    identity_guard()
    state = load_state() if state is None else state
    iface = state['plan']['interface']
    results = []
    if iface in physical():
        require(Path('/sys/class/net', iface, 'address').read_text().strip() == state['plan']['mac'], 'NIC_MAC')
        results.append(run(['/usr/sbin/ip', 'link', 'set', 'dev', iface, 'down'], state, check=False)[0])
        run(['/usr/sbin/ip', 'address', 'del', '192.168.253.2/24', 'dev', iface], state, check=False)
    # Terminate only this created account's processes, never sshd globally.
    if 'uid' in state:
        require(pwd.getpwnam('hbrctl').pw_uid == state['uid'], 'ACCOUNT_DRIFT')
        run(['/usr/bin/pkill', '-KILL', '-u', str(state['uid'])], state, check=False)
    state['status'] = 'SESSION_STOPPED' if not any(results) else 'DISCONNECT_FAILED'
    save(state)
    require(not any(results), 'DISCONNECT_FAILED')


def rollback():
    # Physical removal is required before reverting any firewall/SSH or old autoconnect.
    host_guard(disconnected=True)
    state = load_state()
    require(state['status'] != 'ROLLED_BACK', 'ALREADY_ROLLED_BACK')
    for path, digest in state['files'].items():
        if Path(path).exists():
            require(sha(read_safe(Path(path))) == digest, 'ROLLBACK_FILE_DRIFT: ' + path)
    run(['/usr/bin/systemctl', 'stop', 'hbr-ssh-session.service'], state, check=False)
    run(['/usr/bin/systemctl', 'stop', 'hbr-ssh-expire.timer', 'hbr-ssh-expire.service'], state, check=False)
    if state['account_attempted']:
        try:
            account = pwd.getpwnam('hbrctl')
        except KeyError:
            account = None
        if account:
            require('uid' in state and account.pw_uid == state['uid'], 'ACCOUNT_NEEDS_MANUAL_REVIEW')
            run(['/usr/bin/pkill', '-KILL', '-u', str(account.pw_uid)], state, check=False)
            run(['/usr/sbin/userdel', 'hbrctl'], state)
        try:
            group = grp.getgrnam('hbrctl')
        except KeyError:
            group = None
        if group:
            require('gid' in state and group.gr_gid == state['gid'] and not group.gr_mem,
                    'GROUP_NEEDS_MANUAL_REVIEW')
            run(['/usr/sbin/groupdel', 'hbrctl'], state)
    # Keep private state, command receipts and claim. Delete only files this install created.
    for path in state['files']:
        Path(path).unlink(missing_ok=True)
    run(['/usr/sbin/sshd', '-t'], state)
    run(['/usr/bin/systemctl', 'reload', 'sshd.service'], state)
    run(['/usr/bin/firewall-cmd', '--reload'], state)
    tables = run(['/usr/sbin/nft', 'list', 'tables'], state)[1]
    if 'table inet hbr_ssh_guard' in tables:
        run(['/usr/sbin/nft', 'delete', 'table', 'inet', 'hbr_ssh_guard'], state)
    for uuid in state['old_attempted']:
        require(uuid in OLD, 'UNKNOWN_PROFILE')
        run(['/usr/bin/nmcli', 'connection', 'modify', uuid, 'connection.autoconnect', 'yes'], state)
    run(['/usr/bin/nmcli', 'general', 'reload', 'conf'], state)
    run(['/usr/bin/systemctl', 'daemon-reload'], state)
    state['status'] = 'ROLLED_BACK'
    save(state)
    print('ROLLED_BACK; private receipts and one-use claim preserved')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'session', 'disconnect', 'rollback'])
    parser.add_argument('--bundle', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == 'install':
        require(args.bundle is not None, 'BUNDLE_REQUIRED')
        install(args.bundle.resolve(), Path(__file__).resolve().parent)
    elif args.action == 'session':
        session()
    elif args.action == 'disconnect':
        disconnect()
    else:
        rollback()


if __name__ == '__main__':
    main()
