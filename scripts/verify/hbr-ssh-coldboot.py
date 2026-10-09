#!/usr/bin/env python3
"""One reviewed cold-boot transition for the sealed 2026-10-09 SSH installation.

Never powers off, boots, restarts Docker, raises a link, extends expiry or removes
claims. Capture first; apply only after review of that exact post-boot report.
"""
import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

SOURCE = Path('/usr/local/libexec/hbr-ssh-lifecycle.py')
SOURCE_SHA = 'bd7ad99cfa09983830bf7bdfdf66bb9486e70fde51a3b35dcd575875d8fdfb2d'
STATE_SHA = '5c8666145f48ac68641a5ddfd19e0d0de48362dc85cc0628b3d3260e7ac50400'
PREVIOUS_BOOT = 'ec7a9c3c-3a91-4d4a-8d42-f68ce23ce92b'
A3_FILES = {
    '/root/hbr-a3-joz3x6ya/result.json': '5df896fd9f501cbac82e1091c6368160d79dbca34baf651681f766f331102fa7',
    '/root/hbr-a3-docker-restart.claim': 'fc00ce44c9aaa35b3cb15d150db208a560f0873532736fb4daafe870c3afa175',
}
BOOT_FILE = Path('/proc/sys/kernel/random/boot_id')
NET = Path('/sys/class/net')
sys.dont_write_bytecode = True


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def load_lifecycle():
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    for path in [SOURCE, *SOURCE.parents]:
        info = path.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022 and
                (stat.S_ISREG(info.st_mode) if path == SOURCE else stat.S_ISDIR(info.st_mode)),
                'UNTRUSTED_SOURCE')
    require(digest(SOURCE.read_bytes()) == SOURCE_SHA, 'SOURCE_SHA')
    spec = importlib.util.spec_from_file_location('sealed_lifecycle', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def guard(life):
    life.host_guard()  # UUID/root/hostname/Enforcing/HGFS absent.
    raw = life.read_safe(life.STATE)
    require(digest(raw) == STATE_SHA, 'SEALED_STATE_CHANGED')
    state = json.loads(raw)
    require(state['status'] == 'INSTALLED_LINK_DISABLED', 'INSTALL_STATUS')
    require(time.time() < state['plan']['expires_epoch'], 'EXPIRED')
    require(not (life.ROOT / 'session.claim').exists(), 'SESSION_ALREADY_ATTEMPTED')
    require(not (life.ROOT / 'coldboot.claim').exists(), 'COLDBOOT_ALREADY_ATTEMPTED')
    life.verify_files(state)
    for name, expected in A3_FILES.items():
        require(digest(life.read_safe(Path(name))) == expected, 'A3_PRESERVATION_DRIFT')
    life.verify_account(state)
    life.old_profiles_off()
    life.ssh_guard()
    boot = BOOT_FILE.read_text().strip()
    require(re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot)
            and boot != PREVIOUS_BOOT, 'NEW_BOOT_REQUIRED')
    iface = state['plan']['interface']
    require(life.physical() == [iface], 'NIC_SET')
    require((NET / iface / 'address').read_text().strip() == state['plan']['mac'], 'NIC_MAC')
    require(life.run(['/usr/bin/nmcli', '-g', 'GENERAL.STATE', 'device', 'show', iface])[1]
            .startswith('10 '), 'NIC_MUST_BE_UNMANAGED')
    return raw, state, boot


def check_network(life, state, rows, routes):
    """Keep old interface identities/global addresses; allow bounded veth churn.

    Docker may replace its veths and IPv6 link-local addresses on a new boot.
    Such differences still appear in the operator-reviewed capture; they never
    permit new bridges, arbitrary addresses, default routes or management IPs.
    """
    iface = state['plan']['interface']
    life.validate_addresses(rows, iface, False)
    old = state['baseline_addresses']
    fixed = {name for name in old if not re.fullmatch(r'veth[0-9a-f]+', name)}
    require(all(name == 'lo' or name == 'docker0' or re.fullmatch(r'br-[0-9a-f]{12}', name)
                for name in fixed), 'UNSUPPORTED_OLD_INTERFACE')
    shape = life.address_shape(rows, exclude=iface)
    require({n for n in shape if not re.fullmatch(r'veth[0-9a-f]+', n)} == fixed,
            'FIXED_INTERFACE_DRIFT')

    def stable(addresses):
        return sorted(tuple(a) for a in addresses if not
            (a[0] == 'inet6' and ipaddress.ip_address(a[1]).is_link_local))

    by_index = {r['ifindex']: r['ifname'] for r in rows}
    for row in rows:
        name = row['ifname']
        if name == iface:
            require('LOWER_UP' not in row.get('flags', []), 'CABLE_CONNECTED')
            continue
        addresses = shape[name]
        require(all(a[2] == 64 for a in addresses if a[0] == 'inet6'
                    and ipaddress.ip_address(a[1]).is_link_local), 'LINK_LOCAL_PREFIX')
        if name in fixed:
            require(stable(addresses) == stable(old[name]), 'FIXED_ADDRESS_DRIFT')
        else:
            require(re.fullmatch(r'veth[0-9a-f]+', name), 'UNEXPECTED_INTERFACE')
            master = row.get('master')
            master = by_index.get(master) if isinstance(master, int) else master
            require(master in fixed - {'lo'}, 'VETH_MASTER')
            require(all(a[0] == 'inet6' and ipaddress.ip_address(a[1]).is_link_local
                        and a[2] == 64 for a in addresses), 'VETH_ADDRESS')
    for family, items in routes.items():
        if family == '-4':
            require(sorted(map(encoded, items)) == sorted(map(encoded, state['baseline_routes'][family])),
                    'IPV4_ROUTE_DRIFT')
        for route in items:
            require(route.get('dst') != 'default' and 'gateway' not in route, 'DEFAULT_OR_GATEWAY')
            dev = route.get('dev')
            require(dev in shape, 'ROUTE_INTERFACE')  # No management route, even link-local.
            if family == '-4':
                require(route in state['baseline_routes'][family], 'IPV4_ROUTE_DRIFT')
            elif route not in state['baseline_routes'][family]:
                dst = route.get('dst', '')
                network = ipaddress.ip_network(dst, strict=False)
                local_addresses = {a[1] for a in shape[dev] if a[0] == 'inet6'}
                require(dev != 'lo' and (dst in ('fe80::/64', 'ff00::/8') or
                    (network.prefixlen == 128 and str(network.network_address) in local_addresses
                     and network.network_address.is_link_local)), 'IPV6_ROUTE_DRIFT')


def snapshot(life):
    raw, state, boot = guard(life)
    rows = json.loads(life.run(['/usr/sbin/ip', '-j', 'address', 'show'])[1])
    routes = {f: json.loads(life.run(['/usr/sbin/ip', '-j', f, 'route', 'show', 'table', 'all'])[1])
              for f in ('-4', '-6')}
    check_network(life, state, rows, routes)
    tables = life.run(['/usr/sbin/nft', 'list', 'tables'])[1].splitlines()
    require('table inet hbr_ssh_guard' not in tables, 'NFT_TABLE_ALREADY_EXISTS')
    iface = state['plan']['interface']
    require(life.run(['/usr/bin/firewall-cmd', '--get-zone-of-interface=' + iface])[1]
            == 'hbr-mgmt', 'FIREWALL_ZONE')
    units = {}
    for name in ('docker.service', 'docker.socket', 'containerd.service',
                 'fds-harbor-ac04-guard.service', 'hbr-ssh-session.service', 'hbr-ssh-expire.timer'):
        output = life.run(['/usr/bin/systemctl', 'show', name,
                           '--property=LoadState,ActiveState,SubState,UnitFileState,InvocationID'])[1]
        values = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
        require(values.get('LoadState') == 'loaded' and
                values.get('ActiveState') in ('active', 'inactive', 'failed'), 'UNIT_NOT_SETTLED')
        units[name] = values
    require(units['hbr-ssh-session.service']['ActiveState'] == 'inactive', 'SESSION_ACTIVE')
    require(units['hbr-ssh-expire.timer']['ActiveState'] == 'inactive', 'TIMER_ALREADY_ACTIVE')
    require(BOOT_FILE.read_text().strip() == boot, 'BOOT_CHANGED')
    return {'schema': 1, 'previous_boot': PREVIOUS_BOOT, 'boot': boot,
            'sealed_state_sha256': digest(raw), 'source_sha256': SOURCE_SHA,
            'helper_sha256': digest(Path(__file__).read_bytes()), 'plan': state['plan'],
            'baseline_addresses': life.address_shape(rows, exclude=iface),
            'baseline_routes': routes, 'units': units}, state


def capture(life):
    report, _ = snapshot(life)
    raw = encoded(report)
    path = life.ROOT / ('coldboot-review-' + digest(raw) + '.json')
    # Existing capture is immutable; a repeated identical query returns its path.
    if path.exists():
        require(life.read_safe(path) == raw, 'CAPTURE_CHANGED')
    else:
        with path.open('xb') as stream:
            stream.write(raw)
    print('COLDBOOT_CAPTURE_REVIEW_REQUIRED SHA256=' + digest(raw) + ' PATH=' + str(path))


def apply(life, review_sha):
    require(re.fullmatch('[a-f0-9]{64}', review_sha or ''), 'REVIEW_SHA_REQUIRED')
    captured = life.read_safe(life.ROOT / ('coldboot-review-' + review_sha + '.json'))
    require(digest(captured) == review_sha, 'REVIEW_HASH')
    report, state = snapshot(life)
    require(encoded(report) == captured, 'POST_REVIEW_DRIFT')
    gate = json.loads(life.read_safe(life.ROOT / 'coldboot-host-gate.json'))
    expected = dict(vmnet='VMnet2', host_only=True, dhcp=False, nat=False, bridge=False,
        other_guests=False, host_forwarding=False, host='192.168.253.1', guest='192.168.253.2',
        mac=state['plan']['mac'], interface=state['plan']['interface'],
        checked_epoch=gate.get('checked_epoch'))
    life.gate_valid({k: v for k, v in gate.items() if k not in
                     ('cable_disconnected', 'boot', 'review_sha256')}, state['plan'], time.time())
    require(type(gate.get('cable_disconnected')) is bool and gate['cable_disconnected'] is True,
            'HOST_CABLE_ATTESTATION')
    require(gate == dict(expected, cable_disconnected=True, boot=report['boot'],
                         review_sha256=review_sha), 'HOST_GATE_FIELDS')
    require(time.time() + 60 < state['plan']['expires_epoch'], 'EXPIRY_TOO_CLOSE')
    original = life.read_safe(life.STATE)
    require(digest(original) == STATE_SHA, 'STATE_CHANGED_BEFORE_CLAIM')
    with (life.ROOT / 'coldboot.claim').open('x') as stream:
        stream.write(review_sha + '\n')
    with (life.ROOT / 'before-coldboot-state.json').open('xb') as stream:
        stream.write(original)
    state['status'] = 'COLDBOOT_REARMING'
    state['coldboot'] = {'review_sha256': review_sha, 'previous_boot': PREVIOUS_BOOT,
                         'boot': report['boot'], 'started_epoch': time.time()}
    life.save(state)
    try:
        life.run(['/usr/sbin/nft', '-c', '-f', str(life.NFT)], state)
        life.run(['/usr/sbin/nft', '-f', str(life.NFT)], state)
        require(life.current_nft() == state['nft_shape'], 'NFT_SHAPE_MISMATCH')
        life.run(['/usr/bin/systemctl', 'start', 'hbr-ssh-expire.timer'], state)
        require(life.run(['/usr/bin/systemctl', 'is-active', 'hbr-ssh-expire.timer'])[1]
                == 'active', 'EXPIRY_TIMER')
        next_state = copy.deepcopy(state)
        next_state['baseline_addresses'] = report['baseline_addresses']
        next_state['baseline_routes'] = report['baseline_routes']
        life.host_guard()
        life.verify_files(next_state)
        life.verify_account(next_state)
        life.ssh_guard()
        life.network_guard(next_state)
        require(BOOT_FILE.read_text().strip() == report['boot'], 'BOOT_CHANGED')
        require(time.time() < state['plan']['expires_epoch'], 'EXPIRED_DURING_REARM')
        next_state['status'] = 'INSTALLED_LINK_DISABLED'
        next_state['coldboot']['finished_epoch'] = time.time()
        life.save(next_state)
    except BaseException:
        state['status'] = 'COLDBOOT_REARM_FAILED_CONSOLE_REVIEW_REQUIRED'
        life.save(state)
        raise
    print('COLDBOOT_REARMED_LINK_DISABLED; no session started; original expiry and claims preserved')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('capture', 'apply'))
    parser.add_argument('--review-sha')
    args = parser.parse_args()
    os.umask(0o077)
    life = load_lifecycle()
    if args.action == 'capture':
        capture(life)
    else:
        apply(life, args.review_sha)


if __name__ == '__main__':
    main()
