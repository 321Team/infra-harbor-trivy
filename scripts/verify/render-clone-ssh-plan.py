#!/usr/bin/env python3
"""Render review candidates only. Never install, connect, reload or apply them."""
import argparse
import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import time

HOST = '192.168.253.1'
GUEST = '192.168.253.2'
OLD_PROFILES = ('6b9f0643-4a4e-324d-a969-9e5393d7e0bf',
                '3094c330-0b11-4463-9409-29c11bca6fcb')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def public_key(text):
    # Accept one bare Ed25519 public key, never private material or caller options.
    parts = text.strip().split()
    require(len(parts) in (2, 3) and parts[0] == 'ssh-ed25519', 'PUBLIC_KEY_FORMAT')
    if len(parts) == 3:
        require(bool(re.fullmatch(r'[A-Za-z0-9_.@-]{1,80}', parts[2])), 'KEY_COMMENT')
    raw = base64.b64decode(parts[1], validate=True)
    expected = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32)
    require(len(raw) == 51 and raw.startswith(expected), 'PUBLIC_KEY_WIRE_FORMAT')
    return 'ssh-ed25519 ' + parts[1]


def render(interface, mac, key, expires, now=None):
    now = time.time() if now is None else now
    require(isinstance(interface, str) and
            re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,14}', interface) is not None,
            'INTERFACE_INVALID')
    require(interface not in ('lo', 'docker0') and not interface.startswith(('br', 'veth')),
            'INTERFACE_NOT_MANAGEMENT')
    require(isinstance(mac, str) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac),
            'MAC_INVALID')
    # VMware manually assigned unicast MAC range; candidate, not an allocation.
    octets = bytes.fromhex(mac.replace(':', ''))
    require(octets[:3] == b'\x00\x50\x56' and octets[3] <= 0x3f, 'MAC_NOT_VMWARE_MANUAL')
    require(type(expires) is int and now < expires <= now + 4 * 3600, 'EXPIRY_MAX_FOUR_HOURS')
    key = public_key(key)
    for value in (HOST, GUEST):
        ipaddress.IPv4Address(value)
    policy = {'schema': 1, 'host': HOST, 'guest': GUEST, 'port': 22,
              'user': 'hbrctl', 'expires_epoch': expires,
              'allowed': ['identity', 'network', 'services']}
    files = {
        'hbr-mgmt.nft.candidate': f'''# Review candidate. No flush ruleset; touches only this new table.
table inet hbr_ssh_guard {{
  chain input {{
    type filter hook input priority -20; policy accept;
    iifname "{interface}" ip saddr {HOST} ip daddr {GUEST} tcp dport 22 ct state {{ new, established }} accept
    iifname "{interface}" counter drop
  }}
  chain output {{
    type filter hook output priority -20; policy accept;
    oifname "{interface}" ip saddr {GUEST} ip daddr {HOST} tcp sport 22 ct state established accept
    oifname "{interface}" counter drop
  }}
  chain forward {{
    type filter hook forward priority -20; policy accept;
    iifname "{interface}" counter drop
    oifname "{interface}" counter drop
  }}
}}
''',
        'hbr-mgmt.xml.candidate': f'''<?xml version="1.0" encoding="utf-8"?>
<zone target="DROP">
  <short>Harbor clone management</short>
  <interface name="{interface}"/>
  <rule family="ipv4">
    <source address="{HOST}/32"/>
    <destination address="{GUEST}/32"/>
    <port protocol="tcp" port="22"/>
    <accept/>
  </rule>
</zone>
''',
        'hbr-mgmt.nmconnection.candidate': f'''[connection]
id=hbr-mgmt
type=ethernet
interface-name={interface}
autoconnect=false
zone=hbr-mgmt

[ethernet]
mac-address={mac}

[ipv4]
method=manual
address1={GUEST}/24
never-default=true
ignore-auto-dns=true
ignore-auto-routes=true

[ipv6]
method=disabled
''',
        '90-hbr-no-auto-default.conf.candidate': f'''[main]
no-auto-default=*

[device-hbr-mgmt]
match-device=type:ethernet
managed=0
''',
        '00-hbr-mgmt-sshd.conf.candidate': f'''# Must precede other matching blocks; validate effective settings for ALL users.
Match LocalAddress {GUEST}
    AllowUsers hbrctl@{HOST}
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitRootLogin no
    AuthorizedKeysFile /etc/ssh/hbr-mgmt-authorized_keys
    AuthorizedKeysCommand none
    TrustedUserCAKeys none
    DisableForwarding yes
    PermitTunnel no
    PermitTTY no
    PermitUserRC no
    MaxSessions 1
    ForceCommand /usr/bin/python3 -I /usr/local/libexec/hbr-ssh-readonly.py
Match all
''',
        'authorized_keys.candidate': f'from="{HOST}",restrict {key}\n',
        'hbr-ssh-policy.json.candidate': json.dumps(policy, indent=2) + '\n',
        'plan.json': json.dumps({
            'status': 'REVIEW_CANDIDATE_NOT_DEPLOYABLE', 'runtime': 'NOT_RUN',
            'interface': interface, 'mac': mac, 'host': HOST, 'guest': GUEST,
            'vmnet_candidate': 'VMnet2', 'expires_epoch': expires,
            'old_profiles_disable_autoconnect': list(OLD_PROFILES),
            'unresolved': ['live VMnet and other participants', 'MAC allocation and guest interface',
                           'exact-source independent review',
                           'installer/session/rollback target validation',
                           'sshd/firewalld/nft/NM syntax and effective checks on CentOS',
                           'runtime allow/deny tests', 'expiry teardown target validation'],
        }, indent=2) + '\n',
    }
    return files


def write_candidates(output, files):
    # Refuse overwrite, including an existing symlink. Keep any partial output for diagnosis.
    output = Path(output)
    output.mkdir(parents=False, exist_ok=False)
    hashes = []
    for name, text in files.items():
        raw = text.encode('utf-8')
        with (output / name).open('xb') as stream:
            stream.write(raw)
        hashes.append(hashlib.sha256(raw).hexdigest() + '  ' + name)
    (output / 'SHA256SUMS').write_text('\n'.join(hashes) + '\n', encoding='ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--mac', required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--expires-epoch', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    files = render(args.interface, args.mac, args.public_key.read_text(encoding='ascii'),
                   args.expires_epoch)
    write_candidates(args.output, files)
    print('REVIEW_CANDIDATE_ONLY; no system commands or configuration changes performed')


if __name__ == '__main__':
    main()
