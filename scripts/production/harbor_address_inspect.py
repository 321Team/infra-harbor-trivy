"""Complete Config/HostConfig preservation with narrow reviewed metadata deltas.

Private inspect objects never leave this module. Expected label and inherited
HostConfig.Mounts values are explicit review inputs, not learned from post-state.
MountPreservation and current image/network/volume/host guards remain mandatory.
"""
from copy import deepcopy
import hashlib
import ipaddress
import re

from harbor_address_sequence import ORDER, SERVICES, fingerprint, logging_candidate, row_schema

LABEL_PREFIX = 'com.docker.compose.'
GENERATED_LABELS = {LABEL_PREFIX + suffix for suffix in
                    ('config-hash', 'version', 'project.config_files', 'project.working_dir',
                     'project.environment_file', 'depends_on', 'replace')}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def equal(a, b):
    return fingerprint(a) == fingerprint(b)


def environment(value):
    require(type(value) is list and all(type(v) is str and '=' in v for v in value), 'INSPECT_ENV')
    require(len({v.split('=', 1)[0] for v in value}) == len(value), 'INSPECT_ENV_DUPLICATE')
    return sorted(value)


def labels(value):
    require(type(value) is dict and all(type(k) is str and type(v) is str for k, v in value.items()), 'INSPECT_LABELS')
    result = deepcopy(value)
    key = LABEL_PREFIX + 'depends_on'
    if key in result:
        entries = result[key].split(',') if result[key] else []
        require(len(entries) == len(set(entries)), 'INSPECT_DEPENDENCIES')
        result[key] = ','.join(sorted(entries))
    return result


def config(value):
    require(type(value) is dict and {'Env', 'Labels', 'Hostname', 'Image', 'Cmd', 'Entrypoint',
                                    'User', 'Healthcheck'} <= set(value), 'INSPECT_CONFIG')
    result = deepcopy(value)
    result['Env'] = environment(result['Env'])
    result['Labels'] = labels(result['Labels'])
    return result


def ordered_mounts(mounts):
    require(type(mounts) is list and all(type(m) is dict and type(m.get('Destination')) is str for m in mounts), 'INSPECT_MOUNTS')
    require(len({m['Destination'] for m in mounts}) == len(mounts), 'INSPECT_MOUNT_DUPLICATE')
    return sorted(deepcopy(mounts), key=lambda m: m['Destination'])


def validate_inherited(before, after, mounts):
    """Only add exact existing anonymous volumes to HostConfig.Mounts.

    The concrete JSON shape is an explicit input; unknown options or changed
    preexisting mount definitions are never normalized away.
    """
    require((before is None or type(before) is list) and type(after) is list, 'INSPECT_HOST_MOUNTS')
    old = deepcopy(before or [])
    for values in (old, after):
        require(all(type(v) is dict and type(v.get('Target')) is str for v in values) and
                len({v['Target'] for v in values}) == len(values), 'INSPECT_HOST_MOUNTS_CHANGED')
    previous = {v['Target']: v for v in old}
    current = {v['Target']: v for v in after}
    require(all(current.get(k) == v for k,v in previous.items()), 'INSPECT_HOST_MOUNTS_CHANGED')
    additions = [v for k,v in current.items() if k not in previous]
    actual = [m for m in mounts if m.get('Type') == 'volume' and
              m.get('Destination') not in {v.get('Target') for v in old}]
    require(len(actual) == len(additions), 'INSPECT_INHERITED_SET')
    seen = set()
    for added in additions:
        require(type(added) is dict and set(added) <= {'Type', 'Source', 'Target', 'ReadOnly', 'VolumeOptions'} and
                {'Type', 'Source', 'Target'} <= set(added) and
                added['Type'] == 'volume' and type(added.get('ReadOnly', False)) is bool and
                type(added.get('VolumeOptions', {})) is dict and
                set(added.get('VolumeOptions', {})) <= {'NoCopy'} and
                added.get('VolumeOptions', {}).get('NoCopy', False) is False, 'INSPECT_INHERITED_OPTIONS')
        matches = [m for m in actual if m['Destination'] == added['Target']]
        require(len(matches) == 1 and added['Target'] not in seen, 'INSPECT_INHERITED_TARGET')
        m = matches[0]
        require(added['Source'] == m['Name'] and added.get('ReadOnly', False) is (not m['RW']), 'INSPECT_INHERITED_IDENTITY')
        seen.add(added['Target'])


def host_config(value):
    """Sort only unique-target mount arrays; keep every option/value exact.

    Compose emits these arrays from a Go map. Omitting false is only accepted
    in a separately supplied target, never learned or normalized from live data.
    """
    result=deepcopy(value)
    if result.get('Binds') is not None:
        binds=result['Binds']
        require(type(binds) is list and all(type(v) is str and len(v.split(':')) == 3 for v in binds) and
                len({v.split(':')[1] for v in binds}) == len(binds), 'INSPECT_BIND_TARGETS')
        result['Binds']=sorted(binds)
    if result.get('Mounts') is not None:
        mounts=result['Mounts']
        require(type(mounts) is list and all(type(v) is dict and type(v.get('Target')) is str for v in mounts) and
                len({v['Target'] for v in mounts}) == len(mounts), 'INSPECT_HOST_MOUNT_TARGETS')
        result['Mounts']=sorted(mounts,key=lambda m:m['Target'])
    targets=[v.split(':')[1] for v in result.get('Binds') or []]+[v['Target'] for v in result.get('Mounts') or []]
    require(len(set(targets)) == len(targets),'INSPECT_HOST_MOUNT_TARGETS')
    return result


def networks(row, *, auto_address):
    values = row.get('NetworkSettings', {}).get('Networks')
    require(type(values) is dict and values, 'INSPECT_NETWORKS')
    result = deepcopy(values)
    for key, value in result.items():
        require(type(value) is dict and type(value.get('NetworkID')) is str and
                re.fullmatch('[0-9a-f]{64}', value['NetworkID']), 'INSPECT_NETWORK_ID')
        # Allocation identity is ephemeral. Declarative IPAM/links/options,
        # gateways/prefix sizes and every unknown field stay exact.
        endpoint = value.get('EndpointID')
        require(type(endpoint) is str and re.fullmatch('[0-9a-f]{64}', endpoint), 'INSPECT_ENDPOINT')
        value['EndpointID'] = '<allocated-endpoint>'
        if auto_address:
            require(value.get('IPAMConfig') in (None, {}), 'INSPECT_STATIC_IPAM')
            for name in ('IPAddress', 'GlobalIPv6Address', 'MacAddress'):
                raw = value.get(name)
                require(type(raw) is str, 'INSPECT_NETWORK_ADDRESS')
                if raw:
                    if name == 'MacAddress':
                        require(re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', raw), 'INSPECT_MAC')
                    else:
                        try:
                            parsed = ipaddress.ip_address(raw)
                            require(parsed.version == (4 if name == 'IPAddress' else 6), 'INSPECT_IP_VERSION')
                        except ValueError:
                            raise ValueError('INSPECT_IP_ADDRESS') from None
                    value[name] = '<allocated-address>'
        for name in ('Aliases', 'DNSNames'):
            if name in value and value[name] is not None:
                require(type(value[name]) is list and all(type(v) is str for v in value[name]), 'INSPECT_NETWORK_NAMES')
                value[name] = sorted('<container-id>' if v == row['Id'][:12] else v for v in value[name])
    return result


class FullPreservation:
    def __init__(self, before, *, after_labels, after_host_mounts, auto_hostnames, auto_addresses):
        require(type(before) is dict and set(before) == set(SERVICES) and
                type(after_labels) is dict and set(after_labels) == set(ORDER) and
                type(after_host_mounts) is dict and set(after_host_mounts) <= set(ORDER), 'INSPECT_BASE_SET')
        require(type(auto_hostnames) is list and len(set(auto_hostnames)) == len(auto_hostnames) and
                set(auto_hostnames) <= set(ORDER) and type(auto_addresses) is list and
                len(set(auto_addresses)) == len(auto_addresses) and set(auto_addresses) <= set(ORDER), 'INSPECT_AUTO_FIELDS')
        self.before = deepcopy(before)
        self.target_labels = deepcopy(after_labels)
        self.target_host_mounts = deepcopy(after_host_mounts)
        self.auto_hostnames, self.auto_addresses = set(auto_hostnames), set(auto_addresses)
        self.expected = {}
        for service, row in before.items():
            self._identity(row, service)
            c = config(row['Config'])
            require(type(c.get('StopSignal', 'SIGTERM')) is str and
                    c.get('StopSignal', 'SIGTERM').upper() not in ('SIGKILL', 'KILL', '9'), 'INSPECT_FORCE_SIGNAL')
            h = deepcopy(row['HostConfig'])
            if service != 'log':
                target = labels(after_labels[service])
                require(equal({k: v for k, v in c['Labels'].items() if k not in GENERATED_LABELS},
                              {k: v for k, v in target.items() if k not in GENERATED_LABELS}), 'INSPECT_LABEL_SCOPE')
                require(target.get(LABEL_PREFIX+'version') == '5.6.0' and
                        re.fullmatch('[0-9a-f]{64}', target.get(LABEL_PREFIX+'config-hash', '')) and
                        target.get(LABEL_PREFIX+'project.working_dir') == '/' and
                        target.get(LABEL_PREFIX+'project.config_files') == '-' and
                        target.get(LABEL_PREFIX+'project.environment_file', '/dev/null') == '/dev/null' and
                        target.get(LABEL_PREFIX+'replace') == row['Name'][1:], 'INSPECT_TARGET_LABELS')
                c['Labels'] = target
                h['LogConfig'] = logging_candidate(h['LogConfig'])
            if service in self.auto_hostnames:
                require(c['Hostname'] == row['Id'][:12], 'INSPECT_AUTOMATIC_HOSTNAME')
                c['Hostname'] = '<container-id>'
            if service in after_host_mounts:
                validate_inherited(h.get('Mounts'), after_host_mounts[service], row['Mounts'])
                h['Mounts'] = deepcopy(after_host_mounts[service])
            self.expected[service] = dict(Config=c, HostConfig=host_config(h), Image=row['Image'], Name=row['Name'],
                MountLabel=row['MountLabel'], ProcessLabel=row['ProcessLabel'],
                Networks=networks(row, auto_address=(service in self.auto_addresses)))
        self.binding = fingerprint(dict(baseline=before, after_labels=after_labels, after_host_mounts=after_host_mounts,
                                        auto_hostnames=auto_hostnames, auto_addresses=auto_addresses))

    def _identity(self, row, service):
        require(type(row) is dict and type(row.get('Id')) is str and re.fullmatch('[0-9a-f]{64}', row['Id']) and
                type(row.get('Name')) is str and row['Name'].startswith('/') and
                type(row.get('Image')) is str and re.fullmatch('sha256:[0-9a-f]{64}', row['Image']) and
                type(row.get('Config')) is dict and type(row.get('HostConfig')) is dict and
                row['Config'].get('Labels', {}).get(LABEL_PREFIX+'project') == 'harbor' and
                row['Config']['Labels'].get(LABEL_PREFIX+'service') == service and
                type(row.get('MountLabel')) is str and type(row.get('ProcessLabel')) is str, 'INSPECT_IDENTITY')

    def row(self, service, current, *, recreated, mounts_verified):
        """mounts_verified is the expected full mount array after profile check.

        Caller MUST run MountPreservation.check with fresh volume metadata before
        using this method. It cannot substitute a boolean or learn expected data
        from current inspect; exact expected mount bytes are compared here.
        """
        require(service in SERVICES and type(recreated) is bool, 'INSPECT_SERVICE')
        self._identity(current, service)
        base = self.before[service]
        c, h = config(current['Config']), deepcopy(current['HostConfig'])
        require(equal(ordered_mounts(current['Mounts']), ordered_mounts(mounts_verified)), 'INSPECT_MOUNT_CHANGED')
        if recreated:
            require(service != 'log' and current['Id'] not in {r['Id'] for r in self.before.values()}, 'INSPECT_RECREATION_ID')
            if service in self.auto_hostnames:
                require(c['Hostname'] == current['Id'][:12], 'INSPECT_AUTOMATIC_HOSTNAME')
                c['Hostname'] = '<container-id>'
            actual = dict(Config=c, HostConfig=host_config(h), Image=current['Image'], Name=current['Name'],
                          MountLabel=current['MountLabel'], ProcessLabel=current['ProcessLabel'],
                          Networks=networks(current, auto_address=(service in self.auto_addresses)))
            require(equal(actual, self.expected[service]), 'INSPECT_FULL_PRESERVATION_CHANGED')
        else:
            require(current['Id'] == base['Id'] and equal(c, config(base['Config'])) and
                    equal(h, base['HostConfig']) and current['Image'] == base['Image'] and current['Name'] == base['Name'] and
                    current['MountLabel'] == base['MountLabel'] and current['ProcessLabel'] == base['ProcessLabel'] and
                    equal(current['NetworkSettings'], base['NetworkSettings']), 'INSPECT_UNTOUCHED_CHANGED')
        state = current.get('State')
        require(type(state) is dict and all(type(state.get(k)) is bool for k in
                ('Running', 'Paused', 'Restarting', 'Dead')) and
                state['Running'] == (state.get('Status') == 'running') and
                not any(state[k] for k in ('Paused', 'Restarting', 'Dead')) and
                type(state.get('Error')) is str, 'INSPECT_STATE_CONFLICT')
        result = dict(id=current['Id'], image=current['Image'],
                      preservation_sha256=fingerprint(self.expected[service]),
                      logging=deepcopy(h['LogConfig']), restart=deepcopy(h['RestartPolicy']),
                      status=state['Status'], health=state.get('Health', {}).get('Status'),
                      exit_code=state.get('ExitCode'), error_sha256=hashlib.sha256(state['Error'].encode()).hexdigest())
        row_schema(result)
        return result
