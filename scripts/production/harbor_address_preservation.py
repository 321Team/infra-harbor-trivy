"""Pure comparison for an explicitly reviewed production volume-mode profile.

Not a host collector, implicit approval, relabel command or recreation adapter.
All runtime metadata must come from fresh trusted observations. No clone profile
or observed drift is automatically accepted. Context/data are not inferred from
Mode strings. Full Config/HostConfig preservation remains the caller's duty.
"""
from copy import deepcopy
import hashlib
import json
import re

TARGETS = {
    'registryctl': {'/var/lib/registry'},
    'portal': {'/run', '/var/cache/nginx', '/var/log/nginx'},
    'proxy': {'/run', '/var/cache/nginx', '/var/log/nginx'},
}
FIELDS = {'schema', 'host_binding_sha256', 'authorization_sha256', 'engine', 'compose_version',
          'security_options', 'baseline_mounts', 'source_metadata', 'volume_inventory'}
ENGINE = {'Version': '29.8.2', 'GitCommit': '8af9fe3', 'ApiVersion': '1.56'}
SECURITY = ['name=seccomp,profile=builtin', 'name=cgroupns']
CONTEXT = 'system_u:object_r:container_file_t:s0'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False).encode()).hexdigest()


def validate_profile(profile):
    require(type(profile) is dict and set(profile) == FIELDS and
            profile['schema'] == 'fds.harbor.production-volume-mode.v1', 'PROFILE_SCHEMA')
    require(digest(profile['host_binding_sha256']) and digest(profile['authorization_sha256']), 'PROFILE_BINDING')
    require(profile['engine'] == ENGINE and profile['compose_version'] == '5.6.0' and
            profile['security_options'] == SECURITY, 'PROFILE_ENGINE_SECURITY')
    rows = profile['baseline_mounts']
    require(type(rows) is dict and set(rows) == set(TARGETS), 'PROFILE_TARGETS')
    names, paths = set(), set()
    for service, mounts in rows.items():
        require(type(mounts) is list and len(mounts) == len(TARGETS[service]) and
                {m['Destination'] for m in mounts} == TARGETS[service], 'PROFILE_TARGETS')
        for m in mounts:
            require(type(m) is dict and set(m) == {'Type','Name','Source','Destination','Driver','Mode','RW','Propagation'}, 'PROFILE_MOUNT_SCHEMA')
            require(m['Type'] == 'volume' and digest(m['Name']) and m['Name'] not in names and
                    m['Source'] == '/var/lib/docker/volumes/'+m['Name']+'/_data' and m['Driver'] == 'local' and
                    m['Mode'] == '' and m['RW'] is True and m['Propagation'] == '', 'PROFILE_MOUNT')
            names.add(m['Name']); paths.add(m['Source'])
    metadata = profile['source_metadata']
    require(type(metadata) is dict and set(metadata) == paths, 'PROFILE_METADATA_SET')
    for row in metadata.values():
        require(type(row) is dict and set(row) == {'uid','gid','mode','directory','symlink','xattrs','selinux'} and
                type(row['uid']) is int and row['uid'] >= 0 and type(row['gid']) is int and row['gid'] >= 0 and
                type(row['mode']) is int and 0 <= row['mode'] <= 0o777 and row['directory'] is True and
                row['symlink'] is False and row['xattrs'] == ['security.selinux'] and row['selinux'] == CONTEXT,
                'PROFILE_METADATA')
    inventory=profile['volume_inventory']
    require(type(inventory) is dict and set(inventory) == names, 'PROFILE_VOLUME_INVENTORY')
    for name,row in inventory.items():
        require(row == {'name':name,'driver':'local','mountpoint':'/var/lib/docker/volumes/'+name+'/_data',
                        'scope':'local','has_options':False}, 'PROFILE_VOLUME_INVENTORY')
    fingerprint(profile)
    return deepcopy(profile)


class MountPreservation:
    def __init__(self, profile):
        self.profile = validate_profile(profile)

    def check(self, *, before, after, completed_services, current_metadata, host_binding_sha256,
              authorization_sha256, engine, compose_version, security_options, enforcing, labels, current_inventory):
        """Compare complete 10-service mount sets; only completed apps may get z.

        authorization_sha256 is a binding to an externally confirmed, reviewed
        permission artifact, NOT a permission verifier. Never manufacture it from
        this schema or infer approval from a successful comparison.
        labels: fresh exact10 rows {'MountLabel':'','ProcessLabel':''}.
        No file/content writes occur; successful comparison is metadata only.
        """
        p=self.profile
        require(host_binding_sha256 == p['host_binding_sha256'] and
                authorization_sha256 == p['authorization_sha256'], 'PROFILE_BINDING_CHANGED')
        require(engine == p['engine'] and compose_version == p['compose_version'] and
                security_options == p['security_options'] and enforcing == 'Enforcing',
                'PROFILE_ENGINE_SECURITY_CHANGED')
        require(current_metadata == p['source_metadata'], 'VOLUME_SOURCE_METADATA_CHANGED')
        require(current_inventory == p['volume_inventory'], 'VOLUME_INVENTORY_CHANGED')
        services={'postgresql','redis','registry','registryctl','core','portal','jobservice','trivy-adapter','proxy','log'}
        require(type(before) is dict and type(after) is dict and set(before) == set(after) == services, 'MOUNT_SERVICE_SET')
        require(type(completed_services) is list and len(set(completed_services)) == len(completed_services) and
                set(completed_services) <= services-{'log'}, 'MOUNT_RECREATED_SCOPE')
        require(type(labels) is dict and set(labels) == services and
                all(v == {'MountLabel':'','ProcessLabel':''} for v in labels.values()), 'CONTAINER_LABEL_CHANGED')
        for service in services:
            require(type(before[service]) is list and type(after[service]) is list, 'MOUNT_SET_SCHEMA')
            for mounts in (before[service],after[service]):
                require(all(type(m) is dict and type(m.get('Destination')) is str for m in mounts) and
                        len({m['Destination'] for m in mounts}) == len(mounts), 'MOUNT_DESTINATION_DUPLICATE')
            expected=deepcopy(before[service])
            if service in TARGETS:
                baseline=[m for m in expected if m.get('Type')=='volume']
                sort=lambda a:sorted(a,key=lambda m:m['Destination'])
                require(sort(baseline) == sort(p['baseline_mounts'][service]), 'PROFILE_BASELINE_CHANGED')
                if service in completed_services:
                    for m in expected:
                        if m.get('Type') == 'volume': m['Mode']='z'
            require(sorted(expected,key=lambda m:m['Destination']) == sorted(after[service],key=lambda m:m['Destination']),
                    'MOUNTS_CHANGED_OUTSIDE_PROFILE')
        return {'mount_metadata':'MATCHED_EXPLICIT_PROFILE','content_integrity':'NOT_TESTED',
                'runtime_acceptance':False,'profile_sha256':fingerprint(p)}
