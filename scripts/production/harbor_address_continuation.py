"""Read-only proof for the fixed DB-preserved eight-app contract.

Never repairs or resumes prior evidence. Supplied hashes bind reviewed artifacts;
they do not grant permission. No production paths, identities or budgets default.
"""
from copy import deepcopy
import hashlib
import os
from pathlib import PurePosixPath
import re
import time

from harbor_address_compose import MAX_OUTPUT, _signature, parse, protected_path, remaining, require
from harbor_address_evidence import context_check, inspect_evidence
from harbor_address_inspect import FullPreservation
from harbor_address_host import unit_projection
from harbor_address_package import _file, load_package
from harbor_address_sequence import (DB_PRESERVED_SCHEMA, TRANSITION_SCHEMA, ORDER, SERVICES,
                                     fingerprint, digest, validate_plan)


def validate_reference(ref):
    require(type(ref) is dict and set(ref) == {
        'package', 'launch', 'dispatch', 'evidence', 'plan_sha256', 'source_revision',
        'sequence_record', 'database_record'}, 'CONTINUATION_REFERENCE')
    for key in ('package', 'launch', 'dispatch', 'evidence'):
        row = ref[key]
        require(type(row) is dict and set(row) == {'path', 'sha256', 'context'} and
                type(row['path']) is str and row['path'].startswith('/') and
                str(PurePosixPath(row['path'])) == row['path'] and
                '..' not in PurePosixPath(row['path']).parts and len(PurePosixPath(row['path']).parts) > 2 and
                digest(row['sha256']) and type(row['context']) is str and
                re.fullmatch('[A-Za-z0-9_:.,-]+', row['context']), 'CONTINUATION_PIN')
    paths = [PurePosixPath(ref[k]['path']) for k in ('package', 'launch', 'dispatch', 'evidence')]
    require(all(a != b and a not in b.parents for i,a in enumerate(paths) for j,b in enumerate(paths) if i != j),
            'CONTINUATION_REFERENCE_OVERLAP')
    require(digest(ref['plan_sha256']) and type(ref['source_revision']) is str and
            re.fullmatch('[0-9a-f]{40}', ref['source_revision']), 'CONTINUATION_PRIOR_IDENTITY')
    require(all(type(ref[k]) is int and 0 <= ref[k] < 400 for k in ('sequence_record','database_record')) and
            ref['sequence_record'] < ref['database_record'], 'CONTINUATION_RECORDS')


def disjoint_history(ref, new_paths):
    validate_reference(ref)
    # Even the old execution's parent cannot become the new mutable directory.
    old = [PurePosixPath(ref[k]['path']) for k in ('package','launch','dispatch','evidence')]
    require(all(a != b and a not in b.parents and b not in a.parents
                for a in old for b in map(PurePosixPath, new_paths)), 'CONTINUATION_HISTORY_REUSE')


def _read(path, context, expected_sha, deadline, clock):
    """Exact root:root/0600/nlink1 bounded JSON, never returned to stdout."""
    p = PurePosixPath(path)
    with protected_path(str(p.parent), directory=True) as directory:
        fd = _file(directory, p.name, context)
        try:
            before = os.fstat(fd)
            require(before.st_size <= MAX_OUTPUT, 'CONTINUATION_SIZE')
            raw = bytearray()
            while True:
                remaining(deadline, clock)
                block = os.read(fd, 65536)
                if not block: break
                raw.extend(block); require(len(raw) <= MAX_OUTPUT, 'CONTINUATION_SIZE')
            require(len(raw) == before.st_size and _signature(before) == _signature(os.fstat(fd)) and
                    _signature(before) == _signature(os.stat(p.name, dir_fd=directory, follow_symlinks=False)),
                    'CONTINUATION_CHANGED')
            require(expected_sha is None or hashlib.sha256(raw).hexdigest() == expected_sha,
                    'CONTINUATION_HASH')
            return parse(bytes(raw))
        finally:
            os.close(fd)


def verify_prior(values, *, new_paths, deadline, clock=time.monotonic):
    """Called before constructing new evidence/journal, including preflight."""
    plan = values['plan.json']
    require(plan['schema'] == DB_PRESERVED_SCHEMA, 'CONTINUATION_SCHEMA')
    ref = plan['prior_execution']; disjoint_history(ref, new_paths)
    p,e = ref['package'],ref['evidence']
    prior = load_package(p['path'], manifest_sha256=p['sha256'], context=p['context'].encode(),
                         deadline=deadline, clock=clock)
    prior_plan = validate_plan(prior['plan.json'])
    require(prior_plan['schema'] == TRANSITION_SCHEMA and fingerprint(prior_plan) == ref['plan_sha256'],
            'CONTINUATION_PRIOR_PLAN')
    require(prior_plan['binding_sha256'] == fingerprint(prior['host-policy.json']) and
            prior_plan['inputs_sha256'] == prior['host-policy.json']['inputs_sha256'] and
            prior['profile.json']['host_binding_sha256'] == prior_plan['binding_sha256'], 'CONTINUATION_PRIOR_BINDING')
    launch = _read(ref['launch']['path'], ref['launch']['context'].encode(), ref['launch']['sha256'], deadline, clock)
    require(launch.get('schema') == 'fds.harbor.address-launch.v1' and
            launch.get('source', {}).get('revision') == ref['source_revision'] and
            all(launch.get('session', {}).get(k) == v for k,v in {
                'package_path':p['path'], 'package_sha256':p['sha256'], 'package_context':p['context'],
                'evidence_path':e['path'], 'evidence_context':e['context']}.items()), 'CONTINUATION_PRIOR_LAUNCH')
    for key in ('package_path', 'journal_path', 'evidence_path', 'private_path'):
        old_path = launch['session'].get(key)
        require(type(old_path) is str and old_path.startswith('/') and str(PurePosixPath(old_path)) == old_path and
                '..' not in PurePosixPath(old_path).parts, 'CONTINUATION_PRIOR_PATH')
        old_path = PurePosixPath(old_path)
        require(all(old_path != new and old_path not in new.parents and new not in old_path.parents
                    for new in map(PurePosixPath,new_paths)), 'CONTINUATION_HISTORY_REUSE')
    # A dispatch claim is an externally pinned record, not an authorization.
    require(type(_read(ref['dispatch']['path'], ref['dispatch']['context'].encode(),
                       ref['dispatch']['sha256'], deadline, clock)) is dict, 'CONTINUATION_DISPATCH')
    root = e['path']; context = e['context'].encode()
    closed = _read(root+'/evidence.closed', context, e['sha256'], deadline, clock)
    verified = inspect_evidence(root, context=context, plan_sha256=ref['plan_sha256'], deadline=deadline, clock=clock)
    require(verified['valid'] and verified['sealed'] and verified['up_process_intents'] == ['postgresql'],
            'CONTINUATION_PRIOR_EVIDENCE')
    require(type(closed['records']) is int and 0 < closed['records'] <= 400 and
            closed['plan_sha256'] == ref['plan_sha256'], 'CONTINUATION_CLOSE')
    records = [_read(root+f'/{i:06d}.record.json', context, None, deadline, clock)
               for i in range(closed['records'])]
    previous = '0'*64
    for i,r in enumerate(records):
        require(r['sequence'] == i and r['previous_sha256'] == previous and r['plan_sha256'] == ref['plan_sha256'] and
                fingerprint({k:v for k,v in r.items() if k != 'sha256'}) == r['sha256'], 'CONTINUATION_CHAIN')
        previous = r['sha256']
    require(previous == closed['last_sha256'], 'CONTINUATION_CHAIN')
    results = [r for r in records if r['kind'] == 'PROCESS_RESULT' and r['operation'] == 'recreate']
    require(len(results) == 1 and results[0]['service'] == 'postgresql' and
            type(results[0]['diagnostic'].get('rc')) is int and
            results[0]['diagnostic'] == {'rc':0, 'reason':'COMPLETED'}, 'CONTINUATION_DB_ACK')
    def payload(index, kind, service):
        require(index < len(records), 'CONTINUATION_RECORDS')
        row = records[index]
        require(row['kind'] == kind and row['service'] == service and row['operation'] is None and
                set(row['files']) == {'private'}, 'CONTINUATION_RECORD_KIND')
        item = row['files']['private']
        require(item['file'] == f'{index:06d}.private.bin', 'CONTINUATION_RECORD_FILE')
        return _read(root+'/'+item['file'], context, item['sha256'], deadline, clock)
    result = payload(ref['sequence_record'], 'SEQUENCE_RESULT', None)
    require(fingerprint(result) == fingerprint(dict(status='STOP_RECOVERY_REQUIRED', reason='IO_OR_ADAPTER_FAILURE',
        plan_sha256=ref['plan_sha256'], claimed_services=['postgresql'], transport_entered_services=['postgresql'],
        healthy_services=[], this_invocation_may_have_changed=True, journal_recorded=True,
        runtime_acceptance=False, autostart_tested=False)), 'CONTINUATION_PRIOR_RESULT')
    database = payload(ref['database_record'], 'INSPECT', None)
    require(records[ref['database_record']]['diagnostic'] == {'id':database['Id']}, 'CONTINUATION_DB_RECORD')
    require(results[0]['sequence'] < ref['sequence_record'], 'CONTINUATION_RECORDS')
    verify_linkage(values, prior, database)
    # Recheck the external seal after all selected content was consumed.
    require(_read(root+'/evidence.closed', context, e['sha256'], deadline, clock) == closed,
            'CONTINUATION_CHANGED')
    remaining(deadline, clock)


def verify_linkage(values, prior, database):
    """Private full-state linkage; a prior failure never becomes a success."""
    policy, old_policy = values['host-policy.json'], prior['host-policy.json']
    require(policy['identity'] == old_policy['identity'] and
            {k:unit_projection(v) for k,v in policy['units'].items()} ==
            {k:unit_projection(v) for k,v in old_policy['units'].items()},
            'CONTINUATION_GENERATION')
    projection = deepcopy(prior['preservation.json'])
    # PR57 corrects only this known generated label; all other expected fields
    # and explicit mount/address rules must still match the original package.
    projection['after_labels']['postgresql']['com.docker.compose.depends_on'] = ''
    full = FullPreservation(projection['baseline'], **{k:v for k,v in projection.items() if k != 'baseline'})
    old_db = projection['baseline']['postgresql']
    full.row('postgresql', database, recreated=True, mounts_verified=old_db['Mounts'])
    require(database['State']['Status'] == 'running' and database['State']['Health']['Status'] == 'healthy' and
            database['State']['ExitCode'] == 0 and database['State']['Error'] == '', 'CONTINUATION_PRIOR_DB_STATE')
    linked = deepcopy(projection['baseline']); linked['postgresql'] = database
    current = values['preservation.json']
    check = FullPreservation(linked, db_preserved=True, **{k:v for k,v in current.items() if k != 'baseline'})
    for service in SERVICES:
        check.row(service, current['baseline'][service], recreated=False, mounts_verified=linked[service]['Mounts'])
    # The current base differs from the old base ONLY at the already changed DB
    # address. The new model validator separately permits only the remaining8.
    base = deepcopy(prior['base.json'])
    base['services']['postgresql']['logging']['options']['syslog-address'] = database['HostConfig']['LogConfig']['Config']['syslog-address']
    require(fingerprint(base) == fingerprint(values['base.json']), 'CONTINUATION_BASE_SCOPE')
