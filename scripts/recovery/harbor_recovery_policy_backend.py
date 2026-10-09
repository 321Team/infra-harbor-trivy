"""Separate exact-ID RestartPolicy update adapter; no start/stop/install CLI."""
from copy import deepcopy
import json
import re
import time

from harbor_recovery_core import ORDER
from harbor_recovery_docker import (UnixEngine, digest, execution_binding, parse_json, project,
                                    remaining, require, logger_tcp)
from harbor_recovery_host import LinuxReadOnly, absolute
from harbor_recovery_transition import PolicyObservation, ORIGINAL, TARGET, observation

MANAGER = 'fds-harbor-recovery.service'
MANAGER_PROPERTIES = ('LoadState,ActiveState,SubState,UnitFileState,MainPID,ControlPID,'
                      'FragmentPath,DropInPaths,NeedDaemonReload,Job,TriggeredBy,Transient')


class PolicyEngine(UnixEngine):
    """Installation only. Explicit allowlist excludes logger and start requests.

    The live recovery manager continues to use UnixEngine, which rejects update.
    """
    def __init__(self, api_version, app_ids, **kwargs):
        super().__init__(api_version, **kwargs)
        require(isinstance(app_ids, (list, tuple)) and len(app_ids) == 9 and
                all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in app_ids) and
                len(set(app_ids)) == 9, 'POLICY_ENGINE_IDS')
        self.app_ids = frozenset(app_ids)

    def _validate_request(self, method, path, body):
        if method == 'GET':
            return super()._validate_request(method, path, body)
        match = re.fullmatch('/containers/([0-9a-f]{64})/update', path)
        require(method == 'POST' and match and match[1] in self.app_ids and
                isinstance(body, bytes) and len(body) <= 256, 'POLICY_OPERATION_NOT_ALLOWED')
        obj = parse_json(body)
        require(isinstance(obj, dict) and set(obj) == {'RestartPolicy'} and
                obj['RestartPolicy'] in (ORIGINAL, TARGET) and
                type(obj['RestartPolicy']['MaximumRetryCount']) is int, 'POLICY_PAYLOAD')

    def update(self, cid, value, deadline):
        require(cid in self.app_ids and value in (ORIGINAL, TARGET) and
                type(value['MaximumRetryCount']) is int, 'POLICY_UPDATE_TARGET')
        raw = json.dumps({'RestartPolicy': value}, sort_keys=True).encode()
        status, body = self._request('POST', '/containers/' + cid + '/update', deadline, raw)
        if status != 200:
            return 'unknown'
        obj = parse_json(body)
        return 'ack' if isinstance(obj, dict) and set(obj) == {'Warnings'} and obj['Warnings'] in (None, []) else 'unknown'


class StoppedManager:
    """Read an already staged, disabled unit, never disable/stop it implicitly.

    Its fragment/dropins and systemctl executable must be in the host provider's
    pinned files. HostProvider verifies those pins before and after this probe.
    """
    def __init__(self, host_policy, fragment, dropins, *, io=None, clock=time.monotonic):
        p = deepcopy(host_policy)
        require(absolute(fragment) and isinstance(dropins, list) and
                all(absolute(v) for v in dropins) and len(dropins) == len(set(dropins)) and
                {fragment, *dropins, p['tools']['systemctl']} <= set(p['files']), 'MANAGER_INPUT_PINS')
        self.spec = {'unit': MANAGER, 'fragment': fragment, 'dropins': deepcopy(dropins),
                     'systemctl': p['tools']['systemctl'], 'directory': p['directory'],
                     'files': {v: p['files'][v] for v in (fragment, *dropins, p['tools']['systemctl'])}}
        self.binding = digest({'stopped_manager_version': 1, 'spec': self.spec})
        self.clock, self.io = clock, io if io is not None else LinuxReadOnly(clock=clock)

    def __call__(self, deadline):
        require(digest({'stopped_manager_version': 1, 'spec': self.spec}) == self.binding,
                'MANAGER_SPEC_CHANGED')
        raw = self.io.run([self.spec['systemctl'], 'show', MANAGER, '--no-pager',
                           '--property=' + MANAGER_PROPERTIES], self.spec['directory'], deadline)
        row = {}
        for line in raw.decode('utf-8', errors='strict').splitlines():
            require('=' in line, 'MANAGER_FORMAT')
            key, value = line.split('=', 1)
            require(key not in row, 'MANAGER_DUPLICATE')
            row[key] = value
        require(set(row) == set(MANAGER_PROPERTIES.split(',')), 'MANAGER_FIELDS')
        require(row['LoadState'] == 'loaded' and row['ActiveState'] == 'inactive' and
                row['SubState'] == 'dead' and row['UnitFileState'] == 'disabled' and
                row['MainPID'] == row['ControlPID'] == '0' and row['NeedDaemonReload'] == 'no' and
                row['Transient'] == 'no' and row['Job'] == row['TriggeredBy'] == '' and
                row['FragmentPath'] == self.spec['fragment'] and
                row['DropInPaths'].split() == self.spec['dropins'], 'MANAGER_NOT_DISABLED_STOPPED')
        remaining(deadline, self.clock)
        return self.binding


class PolicyBackend:
    def __init__(self, plan, engine, host_provider, stopped_manager, *, clock=time.monotonic, probe=None):
        require(isinstance(engine, PolicyEngine) and
                engine.app_ids == frozenset(plan.recovery.ids[n] for n in ORDER), 'POLICY_ENGINE_BINDING')
        require(host_provider.binding == plan.host_binding and stopped_manager.binding == plan.manager_binding,
                'POLICY_HOST_MANAGER_BINDING')
        require(plan.recovery.execution_binding == execution_binding(plan.host_binding, 'harbor', engine.binding),
                'POLICY_RECOVERY_BINDING')
        self.plan, self.engine = deepcopy(plan), engine
        self.host_provider, self.manager = host_provider, stopped_manager
        self.clock = clock
        self.probe = probe if probe is not None else lambda deadline: logger_tcp(deadline, clock)

    def _inventory(self, deadline):
        rows = self.engine.inventory(deadline)
        require(isinstance(rows, list), 'POLICY_INVENTORY')
        found = {}
        for row in rows:
            require(isinstance(row, dict) and isinstance(row.get('Labels'), dict), 'POLICY_INVENTORY')
            labels = row['Labels']
            if labels.get('com.docker.compose.project') != 'harbor':
                continue
            service = labels.get('com.docker.compose.service')
            require(isinstance(service, str) and service not in found, 'POLICY_INVENTORY_DUPLICATE')
            found[service] = row.get('Id')
        require(found == self.plan.recovery.ids, 'POLICY_INVENTORY_CHANGED')

    def observe(self, deadline):
        end = min(deadline, self.clock() + self.plan.recovery.max_age_seconds)
        started = self.clock()
        first = self.host_provider(end)
        require(first.binding == self.plan.host_binding and self.manager(end) == self.plan.manager_binding,
                'POLICY_HOST_MANAGER_BINDING')
        self._inventory(end)
        containers, policies = {}, {}
        for name, cid in self.plan.recovery.ids.items():
            row = self.engine.inspect(cid, end)
            policy = row.get('HostConfig', {}).get('RestartPolicy', {})
            require(policy in (ORIGINAL, TARGET) and type(policy['MaximumRetryCount']) is int,
                    'POLICY_UNEXPECTED_RESTART')
            containers[name] = project(row, name, cid, 'harbor', expected_restart=policy['Name'])
            policies[name] = deepcopy(policy)
        tcp = self.probe(end)
        require(type(tcp) is bool, 'POLICY_LOGGER_PROBE')
        self._inventory(end)
        require(self.manager(end) == self.plan.manager_binding, 'POLICY_MANAGER_CHANGED')
        last = self.host_provider(end)
        require((first.boot, first.daemon, first.binding) == (last.boot, last.daemon, last.binding),
                'POLICY_GENERATION_CHANGED')
        remaining(end, self.clock)
        return PolicyObservation(last.boot, last.daemon, min(started, first.at, last.at),
                                 self.plan.host_binding, self.plan.manager_binding,
                                 {n: v.id for n, v in containers.items()},
                                 {n: v.fingerprint for n, v in containers.items()}, policies,
                                 tcp and all(v.status == 'running' and v.health == 'healthy'
                                             for v in containers.values()))

    def update(self, action, previous, deadline):
        try:
            require(isinstance(action, dict) and action['service'] in ORDER and
                    action['id'] == self.plan.recovery.ids[action['service']] and
                    action['from'] == previous.policies[action['service']] and
                    action['direction'] in ('install', 'rollback') and
                    action['to'] == (TARGET if action['direction'] == 'install' else ORIGINAL),
                    'POLICY_ACTION')
            fresh = self.observe(deadline)
            observation(self.plan, fresh, previous.policies, self.clock())
            require((fresh.boot, fresh.daemon) == (previous.boot, previous.daemon), 'POLICY_DISPATCH_GENERATION')
            remaining(deadline, self.clock)
        except Exception:
            return 'not_submitted'
        try:
            outcome = self.engine.update(action['id'], action['to'], deadline)
            remaining(deadline, self.clock)
            return outcome if outcome == 'ack' else 'unknown'
        except Exception:
            return 'unknown'  # request may have reached Engine; never retry
