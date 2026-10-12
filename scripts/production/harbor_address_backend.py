"""Connect Sequence, complete inspect validation and pinned Compose transport.

This is a backend library, not a ready production CLI. host_provider must be a
reviewed, bounded Linux collector of current host/protected inputs, pinned image
refs, exact external network/volume inventory and the mount profile's metadata.
No observed metadata is enrolled as an approval or new profile by this module.
"""
from copy import deepcopy
import os
import threading
import time

from harbor_address_compose import ComposeTransport, remaining, require
from harbor_address_sequence import ORDER, SERVICES, MAINTENANCE_SCHEMAS, TRANSITION_SCHEMA, fingerprint, validate_plan


class AddressBackend:
    def __init__(self, plan, *, engine, host_provider, preservation, mount_preservation,
                 execution_model, execution_model_sha256, process, clock=time.monotonic, legacy_bindings=None):
        self.plan = validate_plan(plan)
        require(self.plan['schema'] in MAINTENANCE_SCHEMAS, 'BACKEND_HEALTHY_MAINTENANCE_REQUIRED')
        require(callable(host_provider), 'BACKEND_HOST_PROVIDER')
        self.engine, self.host, self.preservation, self.mount = engine, host_provider, preservation, mount_preservation
        self.clock, self.pid = clock, os.getpid()
        self.changed, self.new_ids = [], {}
        self.failed, self._writing = False, threading.Lock()
        self.model_sha = execution_model_sha256
        self.transport = ComposeTransport(execution_model, model_sha256=execution_model_sha256,
            plan_sha256=fingerprint(self.plan), ids={s: r['id'] for s, r in self.plan['baseline'].items()},
            process=process, verify=self._prewrite, clock=clock, legacy_bindings=legacy_bindings,
            preflight_seconds=(self.plan['io_seconds'] if self.plan['schema']==TRANSITION_SCHEMA else None))

    def _host(self, deadline):
        started = self.clock()
        value = self.host(deadline)
        now = self.clock()
        remaining(deadline, self.clock)
        required = {'binding_sha256', 'inputs_sha256', 'at', 'logger_ipv4', 'model_sha256',
                    'preservation_binding', 'mount_inputs'}
        require(type(value) is dict and set(value) == required and
                value['binding_sha256'] == self.plan['binding_sha256'] and
                value['inputs_sha256'] == self.plan['inputs_sha256'] and
                value['model_sha256'] == self.model_sha and
                value['preservation_binding'] == self.preservation.binding and
                type(value['at']) in (int, float) and started <= value['at'] <= now and
                now-value['at'] <= self.plan['observation_max_age'] and value['logger_ipv4'] is True and
                type(value['mount_inputs']) is dict, 'BACKEND_HOST_CHANGED')
        return value

    def _ids(self, deadline):
        rows = self.engine.inventory(deadline)
        require(type(rows) is list, 'BACKEND_INVENTORY')
        result = {}
        for row in rows:
            require(type(row) is dict and (row.get('Labels') is None or type(row.get('Labels')) is dict), 'BACKEND_INVENTORY')
            labels = row.get('Labels') or {}
            if labels.get('com.docker.compose.project') != 'harbor':
                continue
            name = labels.get('com.docker.compose.service')
            require(name in SERVICES and name not in result, 'BACKEND_DUPLICATE_OR_EXTRA_SERVICE')
            result[name] = row.get('Id')
        require(set(result) == set(SERVICES) and len(set(result.values())) == 10, 'BACKEND_SERVICE_SET')
        return result

    def observe(self, deadline):
        require(os.getpid() == self.pid, 'BACKEND_FORKED')
        started = self.clock()
        first = self._host(deadline)
        ids = self._ids(deadline)
        raw = {s: self.engine.inspect(cid, deadline) for s, cid in ids.items()}
        require(all(raw[s].get('Id') == ids[s] for s in SERVICES), 'BACKEND_INSPECT_ID')
        require(self._ids(deadline) == ids, 'BACKEND_INVENTORY_CHANGED')
        last = self._host(deadline)
        require(fingerprint({k: v for k, v in first.items() if k != 'at'}) ==
                fingerprint({k: v for k, v in last.items() if k != 'at'}), 'BACKEND_HOST_CHANGED')
        before_mounts = {s: v['Mounts'] for s, v in self.preservation.before.items()}
        after_mounts = {s: v['Mounts'] for s, v in raw.items()}
        labels = {s: {k: v[k] for k in ('MountLabel', 'ProcessLabel')} for s, v in raw.items()}
        self.mount.check(before=before_mounts, after=after_mounts, completed_services=list(self.changed),
                         labels=labels, **last['mount_inputs'])
        expected_mounts = deepcopy(before_mounts)
        for service in self.changed:
            if service in self.mount.profile['baseline_mounts']:
                for m in expected_mounts[service]:
                    if m['Type'] == 'volume':
                        m['Mode'] = 'z'
        projected = {s: self.preservation.row(s, r, recreated=(s in self.changed),
                     mounts_verified=expected_mounts[s]) for s, r in raw.items()}
        for s in self.changed:
            if s in self.new_ids:
                require(projected[s]['id'] == self.new_ids[s], 'BACKEND_NEW_ID_REPLACED')
            else:
                self.new_ids[s] = projected[s]['id']
        remaining(deadline, self.clock)
        return dict(binding_sha256=last['binding_sha256'], inputs_sha256=last['inputs_sha256'],
                    observed_mono=started, logger_ipv4=True, rows=projected)

    def _prewrite(self, deadline):
        observation = self.observe(deadline)
        require(self.clock()-observation['observed_mono'] <= self.plan['observation_max_age'], 'BACKEND_STALE')
        for name, row in observation['rows'].items():
            old = self.plan['baseline'][name]
            if name in self.changed:
                require(row['status'] == 'running' and row['health'] == 'healthy' and
                        row['preservation_sha256'] == old['preservation_sha256'] and row['exit_code'] == 0 and
                        row['error_sha256'] == old['error_sha256'], 'BACKEND_NOT_READY')
            else:
                require(row == old, 'BACKEND_UNTOUCHED_CHANGED')
        return {s: r['id'] for s, r in observation['rows'].items()}

    def recreate(self, *, service, expected_id, plan_sha256, deadline_mono):
        require(self._writing.acquire(blocking=False), 'BACKEND_BUSY')
        try:
            require(not self.failed, 'BACKEND_SPENT')
            rc = self.transport.recreate(service=service, expected_id=expected_id,
                                         plan_sha256=plan_sha256, deadline_mono=deadline_mono)
            self.changed.append(service)
            return rc
        except BaseException:
            self.failed = True
            raise
        finally:
            self._writing.release()
