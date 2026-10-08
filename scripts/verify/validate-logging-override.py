#!/usr/bin/env python3
"""Compare Compose JSON renderings without printing resolved secret values.

No Docker/SSH/subprocess, source writes, container changes or startup judgment.
Inputs may contain resolved credentials: keep them private and never publish.
"""
import argparse
import copy
import json
from pathlib import Path

SERVICES = ('core', 'jobservice', 'portal', 'postgresql', 'proxy', 'redis',
            'registry', 'registryctl', 'trivy-adapter')
OLD = 'tcp://localhost:1514'
NEW = 'tcp://127.0.0.1:1514'
MAX_BYTES = 8 * 1024 * 1024


class Invalid(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Invalid(code)


def load(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'INPUT_SIZE_INVALID')
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, 'DUPLICATE_JSON_KEY')
            obj[key] = value
        return obj
    def constant(_):
        raise Invalid('NONFINITE_JSON')
    try:
        obj = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except Invalid:
        raise
    except Exception:
        raise Invalid('JSON_INVALID') from None
    require(type(obj) is dict, 'JSON_OBJECT_REQUIRED')
    return obj


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), allow_nan=False)


def validate(base, effective):
    """Exact nine-service scope; preserve all other normalized fields."""
    try:
        services = base['services']
        require(type(services) is dict and set(services) == set(SERVICES) | {'log'},
                'SERVICE_SET_CHANGED')
        log = services['log']
        require(type(log) is dict and log.get('restart') == 'always', 'LOGGER_SCOPE_CHANGED')
        ports = log.get('ports')
        require(type(ports) is list and len(ports) == 1 and type(ports[0]) is dict,
                'LOGGER_PORT_CHANGED')
        port = ports[0]
        require(type(port.get('target')) is int and port['target'] == 10514
                and port.get('published') == '1514' and port.get('host_ip') == '127.0.0.1'
                and port.get('protocol') == 'tcp', 'LOGGER_PORT_CHANGED')
        expected = copy.deepcopy(base)
        for name in SERVICES:
            service = services[name]
            require(service['restart'] == 'always' and service['logging']['driver'] == 'syslog'
                    and service['logging']['options']['syslog-address'] == OLD,
                    'BASELINE_LOGGING_CHANGED')
            expected['services'][name]['logging']['options']['syslog-address'] = NEW
        # Compare all fields and types; no projection that hides extra mutations.
        require(canonical(effective) == canonical(expected), 'CHANGE_OUTSIDE_ADDRESS_SCOPE')
        return {'schema': 'P1-HBR-logging-override-check-1', 'CONFIG_DELTA': 'PASS',
                'changed_services': list(SERVICES), 'address_change_count': len(SERVICES),
                'preserved_scope': 'ALL_OTHER_NORMALIZED_FIELDS',
                'RUNTIME_APPLY': 'NOT_PERFORMED', 'AUTOSTART': 'NOT_TESTED',
                'AC04': 'NOT_EVALUATED'}
    except Invalid:
        raise
    except Exception:
        raise Invalid('CONFIG_SHAPE_INVALID') from None


def check(base_raw, effective_raw):
    try:
        return 0, validate(load(base_raw), load(effective_raw))
    except Invalid as exc:
        # Invalid values are fixed codes from this module, never input data.
        return 2, {'schema': 'P1-HBR-logging-override-check-1', 'CONFIG_DELTA': 'FAIL',
                   'error_code': str(exc), 'RUNTIME_APPLY': 'NOT_PERFORMED',
                   'AUTOSTART': 'NOT_TESTED', 'AC04': 'NOT_EVALUATED'}


def read(path):
    with Path(path).open('rb') as stream:
        return stream.read(MAX_BYTES + 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-json', required=True)
    parser.add_argument('--effective-json', required=True)
    args = parser.parse_args()
    try:
        rc, result = check(read(args.base_json), read(args.effective_json))
    except Exception:
        rc, result = 2, {'CONFIG_DELTA': 'FAIL', 'error_code': 'INPUT_READ_FAILED',
                         'RUNTIME_APPLY': 'NOT_PERFORMED', 'AUTOSTART': 'NOT_TESTED'}
    print(json.dumps(result, sort_keys=True))
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
