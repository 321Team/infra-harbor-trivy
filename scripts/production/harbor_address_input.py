"""Encode a reviewed resolved Compose candidate for private stdin consumption.

Pure function, no I/O, credential resolution, authorization or runtime request.
The caller must validate address-only scope and keep both input/output private.
Actual Compose must render the returned bytes and pass validate_rendered before
the SAME bytes are consumed by the reviewed adapter, with a controlled process
environment and --env-file /dev/null. Never reserialize the rendered output.
"""
from copy import deepcopy
import json
from pathlib import PurePosixPath

SERVICES = {'postgresql', 'redis', 'registry', 'registryctl', 'core', 'portal',
            'jobservice', 'trivy-adapter', 'proxy', 'log'}
MAX_BYTES = 8 * 1024 * 1024


def require(ok, code):
    if not ok:
        raise ValueError(code)


def canonical(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    except Exception:
        raise ValueError('INPUT_JSON') from None
    require(len(raw) <= MAX_BYTES, 'INPUT_SIZE')
    return raw


def absolute(value):
    return (type(value) is str and value.startswith('/') and '\0' not in value and
            str(PurePosixPath(value)) == (value.rstrip('/') or '/') and
            '..' not in PurePosixPath(value).parts)


def expected_model(candidate):
    """Make an omitted bind create_host_path=false explicit, never enable it.

    A resolved Compose JSON model can contain missing false defaults that are
    reinterpreted as true on reload. Preserve explicit true/false and all other
    fields, including all secret values, without logging their contents.
    """
    require(type(candidate) is dict and type(candidate.get('services')) is dict and
            set(candidate['services']) == SERVICES, 'INPUT_SERVICES')
    require(not any(candidate.get(k) for k in ('include', 'secrets', 'configs')), 'INPUT_EXTERNAL_SOURCE')
    result = deepcopy(candidate)
    for service in result['services'].values():
        require(type(service) is dict and not any(service.get(k) for k in
                ('env_file', 'extends', 'build', 'secrets', 'configs')), 'INPUT_UNRESOLVED_SERVICE')
        environment = service.get('environment', {})
        require(type(environment) is dict and all(type(k) is str and type(v) is str
                for k, v in environment.items()), 'INPUT_UNRESOLVED_ENV')
        mounts = service.get('volumes', [])
        require(type(mounts) is list, 'INPUT_MOUNTS')
        targets = set()
        for mount in mounts:
            require(type(mount) is dict and mount.get('type') in ('bind', 'volume') and
                    absolute(mount.get('target')) and mount['target'] not in targets, 'INPUT_MOUNT')
            targets.add(mount['target'])
            if mount['type'] == 'bind':
                require(absolute(mount.get('source')), 'INPUT_BIND_SOURCE')
                options = mount.setdefault('bind', {})
                require(type(options) is dict and type(options.get('create_host_path', False)) is bool,
                        'INPUT_BIND_OPTIONS')
                options.setdefault('create_host_path', False)
    canonical(result)
    return result


def _escape_values(value):
    if type(value) is str:
        return value.replace('$', '$$')
    if type(value) is list:
        return [_escape_values(v) for v in value]
    if type(value) is dict:
        # Compose interpolates YAML/JSON values, not mapping keys.
        require(all(type(k) is str for k in value), 'INPUT_JSON_KEYS')
        return {k: _escape_values(v) for k, v in value.items()}
    require(value is None or type(value) in (bool, int, float), 'INPUT_JSON_TYPE')
    return value


def encode_stdin(candidate):
    """Sensitive bytes; never write to public logs/artifacts or process argv."""
    return canonical(_escape_values(expected_model(candidate)))


def validate_rendered(candidate, rendered):
    """Fail on ANY unintended field/value/type change; errors contain no data."""
    require(canonical(expected_model(candidate)) == canonical(rendered), 'INPUT_ROUNDTRIP_CHANGED')
    return {'resolved_input_roundtrip': 'MATCHED', 'runtime_apply': 'NOT_PERFORMED'}
