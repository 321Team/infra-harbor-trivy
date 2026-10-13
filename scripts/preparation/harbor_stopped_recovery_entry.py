"""Trusted-caller adapter; verify helper and resident sources before import.

No standalone CLI or self-authentication. The invoking isolated service must
already trust this adapter, its interpreter/stdlib and the bootstrap object.
No ordinary sys.path project imports and no change to the resident catalog.
"""
import importlib
import time


def operate(bootstrap, *, helper_path, helper_spec, bundle_path, bundle_sha256,
            bundle_context, state_pin, operation, deadline, stop_pin=None,
            execute=False, reader=None, clock=time.monotonic):
    bootstrap.runtime_guard()
    bootstrap.require(operation in ('inspect', 'recover'), 'RECOVERY_OPERATION')
    bootstrap.require(bootstrap.sha(state_pin), 'RECOVERY_STATE_PIN')
    bootstrap.require((stop_pin is None and execute is False) if operation == 'inspect' else
                      bootstrap.sha(stop_pin) and execute is True, 'RECOVERY_EXECUTION_INPUT')
    bootstrap.remaining(deadline, clock)
    reader = bootstrap.SecureReader(clock=clock) if reader is None else reader
    raw = reader.read(helper_path, bootstrap.spec(helper_spec), deadline, bootstrap.MAX_SOURCE)
    helper_code = compile(raw.decode('utf-8'), helper_path, 'exec', dont_inherit=True)
    code, _ = bootstrap.collect(bundle_path, bundle_sha256, bundle_context, deadline,
                                reader=reader, clock=clock)
    bootstrap.require(reader.read(helper_path, helper_spec, deadline, bootstrap.MAX_SOURCE) == raw,
                      'RECOVERY_HELPER_CHANGED')
    with bootstrap.VerifiedImporter(code):
        module = importlib.import_module('harbor_recovery_bundle')
        bundle = module.load_bundle(bundle_path, bundle_sha256, bundle_context, deadline, clock=clock)
        module.verify_store_writer(bundle, deadline, clock=clock)
        components = module.build(bundle, deadline, clock=clock)
        namespace = {'__name__': 'verified_stopped_recovery', '__file__': helper_path}
        exec(helper_code, namespace)
        recovery = namespace['StoppedRecovery'](components['control'], clock=clock)
        if operation == 'inspect':
            return recovery.inspect(state_pin, deadline)
        return recovery.run(state_pin, stop_pin, deadline, explicit=True)
