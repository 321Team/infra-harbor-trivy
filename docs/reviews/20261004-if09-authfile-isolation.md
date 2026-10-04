# IF-09 authfile isolation source verification — 2026-10-04

Parent: `030a4ce14acdab3a58c4767455b7555aaf8ce949`.
D22 intake: https://github.com/321Team/fds-project-baseline/pull/137

## Finding and change
DOCKER_CONFIG alone did not establish Podman authfile isolation. The previous unqualified logout could address the caller's default auth store. The child now creates separate positive/negative auth JSON files under one private temporary directory and supplies --authfile for every login/pull/push. REGISTRY_AUTH_FILE is pinned inside the child; inherited Docker configuration is replaced by an empty private directory. No logout is issued. EXIT/INT/TERM/HUP clean up the private directory. SIGKILL and power loss cannot be cleaned up by traps.

The embedded runner, expected body hash, wrapper hash, oneshot and README are synchronized. Approved base digest and Worker/AC-03 sources are unchanged.

## Executed local validation
Windows Git Bash; mock Podman, no registry/network access:
- `bash tests/review/test_runner_auth_isolation.sh`: 7/7 PASS.
- `bash tests/review/test_runner_push_mock.sh`: 22/22 PASS.
- `bash tests/review/test_hbr_formal_run_wrapper.sh`: 23/23 PASS.

Isolation tests cover normal, positive-login failure, push failure, unexpected negative-login success, INT, TERM, HUP. Runtime/default, inherited authfile and Docker-config fixture hashes remain unchanged; temporary credential files are removed; positive and negative paths differ; negative file starts empty. These are mock contract tests, not actual Podman credential resolution proof.

Body SHA256: `b4c8bf988608e3f067476dafaf4dc2438ee150d2a891a938936a19195053ac99`.
Wrapper SHA256: `f33c937fe9212a46f21b3dcd25ccd5f8f21ab441c602c6a00eeacf806c2a8d2a`.

## Remaining gate
Independent code/security review against the PR exact head, Lead decision, and authorized Linux/Podman verification remain pending. No runtime login/pull/push, credential rotation, merge or production acceptance was performed. Historical IF-09 evidence is not retroactively invalidated or replaced. Existing runtime authfile metadata does not establish active CI binding.
