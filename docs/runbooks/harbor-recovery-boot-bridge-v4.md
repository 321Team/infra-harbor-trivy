# Production v4: OS boot bridge identity contract

CODEX_ASSISTED. Code/input contract only; no production enrollment or H4/AC pass.

## Failure and scope

On 2026-10-14 H4, the approved v3 source rejected `docker0` and the Harbor
bridge after the kernel recreated them during a VM reboot. Their MAC,
`bridge_id` and `root_id` changed together; the Harbor bridge's EUI64 link-local
IPv6 route changed too. Physical links and other stable network fields matched.
The retained production evidence reproduced both old digest mismatches offline.
PR63's daemon restart CI kept kernel bridges alive and did not cover this event.

New schema `fds.harbor.recovery.bundle.production.v4` binds host version4 to a
new reviewed input/Store. Existing v1/v2/v3 parsing, projections, fingerprints
and bindings retain their old meaning. V4 keeps the v3 fingerprint2/DNS rule.
Bootstrap, package/checker, installer and runtime must use the same source.

## Bound comparisons

- Exact physical interface set, physical MAC/MTU, custom Docker network ID,
  complete stable network/IPAM/options, empty built-in bridge, container IDs,
  and both ends of every container veth remain verified. No foreign bridge
  port, endpoint or interface is accepted by name alone.
- Only those approved Docker bridge links may vary their locally administered
  unicast MAC. Both bridge IDs must encode that **current MAC and the pinned
  priority**. STP must be disabled, root port/cost zero and address generation
  EUI64. Missing/malformed IDs or a different root fail closed. The projection
  normalizes these three validated fields; priority, MTU and every other
  configuration/unknown field remain pinned. A coherent MAC rotation within
  this narrow contract is accepted regardless of who initiated it; this check
  cannot attribute a root user's consistent manual MAC change to a reboot.
- `network.bridge_ipv6` is required in v4, with exactly one reviewed mode for
  each custom/default bridge: `absent` or `eui64`. It is an input contract,
  not permission to learn the current host automatically.
- `absent` requires no IPv6 address or IPv6 bridge route. `eui64` requires
  exactly one /64 link-local address matching the current MAC, and the exact
  kernel prefix/local/multicast routes. Only the validated local destination
  is canonicalized. DAD-failed/optimistic, foreign addresses/routes and unknown
  route attributes fail closed. A missing local route is accepted only while
  that exact address is visibly tentative and the other two routes exist;
  the comparison represents the expected local route without writing one.
- Physical/default/static routes, IPv4 IPAM and the nftables AC04 table remain
  pinned. Full host/code/unit/SELinux checks and second topology reads remain.

The Linux reference behavior is described by [bridge documentation](https://docs.kernel.org/networking/bridge.html)
and the pinned upstream [bridge setup](https://github.com/torvalds/linux/blob/v6.12/net/bridge/br_device.c),
[bridge ID update](https://github.com/torvalds/linux/blob/v6.12/net/bridge/br_stp_if.c),
and [IPv6 address configuration](https://github.com/torvalds/linux/blob/v6.12/net/ipv6/addrconf.c).
These support the algorithm; retained host bytes and actual CI are separate evidence.

## Validation before review

`test_boot_bridge_contract.py` covers full/partial/stopped inventories,
new boot+daemon+MAC+IPv6 change, ordered one-time recovery, persistent claim
reuse prevention, DAD transition, malformed/mismatched IDs, physical/network
drift, failure after the first start, legacy compatibility and the full v4
package/bootstrap/installer/runtime path.

The CI matrix retains the v3 daemon-only case and adds v4 `bridge-recreate`:
an explicitly disposable empty Linux network namespace, isolated Docker29.8.2
socket/data/exec roots, scratch synthetic workload, real daemon shutdown,
exact kernel bridge deletion/recreation, preserved Docker IDs, real Engine
start/health and POSIX Store. Boot UUID, systemd/SELinux/AC04 and workload are
synthetic. **This is not a real VM reboot, service installation, Harbor H4 or AC.**

## Production transition and stop boundaries

1. After independent code review and separately authorized merge, derive the
   v4 projections from actual approved target inputs. Supply new source hashes,
   bootstrap, bundle/bindings and a new Store namespace. Do not replace the
   old bundle's hashes, reinterpret old RUN state or delete/reuse used claims.
2. Review the complete package and transition, including current bridge IPv6
   modes, manager failed state, app policies and all existing Store originals.
   Reuse the existing proven install/writer/protection workflow; no SELinux or
   network exception is introduced here. Do not synthesize boot, window,
   label, target or budget values.
3. Confirm the current non-overlap after Ansible PR83/AC05 release, then perform
   only the specifically authorized installation/manager restoration scope.
   A mismatch, unknown result, generation change or deadline stops subsequent
   writes, preserving receipts and partial state. No automatic rollback/retry.
4. The failed H4 one-time reboot and availability-recovery permits are consumed.
   A new H4 VM reboot trial needs its own concrete approved execution boundary.
   Preserve the pre-change snapshot and recovery procedure; no automatic restore.

Until separately verified, manager restoration, new H4 Runtime and AC remain open.
