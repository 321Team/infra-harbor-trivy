# 격리 Harbor SSH — 계획 전원 전환 후보

baseline#13, CODEX_ASSISTED. **코드 리뷰·실행안 후보이며 전원 종료/Runtime GO가 아니다.**
이 문서와 `hbr-ssh-coldboot.py`는 evidence#187의 2026-10-09 설치 한 건에만 해당한다.
기존 설치기/endpoint/세션/rollback 코드는 수정하지 않는다.

## 문제와 경계

Workstation 26의 실행 중 NIC 추가 화면에서 Connected 및 MAC 입력란이 비활성이다.
고정 MAC `00:50:56:35:78:e4`를 적용 전에 지정하는 현 경로는 막혔다.
설치 성공이 VMware 하드웨어 변경 가능성을 증명하지 않는다는 점을 정정했다.
전원 순환은 현재 A3 실패상태를 바꾸는 새 회차다. 기존 claim/result와 원 판정을 유지한다.

조회 근거: evidence#187, 설치 상태 SHA256
`5c8666145f48ac68641a5ddfd19e0d0de48362dc85cc0628b3d3260e7ac50400`,
이전 boot `ec7a9c3c-3a91-4d4a-8d42-f68ce23ce92b`.
Docker enabled, 컨테이너10개 restart=always, 현재 logger1 healthy/앱9 exited다.
Docker Requires에 docker.socket 및 fds-harbor-ac04-guard가 포함된다.
socket/containerd disabled만으로 부팅 시 Docker를 막는다고 판단하지 않는다.

선택한 후보는 **Docker 자동기동 정책을 바꾸지 않고 새 부팅의 상태를 관측**하는 것이다.
기존 실패한 부트를 계속 유지해야 하면 전원 전환하지 않고 콘솔 수집을 계속한다.
기존 서비스 mask/disable, A3 재시도/restore, 신규 계정·권한 확대는 이 코드에 없다.

## 종료 전 필수조건 — 아직 충족 완료 아님

1. evidence#187 독립 검토 및 private 원문 보존 위치/해시 확인. 원문은 guest root 전용
   `/root/hbr-ssh-bootcheck-k_awxzgk`에 있다. 이 폴더의 요약을 반출한 것과 전체 원문
   외부 백업을 혼동하지 않는다. 전원 전환 전 현재 상태 복구점을 확보하고 검증한다.
   기존 `before-address-A2-20261008-1500` 스냅샷은 **현재 설치/A3 상태의 복구점이 아니다**.
   새 복구점 생성 방식과 충분한 저장 공간을 확인하고, 자동 snapshot restore는 하지 않는다.
2. 본 helper exact HEAD 독립 리뷰와 실제 CentOS Python/CLI 사전검증. root 보존 경로로
   전달하고 source SHA를 확인한다. HGFS를 닫고 마지막 guest umount까지 확인한다.
3. Lead가 정확한 clone UUID/VMX와 **정상 종료1회·부팅1회 및 Docker 자동기동에 따른
   상태 변화**를 명시해 실행 창을 확정한다. user의 코드 보완 착수는 이 결정과 별개다.
4. 만료 2026-10-09 15:06:30 KST까지 검토·부팅·capture/apply/접속·정리에 충분한 시간이
   있어야 한다. apply는 최소60초 잔여를 요구하지만 운영 작업시간은 더 필요하다.
   만료나 상태 변경 시 이 helper 사용을 중단한다. 설정/해시/시각을 편집해 우회하지 않는다.

## 전원/NIC 순서 — 승인 후에만

1. 정확한 clone을 콘솔에서 정상 종료한다. hard power-off/강제 reset은 이 안에 없다.
2. 전원 OFF 확인 후 NIC1개를 Custom VMnet2, MAC `00:50:56:35:78:e4`로 추가한다.
   **Connected 및 Connect at power on 모두 해제**한다. VMX/GUI를 대조한다.
   기존 운영 NIC를 복원하거나 VMnet0/1/8로 연결하지 않는다.
3. 부팅1회 후 케이블 미연결을 유지한다. Docker/guard 자동기동 결과를 새 부트 증적으로
   수집하며 A3 자동기동 PASS로 소급하지 않는다. 도구는 Docker 명령을 실행하지 않는다.
4. 콘솔에서 `hbrmgmt0`/지정MAC, unmanaged/down/주소 없음, 기존 운영 autoconnect=no,
   HGFS 없음, SELinux Enforcing을 확인한다. 전용 nft는 아직 복구 전이다.

## capture → 사람의 검토 → apply

형식 예시이며 현재 실행 명령이 아니다. helper는 root 소유·비쓰기 부모의 로컬 경로에 둔다.

```bash
sudo python3 -I /root/<reviewed-source>/hbr-ssh-coldboot.py capture
```

capture는 현재 설치기 파일의 승인 SHA, 기존 state/A3 result/claim의 고정 해시,
새 boot, 미사용 session/coldboot claim, 실제 계정/설치파일/SSHD/물리NIC 및 NM guard를
확인한다. 전원이나 설정을 바꾸지 않고 root private review JSON을 쓴다.

이전 loopback/Docker bridge의 이름·global 주소·IPv4 route는 유지해야 한다. 새 veth는
기존 bridge에 종속되어 IPv6 link-local /64만 갖는 경우에 한해 조회를 허용한다.
기존 bridge의 IPv6 link-local 변화도 보고서에 남긴다. 새 bridge/global주소/default/
gateway/관리주소/관리route/추가 물리NIC/관리 link UP이면 거부한다.
이 범위 허용은 기존 세션 guard의 완화가 아니다. 승인된 **새 부트 기준값**을 명시적으로
결속하기 위한 후보이며 세션 실행 때는 기존 guard가 새 기준과 정확히 대조한다.

출력 `COLDBOOT_CAPTURE_REVIEW_REQUIRED SHA256=... PATH=...`의 JSON을 검토한다.
원 부트와의 차이, Docker/guard 상태, nft table 부재, 만료 timer inactive가 포함된다.
단순 SHA 복사로 승인을 대신하지 않는다. capture가 중단되면 콘솔 오류를 보존한다.
capture 이전 guard/조회 실패의 raw stdout/stderr를 자동 보존하는 수집기는 아니므로,
필요한 오류 원문은 별도 읽기 전용 조회로 확보한다.

호스트에서 VMnet2 고립, .1/24, DHCP/NAT/bridge/다른VM/forwarding 없음 및 **실제
VMware 케이블 미연결**을 새로 확인한다. root 소유 비쓰기
`/var/lib/hbr-ssh-control/coldboot-host-gate.json`에 다음 값을 기록한다.
템플릿을 미검증 true/false로 채우지 않는다.

- 기존 host-gate 필드: vmnet/host_only/dhcp/nat/bridge/other_guests/host_forwarding/
  host/guest/mac/interface/checked_epoch. 기존 `gate_valid`와 같은 정확한 값·bool타입,
  10분 이내·미래 아님 조건이다.
- 추가: `cable_disconnected: true`, `boot: <검토한 새 boot UUID>`,
  `review_sha256: <검토한 capture SHA256>`. 알 수 없는 필드는 거부한다.
- guest admin-down은 실제 VMware 케이블 미연결의 독립 증명이 아니다. host 기록이 필수다.

```bash
sudo python3 -I /root/<reviewed-source>/hbr-ssh-coldboot.py apply --review-sha <reviewed-sha256>
```

apply는 동일 조회를 다시 수행해 검토 후 변화를 거부한다. `coldboot.claim`을 배타 생성,
원 state를 `before-coldboot-state.json`에 보존하고 전용 nft 테이블만 syntax/apply한다.
기존 nft shape와 일치해야 원래 절대시각 expiry timer만 시작한다. 만료를 연장하지 않는다.
계정/파일/SSHD/네트워크를 다시 검증한 뒤 검토받은 새 baseline을 state에 결속한다.
정상 `COLDBOOT_REARMED_LINK_DISABLED`는 연결 준비 단계이고 session start/AC PASS가 아니다.

5. 복구 결과를 검토한 뒤 새 host-gate.json(기존 세션 형식)을 실제 확인값으로 작성한다.
   케이블 연결은 그 다음 명시된 단계다. NIC 활성화/주소는 기존
   `hbr-ssh-session.service`를 통해서만 수행한다. 네트워크/방화벽/SSH 음성시험은 별도다.

## 실패·원복

- capture 실패: 케이블 미연결 유지, 조회 오류를 보존. 설정 자동 변경 없음.
- apply 실패: `COLDBOOT_REARM_FAILED_CONSOLE_REVIEW_REQUIRED`와 원 state/claim을 보존.
  원 baseline을 성공 기준으로 덮어쓰지 않는다. 적용된 nft/timer를 무조건 지우지 않는다.
  링크를 올리는 명령 자체가 없으며 실패 시에도 케이블은 호스트에서 미연결 상태여야 한다.
  claim을 지우거나 반복 apply하지 않고 콘솔에서 현재 상태와 명령 receipt를 검토한다.
- SSH 설치 철거는 기존 검토된 rollback을 사용하되 **물리NIC를 제거하고 HGFS가 없는 상태**가
  선행조건이다. 현재 장비에서 hot-remove가 불가능하면 추가 전원 조작은 별도 결정한다.
  MAC/파일 drift를 무시하거나 임의 reboot/restore로 복구하지 않는다.
- 만료는 연결 차단이고 자동 계정/파일 철거가 아니다. 이번 helper도 파일/claim 이력을 남긴다.

## 검증 한계

자동 테스트는 MOCK으로 실패·해시·gate·네트워크 차이·nft/timer·단일 실행 보존을 검증한다.
실제 CentOS 새 부팅, nft 재구성, timer, VMware NIC, SSH 인증·격리·복구는 NOT_RUN이다.
현재 도구는 고정 설치 한 건에만 적용되며, 다른 설치로 일반화하거나 pin을 수정해 재사용하지 않는다.
