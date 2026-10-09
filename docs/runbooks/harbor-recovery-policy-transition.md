# Phase 1 앱 restart policy 전환·명시적 부분 원복

CODEX_ASSISTED · 2026-10-09. #33 호스트 provider의 후속이다. 설치 전체가 아니라
**정책 전환 transaction·영속 journal·정책 전용 Engine adapter**를 구현했다.
서버 실행 CLI, 입력 승인/Plan 로더, unit 파일 설치·enable/arm, 일반 reconciliation은 아직 없다.
이번 변경을 서버에 복사해 실행하거나 과거 A3/복구 bundle을 수정하지 않는다.

## 범위

검토된 `TransitionPlan`은 기존 recovery Plan(정확한10개 ID·불변 metadata 지문·예산·실행 binding),
host policy binding, 중지된 manager의 입력 binding에 결속한다. 원 정책은 이번 P1 후보의
logger/앱 전부 `always/MaximumRetryCount=0`으로 제한한다. 실제값이 다르면 새 기준으로 자동 등록하지 않는다.
대상은 앱9개 `always→no`와 그 기록에 대한 `no→always` 원복이며 logger policy는 쓰지 않는다.

`PolicyEngine`은 앱9개 ID의 **RestartPolicy 필드만** update할 수 있다. start/stop/restart/create/
pull/delete/update의 다른 필드는 거부한다. 실제 manager가 사용하는 기존 `UnixEngine`은 계속
update를 거부한다. HTTP 200과 빈 Warnings만 ACK로 보고, 경고/비정상 응답/시간초과는 unknown이다.
ACK는 완료 판정이 아니며 별도 fresh inspect로 전체 정책·ID·metadata·health를 재확인한다.

## 전환 순서

1. 기존 controller Store와 **같은 nonblocking lock**을 획득한다. Store는 앞선 설치 단계에서
   명시적으로 만든 초기 HOLD여야 한다. 이 transaction은 Store를 자동 초기화하거나 기존 HOLD를 지우지 않는다.
2. 검토된 host provider, 준비된 `fds-harbor-recovery.service`의 loaded/inactive/dead/disabled,
   PID0·미실행 Job/trigger·pending reload 없음·정확한 pinned fragment/drop-in을 확인한다.
   unit이 없으면 실패하며 대신 생성/disable/stop하지 않는다.
3. 10개 running/healthy·logger TCP·정확한 승인 metadata·원 정책·동일 boot/daemon을 확인한다.
   원 정책과 Plan/세대를 `policy-transition.json`에 fsync하여 남긴다.
4. postgresql→redis→registry→registryctl→core→portal→jobservice→trivy-adapter→proxy 순으로
   변경 의도 저장 → 토큰별 O_EXCL claim/fsync → fresh guard 재검사 → 단일 정책 update →
   fresh 전체 readback → 결과 저장을 수행한다. 전후 검사도 하나의 monotonic deadline 안에 들어가야 한다.
5. 모두 확인된 경우 `INSTALLED_HOLD`로 끝난다. unit enable/start, controller arm, 앱 start는 하지 않는다.
   이 상태는 정책만 전환된 것이며 자동복구 서비스 설치·동작 완료가 아니다.

Docker policy 변경은 즉시 효력을 갖는다. 전환 도중에는 일부 앱의 자동 재시작 정책이 `no`이고
manager도 아직 꺼져 있는 유지보수 구간이 생긴다. 따라서 실제 설치 회차의 단독 작성·복구 담당·
유한 시간 및 종료 시 명시적 arm 또는 원복 계획이 필요하다. 코드 시험에서 이를 운영 가용성 보장으로
표시하지 않는다. [Docker update 계약](https://docs.docker.com/reference/cli/docker/container/update/)과
[중복 기동 주체 주의](https://docs.docker.com/engine/containers/start-containers-automatically/)를 따른다.

## 실패·부분 원복

- 전송 전 guard 실패는 `not_submitted`, 전송 뒤 오류/응답 유실은 `unknown`이다.
  unknown은 실제 정책이 바뀌었을 수 있으므로 pending/claim을 보존하고 HOLD한다. 조회값이 우연히
  목표와 같다는 이유만으로 완료 처리·재제출·자동 원복하지 않는다.
- ACK 후 readback 실패도 결과 미확정이며 같은 제한을 적용한다. 작업 프로세스 중단 후
  `resume()`은 중간 상태를 HOLD로 남길 뿐 자동 재개하지 않는다.
- 저장/claim 실패 뒤에는 요청을 보내지 않는다. ACK 저장 실패는 이전 pending 또는 `.pending` 원문을
  보존한다. journal 저장의 임시파일이나 기존 Store의 `state-*.pending`이 있으면 다음 transaction을
  차단하며 자동 승격·삭제하지 않는다.
- **원복은 명시적 호출**이다. pending이 없고 기록/현재 정책/ID/불변 metadata/세대가 모두 맞으며
  manager 중지·HOLD와 전체10개 healthy 조건이 유지될 때, readback까지 확인된 변경 목록만 역순으로
  되돌린다. 일부 미전송 실패의 경우 변경한 부분만 이 경로로 원복할 수 있다.
- 앱 unhealthy/세대 변경/manager 활성/불통이면 원복도 중단한다. 원복 성공을 강제하기 위해 restart,
  재생성, 강제 종료, 정책 기준 변경을 하지 않는다. 새 판단·구체 복구가 필요한 상태로 남긴다.
- 실패 시 무조건 자동 compensation을 하는 설치기는 아니다. 결과 미확정 해소 절차는 후속이며,
  `pending` 또는 claim 삭제로 우회하지 않는다.

종료값 `ROLLED_BACK`은 정책 원복만 의미한다. 원 기동 경쟁의 해결·재부팅 성공이나
unit/Compose 파일 원복을 뜻하지 않는다. original/journal/claim은 원복 이후에도 보존하고 같은
directory에서 새 설치 회차를 자동 생성하지 않는다.

## 검증

`python3 -B -m unittest discover -s tests/recovery-core -v`

합성 transaction 시험은 정상9개/역순 원복, 미전송 부분 실패, ACK 후 readback 실패, 응답 유실,
저장/claim 실패, 중복 토큰, 프로세스 중단, 세대·metadata·manager drift와 deadline을 확인한다.
Linux CI에서는 임시 private Store의 실제 fsync/원자 교체/claim·pending 보존과 가짜 Unix HTTP
서버에 대한 정확한 단일 update body를 확인한다. 실제 Docker나 systemd를 변경하지 않는다.

실제 runtime builder는 추가로 승인 입력의 로딩/출처·원복점, root 입력/코드·state/claim/audit의
ACL/xattr/SELinux, unit 파일 준비와 단일 운영 경로, 회차 GO와 증적 수집을 연결해야 한다.
현재 `Journal`은 기존 Store의 mode/소유/nofollow/hardlink 보장을 사용하며, Store 전체 ACL/xattr
검사까지 구현했다고 주장하지 않는다. 실제 서버 전환·AUTOSTART·SYSLOG_INGESTION은 NOT_RUN이다.
