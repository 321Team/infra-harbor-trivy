# Phase 1 명시적 상태 재판정과 앱 중지

CODEX_ASSISTED · 2026-10-09. 독립 코드 리뷰 및 구체 Runtime GO 전 구현이다. 실제 서버 변경 NOT_RUN.

## 입력과 실행 위치

승인된 격리 Harbor의 root·신뢰된 bootstrap에서 기존 bundle/hash/context/timeout 인수를 사용한다.
현재 source 집합은 control을 포함한11개다. 기존9/10개 입력과 source hash를 재사용하지 않는다.

1. `state`는 보호된 Store를 읽고 canonical state SHA256·desired/reason·pending 유무를 반환한다. Executor.open 또는 상태 저장을 하지 않는다. hash는 무결성 식별이며 승인 사실이 아니다.
2. 실행 전 manager가 disabled/inactive/dead이고 작업·복구 인수를 단독 보유해야 한다. manager lifetime lease와 controller lock을 모두 확보한다. 활성 관리자가 있으면 실패한다.
3. `reconcile --state-sha256 <검토한 값> --execute` 또는 `graceful-stop --state-sha256 <검토한 값> --stop-seconds <각 앱 예산> --execute` 중 하나를 선택한다. 전체 timeout/앱별 예산은 최대600초이며 현장 검토값이 필요하다. 다른 명령을 자동 실행하지 않는다.

## 명시적 healthy 재판정

완료된 정책 설치, 정확한 현재 HOLD hash/Plan, 동일 boot/daemon, 단조시계, 전체10 healthy 및 logger TCP, host/보안/소스 검사를 통과해야 한다. 기존 상태를 immutable audit에 먼저 저장하고 RUN으로 전환한다. 이전 start intent/health wait는 현재 settled 관측으로 해소할 수 있으나 과거 POST의 ACK를 얻은 것으로 표시하지 않는다. token sequence·retry history·원 claim은 유지한다. 앱/manager 기동은 수행하지 않는다.

새 boot/daemon·변경된 Plan·불건강·미완료 stop claim·정책 전환 미완료·pending 파일은 해제할 수 없다. 미래 장애의 예산을 임의 초기화하지 않는다.

## 앱9 graceful stop

- 기동 pending/health wait/episode가 없고 전체 healthy에서 시작한다. HOLD를 먼저 영속화한 뒤 proxy→trivy-adapter→jobservice→portal→core→registryctl→registry→redis→postgresql 순서다. logger는 중지·정책 변경하지 않는다.
- 각 앱의 정확한 ID·intent token·claim을 기록하고 다시 fresh 관측한 뒤 요청을 한 번 보낸다. 별도 StopEngine은 승인 앱9 ID의 `POST /stop?t=-1`만 허용하며 신호를 덮어쓰지 않는다. create/start/delete/kill/임의 signal/유한 Docker kill timeout은 거부한다. Config.StopSignal은 전체 immutable fingerprint에 이미 포함되며, 요청 전 동일성을 다시 확인한다.
- 전체9개에 대해 proxy·portal은 SIGQUIT(또는 Linux 신호3), 나머지는 SIGTERM(또는15)인지 첫 HOLD/claim 전과 각 요청 전에 확인한다. 미설정은 Docker 기본 SIGTERM이다. nginx의 SIGTERM은 빠른 종료이므로 허용하지 않으며 PostgreSQL의 SIGQUIT은 즉시 종료이므로 허용하지 않는다. 새 이미지의 종료 계약이 다르면 현장 신호를 임의로 바꾸지 말고 적용 전에 재검토한다. [nginx 종료 신호](https://nginx.org/en/docs/control.html), [PostgreSQL 종료 신호](https://www.postgresql.org/docs/14/server-shutdown.html).
- `t=-1`은 Docker daemon의 강제 종료 타이머를 사용하지 않는 선택이다. 클라이언트 deadline은 별개다. deadline 만료를 daemon 요청 취소로 간주하지 않는다. 실제 종료 시간과 데이터 보존은 별도 Runtime 시험으로 확인한다. [Docker stop 공식 설명](https://docs.docker.com/reference/cli/docker/container/stop/) 및 [Engine API1.53 명세](https://docs.docker.com/reference/api/engine/version/v1.53.yaml)를 기준으로 한다.
- 기존 claim/ACK/readback 형식과 미확정 기록은 보존한다. stop 경로의 의미는 source/host를 포함하는 plan execution binding에 결속되므로 새 소스로 옛 RUN plan이나 미완료 claim을 재사용하지 않는다. 이 수정은 manager 설치·앱 종료·재부팅 허용을 대신하지 않는다.
- 204 ACK 뒤 원 claim에 결속한 `stop-ack`를 영속 기록한다. 대상/기존 중지 앱 exited·나머지 앱 healthy·logger healthy/TCP·동일 세대 전체 readback을 확인해야 stop-done receipt를 남기고 다음 앱으로 간다.304는 우리 요청의 ACK로 간주하지 않는다.
- 모두 완료하면 `APPS_STOPPED_LOGGER_PRESERVED`, HOLD, rc0이다. AUTOSTART 또는 SYSLOG_INGESTION 성공 표기가 아니다.

## 실패와 복구 경계

사전 검사 실패는 새 stop을 보내지 않는다. 중간 실패/ACK 미확정/readback·receipt 저장 실패는 `STOP_INTERRUPTED_OR_UNKNOWN`, rc2 또는 STOP이다. 이미 종료한 앱을 자동 재기동하지 않고 다음 앱에도 요청하지 않는다. 원 claim/audit/receipt/pending를 유지한다. 미완료 stop claim은 재실행·healthy 재판정·bundle에서 조립한 정책 원복을 차단한다.

실제 ACK가 영속 기록된 동일 세대 tail의 readback 누락만 [명시적 관측 정리](harbor-recovery-stop-readback.md)로 확인할 수 있다. 별도 exact state/claim/ACK pin·HOLD·fresh guard를 요구하고 Engine POST0/HOLD 유지다. ACK 없는 미확정 요청이나 legacy pending에는 적용하지 않는다.

강제 kill, claim 삭제, 임의 새 Store 우회, snapshot 복귀는 제공하지 않는다. 미확정 stop의 수동 증적 조사와 복구 결정, 다른 세대/Plan 전환, 정상 중지 후 승인된 재기동은 별도 회차다. `reconcile`은 stopped 앱을 자동 시작하는 기능이 아니다. 운영자 콘솔 인수와 중단된 앱 목록을 남긴다.

## 검증 범위

합성 시험은 state 변경 감지, 전체 healthy/세대/재시도 보존, reverse9/무중복, 부적합 신호의 변경 전 차단·claim 후 metadata drift, 불확실 응답·readback·저장 실패, 정책 원복 gate, API capability를 확인한다. Linux CI는 private file claim과 fake Unix HTTP 전송을 검사한다. 실제 Docker/SELinux/systemd, Harbor 데이터 종료 일관성, 이미지별 종료 반응은 NOT_RUN이다.
