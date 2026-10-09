# A3 실패 앱의 명시적 복구와 영구 기동 보완 경계

CODEX_ASSISTED. baseline #13, evidence #171/#187, code #18/#22/#25 후속.
이 변경은 **고정된 격리 clone의 일회성 복구 코드**다. Docker 자동기동 수정,
상주 기동기 설치, AC04 PASS 또는 운영 Harbor 실행 승인이 아니다.

## 현재 근거와 목적

A3 Docker restart는 rc0였지만 앱9개가 IPv4 syslog `127.0.0.1:1514` 접속 거부로
기동에 실패했다. logger는 이후 healthy가 됐다. 원 실패 결과와 claim은 보존한다.
SSH 준비는 주 실행 경로에서 제외했으며 사용자는 rollback의 ROLLED_BACK/rc0를 확인했다.
이후 콘솔 조회에서 AC04 테이블, Docker Requires/After의 guard 참조를 확인했다.
이는 실제 패킷 차단, SSH 잔여파일 전체 부재 또는 Harbor 자동기동 PASS가 아니다.

현재 실패 상태에서 과거 A2 restore나 A3 재시작 명령을 재사용하지 않는다.
복구를 독립된 회차로 남겨 향후 후보 검증의 기준 상태를 확보한다.

## 고정 범위

- VM `D:\FDS-Isolated-Lab\harbor01-20261008\harbor01-test.vmx`만, 기존 UUID/hostname guard 적용.
- NIC 없음, HGFS mount 없음, SELinux Enforcing, SSH state ROLLED_BACK 필수.
- 원 A3 result/claim과 candidate-check-result.json은 각각 SHA256으로 고정한다.
- 기존 A3 boot 및 Docker InvocationID가 달라졌으면 거부한다.
- trial.py는 기존 승인 바이트 `0a79b3b70d18211fcacb94903332b81e71168ade18225909ed4d53e26be3d8c4`만 사용한다.
- 10개 컨테이너 ID/image/mount/logging/restart/ports/project/service/name을 A3 이후 메타데이터와 대조한다.
- logger는 running/healthy 및 IPv4 TCP accept가 필요하다. 앱9개는 원 exited/unhealthy,
  exit128 및 고정 syslog 오류 해시와 일치해야 한다. 다른 원인의 장애를 이 코드로 복구하지 않는다.
- Docker 활성 상태/동일 InvocationID/guard 의존성·순서·활성 상태를 확인한다.
  AC04 JSON 테이블을 기록하고 이후 매 앱 기동 전에 형태가 같은지 대조한다.
  counter 값과 handle만 비교에서 제외한다. 이는 시작 시점 allowlist 정당성/패킷 시험을 대신하지 않는다.
- 기존 engine/compose/security/label 및 volume inventory/xattr 검사를 재사용하고 전후 대조한다.

## 동작

기존 A3 lock을 비차단 획득한다. preflight 후 상태를 재조회하고 별도
`/root/hbr-a3-app-recovery.claim`을 배타 생성하여 fsync한 뒤 시작 의도를 기록한다.
기존 A3 claim은 읽기만 한다. 새 claim도 성공/실패와 무관하게 삭제하지 않는다.

순서는 postgresql → redis → registry → registryctl → core → portal → jobservice →
trivy-adapter → proxy다. 각 단계는 이름 대신 사전에 대조한 정확한 컨테이너 ID에
`docker --host=unix:///var/run/docker.sock start <ID>`를 최대 1회 제출한다.
시작 전 logger/TCP/동일boot·Docker invocation/격리/AC04·컨테이너 메타데이터 및
기동 완료 앱들의 healthy를 재확인한다. 아직 차례가 아닌 앱이 이미 시작됐어도 중단한다.

각 start timeout60초, 이후 health 대기60초(조회2초 간격/개별조회20초),
전체 변경 진행 deadline900초다. 늦게 healthy를 받았어도 해당 deadline 이후면 실패다.
개별 조회가 진행 중이면 deadline을 즉시 강제 취소하는 것은 아니며, 그 조회의 timeout을
따른다. 실패 증적 독립 조회3건은 별도로 최대 각20초가 추가될 수 있다.
컨테이너 기동 자체가 앱의 정상 데이터 기록을 유발할 수 있으므로 데이터 무변경 시험이 아니다.

Docker/VM 재시작, Compose up/down, 컨테이너 재생성, restart policy 변경,
pull, 볼륨 삭제, 방화벽/SELinux 변경, SSH 재설치, 자동 복구 반복은 하지 않는다.
직접 명시하는 start 외 Docker의 기존 restart=always 내부 동작 횟수까지 제어한다고 주장하지 않는다.
이 스크립트는 systemd/cron에 설치하거나 반복 실행하는 기동기가 아니다.

## 실행 인계 조건과 형식

새 코드 exact HEAD 검토와 책임자의 격리 복구 회차 판단 후 전달한다.
현재 문서의 명령은 형식이며 실행 GO나 이미 전달된 bundle을 뜻하지 않는다.

1. 기존 A3 및 이후 SSH 원문/claim 보존 위치와 host 회수본 해시를 확인한다.
   기존 snapshot은 A2 이전 상태이며 현재 상태의 백업이라고 표시하지 않는다.
   해당 snapshot을 복원하면 이후 guest 원문이 사라질 수 있으므로 미회수 자료를 먼저 보존한다.
2. 실행자 한 명, 다른 세션의 VM/Docker/앱 변경 없음, 현재 clone/host 무NIC 및 HGFS 폐쇄를 확인한다.
3. `clone-app-recovery.py`와 승인 `trial.py`를 root 소유/쓰기 제한된 `/root/<bundle>`에
   복사·해시검수한다. Python은 HGFS에서 실행하지 않는다. 모든 HGFS mount를 해제한다.
4. server08@harbor01 콘솔에서 sudo로 실행한다. host-gate 값은 작업자의 확인 표시이며
   guest가 host/snapshot/원문 회수 또는 실행 승인까지 자동 인증한 것은 아니다.

```bash
sudo python3 -I /root/<reviewed-bundle>/clone-app-recovery.py \
  --bundle /root/<reviewed-bundle> \
  --confirm-host-gate a3-evidence-preserved-no-nic-no-hgfs
```

정상 표식: `MANUAL_RECOVERY_HEALTHY_REVIEW_REQUIRED PRIVATE=/root/hbr-app-recovery-...`, rc0.
모든 앱 healthy와 구성 보존의 실행기 판정이다. 로그 실제 저장, 외부 API/패킷,
자동기동 및 AC 인수는 이 출력으로 인정하지 않는다.

## 중단과 복구

preflight 실패는 STOP_BEFORE_CHANGE, claim 이후 실패/불확실성은 STOP_RECOVERY_REQUIRED/rc2다.
start timeout은 Docker 서버 측 작업 취소를 의미하지 않는다. 자동 retry/stop/rollback은 없다.
일부 앱이 기동된 상태일 수 있으므로 이후 앱을 임의로 시작하거나 claim을 지우지 않는다.
실패 후 state/unit/AC04를 각각 독립 수집하고 query 오류도 result.json에 보존한다.
raw stdout/stderr·명령 argv/rc/시각·전후 metadata는 root 전용 새 회차 폴더에 남긴다.
저장 장치 실패나 SIGKILL에는 완결 result를 보장하지 않으며 claim/부분 원문을 보존한다.

원상태로 되돌리는 자동 stop은 앱 데이터 처리 도중의 추가 변경이므로 포함하지 않는다.
부분 복구면 결과 회수 후 새로운 복구 판단을 한다. 고정 A2 snapshot 복원은 별도 범위이며
보존·대상 확인 없이 실행하지 않는다. 이번 복구 결과가 원 A3 실패를 소급 통과시키지 않는다.

## 영구 자동기동 보완안 — 구현·채택 전 후보

이 PR의 일회성 복구를 영구 기동 대책으로 배포하지 않는다. 권장 검토 후보는
**앱9개의 기동/재기동 주체를 한 곳으로 통일**하는 것이다. 현재 syslog 경로와 AC04 guard를
유지하려면 앱의 Docker restart=always와 host 기동기가 동시에 같은 앱을 관리하지 않도록 해야 한다.

- 앱9개의 restart policy를 명시적으로 변경하는 후보는 A2/A3의 정책 보존 조건을 벗어난다.
  새 시험 범위로 검토하며 기존 결과의 보존 기준을 소급 완화하지 않는다.
- systemd 후보라면 각 앱 종료/정상 exit/비정상 exit/health 악화, Docker restart·중단·복구,
  VM boot, 관리자의 의도적 stop을 각각 정의한다. 단순 oneshot start만으로 기존 always의
  장애 후 재기동 기능을 대체했다고 하지 않는다.
- Docker의 기존 firewall guard를 그대로 둔다. logger 대기는 Docker 이후 앱 기동 경로에 둔다.
  logger 실패 시 앱 시작 금지 및 명확한 실패 결과를 남기며 Docker 전체 재시작 반복으로 복구하지 않는다.
- logger healthy/TCP accept와 실제 로그 수신·저장은 구분한다. 승인된 표식 로그의 저장 증적까지
  새 시험에 포함한다. 기존 daemon 실패 복제 + 성공 + logger 미준비 음성 경로를 함께 시험한다.
- Compose depends_on 또는 sleep만 추가하는 방식은 daemon 자체의 restart 경로를 해결하지 않는다.
- logging driver 변경/UDP 전환은 현재 로그 수집·전송 의미를 바꾸므로 이번 최소 후보에 포함하지 않는다.

따라서 순서는 **명시적 현상태 복구 → 단일 기동 주체 후보의 정확한 소스·복구/실패 계약 검토 →
새 회차 자동기동 시험**이다. 이번 변경으로 영구 수정이 완료됐다고 보고하지 않는다.

공식 근거: [Docker restart policy 및 host process manager 충돌](https://docs.docker.com/engine/containers/start-containers-automatically/),
[Compose startup order](https://docs.docker.com/compose/how-tos/startup-order/).

## 검증 경계

tests/clone-trial/test_app_recovery.py는 실제 guest 호출을 하지 않는 MOCK이다.
정상 정확한9-ID/1회, 준비 실패, 메타데이터 drift, logger 소실, health timeout,
start timeout의 기록·재시도 부재, 부분 실패 후 독립수집, claim 배타성,
boot/HGFS/격리/source pin, guard 의존성·nft drift, profile drift 경로를 검증한다.
기존 clone-trial 회귀도 함께 실행한다. 실제 CentOS/앱 복구 및 로그 저장/영구 자동기동은 미실행이다.
