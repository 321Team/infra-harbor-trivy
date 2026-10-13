# 받은 stop ACK의 영속 보존과 명시적 종료 관측 정리

Phase 1 H6 중 **실제 HTTP204를 받았으나 이후 readback/receipt 저장이 실패한 경우**만 다룬다. [기존 실패 의미](harbor-recovery-review-followups.md), [bootstrap](harbor-recovery-bootstrap.md), [operator control](harbor-recovery-operator-control.md)의 신뢰·설치·세대·예산 조건을 유지한다. 이 문서는 Runtime 허용이나 H6 전체 완료가 아니다.

## 기록과 경계

`graceful-stop`은 기존 exact-ID `/stop?t=-1` 요청이 HTTP204로 반환되면 `stop-ack-<token20>.json`을 새 파일로 쓰고 fsync한 뒤 상태를 다시 읽는다. 전송 전 설정 신호의 적합성(proxy·portal SIGQUIT, 나머지 SIGTERM)을 확인하며 신호를 덮어쓰지 않는다. ACK에는 원 claim과 `HTTP_204` 사실만 포함한다. [Docker stop API](https://docs.docker.com/reference/api/engine/version/v1.53/)의 304/오류/transport timeout은 ACK로 기록하지 않는다. [timeout=-1](https://github.com/docker/cli/blob/master/docs/reference/commandline/container_stop.md)은 daemon의 무기한 대기이며 클라이언트의 유한 예산과 다르다. 클라이언트 timeout 후 나중에 exited가 되어도 ACK를 소급 생성하지 않는다.

- `stop-claim`: 전송 전의 시도 결속. ACK와 동일하지 않다.
- `stop-ack`: 이 프로세스가 실제 받은 HTTP204를 영속 기록한 사실. 쓰기 실패·ACK 전 crash에는 존재하지 않을 수 있다.
- `stop-done`: 같은 대상의 fresh exited readback. ACK 파일이 있다고 자동 생성하지 않는다.
- 과거 completed claim/done은 그대로 유효하다. 과거 pending claim에 ACK를 추가하는 migration·수동 편집·삭제는 없다.

## 실행 전 준비와 위치

기존 정확 격리 복제본의 콘솔에서 검토된 root/Python3.10+ `-I -S -B` 경로를 사용한다. 변경된 source4개 및 bootstrap를 포함하는 **새 독립 리뷰와 exact bundle/source/외부 pin**이 먼저다. 이전 sealed package/승인 bundle에 새 코드를 섞거나 hash를 현재값으로 자동 치환하지 않는다. 신규 bundle 공급·실제 회차 허용은 코드 승인과 별개다.

manager는 중지된 상태이며 ManagerLease·host guard·installation gate가 모두 통과해야 한다. 다른 root 작성자/정책·Docker·VM 작업을 배제한다. 실제 복구 인수자와 보존 위치를 고정하고 기존 state·claim·ACK·journal·원 명령 결과를 보존한다. claim/ACK의 정확 bytes SHA256과 최신 state pin을 읽어 검토하며, 아래 변수는 현장 실측/검토로 채우는 자리다. 샘플·합성 입력을 실증으로 사용하지 않는다.

다음 조건을 코드가 모두 확인한다.

1. state는 HOLD이며 `STOP_INTENT` 또는 `STOP_INTERRUPTED_OR_UNKNOWN`. pending start/health wait/episode 없음. next_token은 모든 start/stop claim보다 크다.
2. 미완료 stop claim은 오직 하나이며 최신 tail/token=next_token-1. 현재 state/plan/boot/daemon/정확 대상 ID에 결속한 reverse-stop 연속 prefix이다. prefix의 앞선 claim은 done과 ACK가 모두 있다.
3. tail claim/실제 ACK의 원본 SHA가 검토값과 일치한다. orphan·mismatch·부분 저장·symlink·legacy ACK 부재는 중단한다.
4. 같은 daemon/boot·컨테이너 ID/fingerprint/restart policy·fresh guard. prefix 전체 exited, 나머지 앱 running/healthy, logger running/healthy/TCP 정상. manager/설치 gate는 유지된다.

## 명시적 관측 정리

```bash
sudo /검토된/Python3.10이상 -I -S -B /검토된/harbor_recovery_bootstrap.py settle-stop-readback \
  --bundle /검토된/실제.bundle.json --sha256 "$BUNDLE_SHA256" \
  --context "$BUNDLE_CONTEXT" --timeout "$REVIEWED_READBACK_SECONDS" \
  --state-sha256 "$STATE_SHA256" --claim-sha256 "$CLAIM_SHA256" \
  --ack-sha256 "$ACK_SHA256" --execute
printf 'READBACK_RC=%s\n' "$?"
```

이 동작은 기존 lease/controller 잠금에서 원 state audit → fresh 재관측 → 빠진 done만 새 파일 기록 → state의 HOLD 유지 순이다. **Engine POST0**, 새로운 stop/start/RUN/rollback/namespace 생성 없음. 성공 rc0의 stage는 `ACKED_STOP_READBACK_SETTLED_HOLD`, `engine_post=NONE`, `prior_ack=RECORDED_HTTP_204`다. 다음 앱을 종료하거나 앱을 기동하지 않는다. retry/token/claim/ACK와 원 journal은 보존한다.

## 실패·복귀

불일치·세대 변경·logger/정책 drift·예산 소진·저장 실패면 STOP/rc2로 끝나며 후속 요청을 보내지 않는다. audit/부분 새 파일/원 claim·ACK를 보존한다. 원인을 해소하지 않고 재시도·Store 초기화·relabel·파일 덮어쓰기를 하지 않는다.

done 저장 뒤 state 저장만 실패할 수 있다. 이 경우 원 state는 HOLD이고 done은 남으므로 같은 정리를 성공으로 재실행하지 않는다. 두 기록을 분리해 보고하고 정확한 현재 상태로 후속 복구를 준비한다. 이미 기록된 done을 없애 재실행하지 않는다.

부분 stop 뒤 나머지 앱 stop, 같은 대상 재기동, ACK 없는 미확정 전송, legacy pending, 다른 daemon/boot, 일부 policy 복귀는 이 기능이 해결하지 않는다. 원본·실제 데이터 상태·콘솔 인수·별도 복구 안과 필요한 코드 검토가 여전히 필요하다. 전체 healthy로 복구한 뒤에도 기존 `reconcile`의 exact state/설치/세대/ledger 조건과 실제 허용을 별도로 적용한다.

## 검증의 의미

회귀 시험은 ACK 이전/이후 저장 실패·잘못된 pin/세대/대상/prefix·orphan/legacy/partial file·재실행·audit 이후 drift·CLI 잘못된 조합을 검증한다. Linux 파일 시험은 임시 경로에서 수행하며 실제 enforcing SELinux·Docker·VM Runtime을 대신하지 않는다. 실제 StopSignal/DB 연결/예산·미확정 요청 해소가 남아 있어 H6 전체는 NOT_READY를 유지한다.
