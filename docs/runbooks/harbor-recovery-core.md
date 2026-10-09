# Phase 1 자동복구 제어 코어 — 로컬 구현/모의검증

CODEX_ASSISTED · 2026-10-09. 사용자는 Phase 1 자동복구를 인수한 작업이며 이미 복구하기로
결정됐고 별도 Lead 결정이 필요하지 않다고 명시했다. 추가 구현 GO 대기를 제거한다.
코드 독립 리뷰와 실제 적용·시험 결과는 계속 구분한다. Phase 2 입력은 받지 않는다.

## 구현과 사용 범위

`scripts/recovery/harbor_recovery_core.py`는 I/O 없는 제어 모듈이다. 입력 관측과 저장 상태에서
다음 상태 및 최대 한 개의 start 의도를 계산한다. 실제 Docker 실행, 설치기, unit,
policy 전환, 상태 파일 저장, HOLD 해제/reconciliation은 **아직 미구현**이다.
이 모듈을 서버에 복사하거나 systemd에 등록하여 자동복구가 동작한다고 해석하지 않는다.
일회 복구 스크립트와 기존 A3/복구 claim은 수정하지 않는다.

Plan은 고정 서비스/ID/불변 메타데이터 지문, 앱별 health 시간, 유한 재시도 예산을 받는다.
State는 RUN/HOLD, boot·Docker 세대, 실행 intent, health 대기, retry 이력 및 Plan 해시를
보존한다. 변경된 Plan이 이전 RUN 상태를 재사용하면 HOLD한다. 인수 전 현장 시간 예산을
이번 합성시험 기본값으로 확정하지 않는다.

- 초기 상태는 HOLD이며 최초 명시적 arm만 가능하다. 실패/운영자 HOLD를 arm 호출로
  해제하거나 불확실한 intent·예산을 삭제하지 않는다.
- logger healthy/TCP와 전체 컨테이너 구성·policy gate 후 순차적으로 정확한 ID를 선택한다.
  이미 healthy인 앱은 재시작하지 않으며 logger를 start/stop하지 않는다.
- start 의도는 한 번만 반환한다. 결과가 실패/불확실/기한 초과면 원 intent를 남기고 HOLD한다.
  fresh dispatch 재검사에서 logger·세대·선행 앱·guard가 바뀌면 실행을 허용하지 않는다.
- health 대기는 앱별·전체 회차 deadline으로 제한한다. healthy가 늦게 관측돼도 통과시키지 않는다.
- healthy였던 앱의 exit 후에는 backoff/횟수/기간 제한을 적용한다. 정상·비정상 exit를
  구분하지 않는 후보 계약이며, 실제 외부 stop 의도 판별은 실행 계층의 과제다.
- 실행 중 unhealthy는 HOLD하되 kill하지 않는다. logger 소실은 새 시작을 차단하고 유한 대기한다.
- 새 daemon/boot에서도 미완료 작업을 재사용하지 않는다. 깨끗하게 완료된 RUN만 새 boot에서
  자동기동할 수 있다. 미결 예산/회차가 있으면 boot 변경 시 HOLD한다.
- HOLD의 보존과 crash recovery는 상태 전이를 검증한 것이며 실제 디스크 영속성을 증명하지 않는다.

## 실행 어댑터가 지켜야 할 계약

1. root 소유·쓰기 제한·symlink 거부·스키마/버전/Plan hash 검증을 거친 상태를 복원한다.
   파일 부재/손상 때 RUN을 새로 만들지 않는다. 최초 생성과 승인된 명시적 reconciliation을 구분한다.
2. 배타 lock으로 정책 변경·복구·operator stop을 직렬화한다. `step`의 새 intent 상태를
   원자 저장/fsync하고, 저장 실패면 Docker 명령을 제출하지 않는다.
3. root/대상 identity/격리·SELinux/AC04 의존성·규칙/유효 Compose·실제 ID metadata를
   읽어 `guards_ok`를 만든다. CLI의 true나 사용자 확인 문자열을 검증 완료값으로 대체하지 않는다.
   metadata fingerprint에는 이미지/마운트/보안·logging driver/tag/options/healthcheck 설정을
   포함한다. 아직 codec/projection 구현이 없으므로 임의 합성 지문으로 실제 실행하지 않는다.
4. 관측은 일관된 세대에서 수집하고 완료 시각·신선도를 검증한다. logger 준비만 참인
   과거 관측을 재사용하지 않는다. `authorize`로 실행 직전 재검사하며 실패 상태도 저장한다.
5. lock 하에서 정확한 saved token을 **최대 한 번 제출**한다. `authorize` 자체는 token을
   소모하는 실행기나 분산 exactly-once 보장이 아니다. 실행 직전/직후 죽으면 의도가 남아야 한다.
6. 결과를 `acknowledge`에 넘기고 새 상태를 저장한다. timeout/통신 오류는 unknown이며
   Docker 서버 작업 취소로 가정하지 않는다. controller 재시작 때 `resume`을 먼저 호출한다.
7. `hold`는 추가 start를 막는 동작이다. 명시적 서비스 stop은 별도 제어 경로에서 HOLD를 먼저
   저장하고 역순 graceful 종료한다. 자동 SIGKILL·삭제나 `docker stop` timeout의 강제 종료를
   이 코어가 막았다고 주장하지 않는다. 그 정책은 어댑터 구현/시험에서 확인해야 한다.
8. 운영자의 외부 직접 stop과 프로세스 exit를 구별할 수 없는 상태, Plan 변경, 손상 상태,
   미완료 intent는 자동 재시도로 풀지 않는다. 증적 조회/명시적 reconciliation을 구현한다.

## 검증과 다음 코드 범위

저장소 루트에서 Python 3.10 이상으로 실행한다.

```bash
python3 -B -m unittest discover -s tests/recovery-core -v
```

합성 입력 36개 시험: 순서/ID·중복 방지, 기존 healthy 보존, logger 준비·소실,
guard/stale/구성/policy drift, 실패·unknown·뒤늦은 성공·잘못된 ACK,
health/전체 deadline, 정상 exit 재기동·backoff/횟수/기간, HOLD·boot/daemon 세대,
Plan drift, 실행 직전 상태 변화, 앱별 예산과 원본 입력 비변경을 포함한다.
실제 VM·Docker·네트워크 호출은 없다. MOCK의 건강상태는 실제 실행 증적이 아니다.

다음 구현은 위 계약을 지키는 영속 상태 저장/lock·현장 관측/실행 어댑터,
정책 전환/부분 원복·unit·운영 명령, 대응 실패 주입 시험이다. 이 코어 PR은 자동복구 전체
구현 완료 또는 설치 가능한 패키지가 아니다. 구현 GO를 다시 받기 위한 문서 단계는 추가하지 않는다.
