# Phase 1 자동복구 제어 코어 — 로컬 구현/모의검증

CODEX_ASSISTED · 2026-10-09. 사용자는 Phase 1 자동복구를 인수한 작업이며 이미 복구하기로
결정됐고 별도 Lead 결정이 필요하지 않다고 명시했다. 추가 구현 GO 대기를 제거한다.
코드 독립 리뷰와 실제 적용·시험 결과는 계속 구분한다. Phase 2 입력은 받지 않는다.

## 구현과 사용 범위

`scripts/recovery/harbor_recovery_core.py`는 I/O 없는 제어 모듈이다. 입력 관측과 저장 상태에서
다음 상태 및 최대 한 개의 start 의도를 계산한다. 후속 구현으로 POSIX 영속 저장,
실행 계층 및 logger-only HOLD reconciliation을 추가했다(아래 절 참조).
Docker inspect projection과 제한된 Unix Engine API backend를 추가했다. 후속으로 명시적 정책에
대조하는 [Linux 읽기 호스트 provider](harbor-recovery-host-provider.md)를 구현했다.
승인 정책 로딩·현장 Plan 생성, 설치기, unit, policy 전환과 일반 장애 reconciliation은 **아직 미구현**이다.
이 모듈을 서버에 복사하거나 systemd에 등록하여 자동복구가 동작한다고 해석하지 않는다.
일회 복구 스크립트와 기존 A3/복구 claim은 수정하지 않는다.

아래 #30~#32 구현 기록의 provider 미구현 표기는 당시 단계다. 최신 후속은 위 링크를 따른다.
provider 자체는 새로 구현했지만 실제 호스트 실행/설치 진입점/승인 입력 생성을 완료한 것은 아니다.

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
- 한 번도 healthy를 관측하지 않은 앱의 첫 start는 exit 후 재시도 예산에 넣지 않는다.
  첫 시도 실패/불확실/health timeout은 즉시 HOLD이므로 첫 시도를 무한 반복하지 않는다.
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
   포함한다. 현재 projection은 아래 Docker adapter에 구현됐다. 실제 호스트 provider와
   승인된 현장 Plan 생성은 남아 있으며 임의 합성 지문으로 실제 실행하지 않는다.
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

코어 초기 합성 입력 36개 시험: 순서/ID·중복 방지, 기존 healthy 보존, logger 준비·소실,
guard/stale/구성/policy drift, 실패·unknown·뒤늦은 성공·잘못된 ACK,
health/전체 deadline, 정상 exit 재기동·backoff/횟수/기간, HOLD·boot/daemon 세대,
Plan drift, 실행 직전 상태 변화, 앱별 예산과 원본 입력 비변경을 포함한다.
실제 VM·Docker·네트워크 호출은 없다. MOCK의 건강상태는 실제 실행 증적이 아니다.

다음 구현은 위 계약을 지키는 현장 보안·구성 provider, 정책 전환/부분 원복·unit·운영 명령,
일반 장애 reconciliation 및 대응 실패 주입 시험이다. 아직 자동복구 전체 구현 완료 또는
설치 가능한 패키지가 아니다. 구현 GO를 다시 받기 위한 문서 단계는 추가하지 않는다.

## #30 리뷰 후속 — 영속 상태·실행 계층

`harbor_recovery_store.py`는 POSIX 전용이다. 미리 준비된 절대 경로의 private 디렉터리를
dirfd/O_NOFOLLOW로 열고 부모 경로 소유자·쓰기 권한, 파일 소유자·0600 수준 권한·단일
hardlink·일반 파일·크기를 검사한다. 초기화를 명시적으로 분리하고, 기존 claim/audit/부분
파일이 있으면 새 상태를 만들지 않는다. state 손상·부재는 자동 초기화로 복구하지 않는다.

실행 순서:

1. nonblocking flock 획득 후 state를 읽는다. 다른 작업이 lock을 잡고 있으면 충돌로 반환하며
   기다렸다가 몰래 재실행하지 않는다. production uid 기본값은 root이며 테스트만 자기 uid를 쓴다.
2. strict version/schema/type·중복 JSON key·finite 시간·token·세대·retry 이력을 검사한다.
3. 새 intent를 임시 private 파일에 쓰고 fsync, 원자 교체, directory fsync 후에만 진행한다.
4. fresh 관측으로 authorize 후 상태 저장, token별 O_EXCL claim 생성/fsync 뒤 한 번 제출한다.
5. backend 결과를 ACK하고 다시 저장한다. 실패·unknown·응답 유실·ACK 저장 실패는 intent/claim을
   남긴다. 새 executor의 open은 미완료 intent/health wait를 HOLD로 바꾸고 재제출하지 않는다.

`harbor_recovery_executor.py`는 위 순서를 구현하지만 backend는 주입형 인터페이스다.
executor 자체에는 기본 Docker client나 CLI가 없다. `observe()`는 bounded fresh 관측을, `start(action, timeout)`은
정확한 ID에 대한 단일 bounded 실행과 ok/failed/unknown을 제공해야 한다. 현장 backend를
구현·검증하기 전에는 실행기로 배포하지 않는다. 합성 backend를 실제 guard 대용으로 쓰지 않는다.

lock은 실행/ACK 저장까지 유지한다. 이 동안 operator HOLD도 busy를 받을 수 있으며 이미 제출된
start를 취소하지 않는다. 해당 경합/응답의 운영 CLI 처리는 후속 범위다. 일반 오류는 unknown,
프로세스 종료는 intent/claim 보존으로 처리한다. 저장 실패 시 다음 Docker 명령을 진행하지 않는다.
한 host의 승인된 상태 디렉터리에 대한 중복 제출 방지이며 분산 exactly-once 보장이 아니다.

### logger-only HOLD 해제

#30 리뷰의 logger 일시 장애 경로를 우선 구현했다. 자동으로 모든 HOLD를 해제하는 기능이 아니다.
명시적 reconcile 요청에서 다음을 **모두** 확인한다.

- 이유가 LOGGER_TIMEOUT이며 미완료 intent/health wait/복구 episode가 없음.
- Plan과 boot·Docker 세대 동일, 관측 fresh, 모든 구성/보안 gate 정상.
- logger 포함 10개가 running/healthy, logger TCP 정상.

통과하면 이전 HOLD를 private audit request로 먼저 보존하고 RUN으로 변경한다. 앱 start/stop은
발생하지 않고 retry 이력·token은 그대로 유지된다. audit는 요청 기록이며 뒤따른 state 저장의
성공 증명은 아니다. 구성/세대 변화, 앱 장애, operator HOLD, budget 초과 등 다른 HOLD는 거부한다.
**부팅 시 logger timeout으로 앱이 아직 시작되지 않은 HOLD는 일반 reconciliation(잔여) 대상**이다.
logger-only 해제를 그 경로에 재사용하지 않는다(#31 독립 리뷰 비차단 의견 1 반영).

### 후속 시험과 검증 범위

전체 68개 중 Windows에서 55개 통과, POSIX 전용 13개는 SKIP이다. POSIX 시험은 Ubuntu CI에서
권한/lock 경쟁/symlink·hardlink·FIFO 거부/fsync·replace 실패/claim 중복과 실제 자식 프로세스의
`os._exit` 후 재기동을 검증한다. 실행 backend는 모든 환경에서 합성이며 실제 Docker는 호출하지
않는다. Linux CI 결과는 PR check에서 확인하고 Windows SKIP을 PASS로 집계하지 않는다.

## #31 후속 — Docker projection·Unix API adapter

`harbor_recovery_docker.py`는 I/O 모듈이다. 기본 실행 진입점·서비스 설치·호스트 검증 provider는
제공하지 않으므로 이 파일만 배포해 실행하지 않는다. 기존 일회 복구 파일/claim에는 연결하지 않는다.

- inspect의 Config 전체(환경값·healthcheck·label 포함), HostConfig 전체에서 RestartPolicy만
  제외한 값, 이미지 ID, 컨테이너 ID/이름, 정렬한 실제 Mounts, SELinux process/mount label을
  version 1 지문으로 묶는다. 환경값과 health 로그 원문은 관측 결과나 예외에 내보내지 않는다.
  runtime State/NetworkSettings는 지문에서 제외하며 호스트·네트워크 검증은 provider 책임이다.
- RestartPolicy는 별도로 앱 `no`, logger `always`, MaximumRetryCount 정수 0을 검증한다.
  syslog driver·loopback 주소·tag 및 기타 옵션은 주소 검사와 전체 메타데이터 지문으로 결속한다.
  ID/서비스/project 대조, 전체 project inventory의 누락·추가·중복·교체를 검사한다.
- 관측 전후 host provider와 inventory를 다시 확인한다. host/config digest와 boot 및 Docker
  InvocationID가 일치해야 한다. 전체 수집은 하나의 monotonic deadline 안에서 끝나야 하며,
  관측 시각은 완료 시각으로 갱신하지 않고 가장 오래된 입력 시각을 사용한다.
- TCP는 `127.0.0.1:1514`에 유한 connect만 수행한다. 로그를 보내지 않으며 수집/저장 성공 증적이 아니다.
- start 직전에 전체 관측·정확한 ID·logger·선행 앱·세대를 재확인한다. start만 단일 POST하며
  logger start, restart/stop/update/create/pull/delete 경로는 없다. executor의 영속 intent/claim
  이후에만 호출한다. adapter 자체는 독립적인 중복 제출 방지 서비스가 아니다.
- UnixEngine은 Linux AF_UNIX와 기본 root peer 확인을 사용한다. GET inventory/inspect와
  POST exact-ID/start만 허용하며 redirect/retry·shell·Docker context 환경변수는 사용하지 않는다.
  응답/전송량 상한과 socket read마다 남은 전체 기한을 적용한다. HTTP 204만 시작 ACK이며
  304(already running), 오류 응답, 시간 초과, 응답 유실은 unknown이다. 시작 기한이 지난 응답도
  성공으로 올리지 않는다. 클라이언트 timeout을 daemon 동작 취소로 해석하지 않는다.

`Plan.execution_binding`은 host/config digest·project·adapter version·Engine API version/
socket path/peer UID 계약을 묶는다. 빈 값은 순수 코어 MOCK만 허용하고 DockerBackend는 거부한다.
계약이 바뀌면 기존 RUN의 Plan digest가 달라져 HOLD한다. 이전 Plan hash의 무조건 마이그레이션이나
재초기화는 없다. 아직 설치된 controller가 없으므로 기존 A3/수동 복구 상태에는 영향이 없다.

### 연결 전에 남은 검증

host provider는 매 호출에서 root·대상 UUID/격리·SELinux·AC04 활성/의존성/규칙·유효 Compose·
Engine/storage profile·승인 파일 및 socket 경로 소유/권한을 실제 읽고 검증해야 한다.
HostSnapshot은 그 검증 결과를 전달하는 내부 계약이며 상수/사용자 확인 문자열은 검증 대용이 아니다.
현재 provider는 시험용 합성 구현만 존재한다. 승인된 현장 입력에서 지문을 생성하는 설치 경로,
API 버전/스키마와 5초 수집 예산의 현장 적합성, Docker 동작은 아직 검증하지 않았다.

#31 리뷰 의견 2·3은 설치/원복 구현에 다음과 같이 유지한다.

- `state-*.pending`은 commit되지 않은 증거로 보존하며 자동 승격·삭제·새 상태 초기화 근거로
  쓰지 않는다. 설치/원복은 authoritative state와 claim/audit를 함께 판독하고 부분 파일을 기록한다.
- 운영 경로는 root 전용 0700을 기준으로 준비하고 상위 경로·파일 ACL/default ACL 및 xattr/SELinux
  맥락을 현장 검증한다. 현재 Store가 ACL/xattr까지 검사한다고 주장하지 않는다.

시험은 기존 상태/저장소 시험과 함께 `tests/recovery-core`에서 실행한다. 새 projection/adapter는
합성 Engine/host로 검증하고, Linux의 로컬 가짜 Unix HTTP 서버로 framing·peer UID·전체 기한·
응답 유실/오류를 검증한다. Docker 소켓·VM 접속은 없다. STATIC/MOCK/CI와 격리 RUNTIME,
AUTOSTART/SYSLOG_INGESTION 및 Phase 1 AC 인수는 별도 단계다.

API 참조: [Engine API](https://docs.docker.com/reference/api/engine/version/v1.53/),
[container inspect](https://docs.docker.com/reference/cli/docker/container/inspect/),
[container start](https://docs.docker.com/reference/cli/docker/container/start/).
시험의 API 1.53은 합성 입력이며 현장 협상 결과나 운영 채택 증적이 아니다.
