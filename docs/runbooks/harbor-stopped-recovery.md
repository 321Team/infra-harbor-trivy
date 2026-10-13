# 완료된 H6 종료 이후의 명시적 앱 복구

CODEX_ASSISTED. 이 경로는 `graceful-stop`이 앱 9개의 HTTP204와 exited readback을
모두 기록하고 `HOLD/APPS_STOPPED_LOGGER_PRESERVED`로 끝난 **같은 boot/daemon**에만 적용한다.
부분 종료·ACK 없는 timeout·재부팅 후 복구는 대상이 아니다. 기존 H6/인수조건은 변경하지 않는다.

## 필요한 이유와 경계

기존 `reconcile`은 10개 healthy 상태를 확인한 뒤 HOLD를 해제하며 정지한 앱을 기동하지 않는다.
`arm`은 최초 상태에만 적용되고, HOLD에서 manager를 다시 켜거나 VM을 재부팅해도 HOLD가 유지된다.
따라서 복구 경로 없이 H6 정지를 먼저 수행하지 않는다.

별도 operator helper `scripts/preparation/harbor_stopped_recovery.py`는 설치된 Plan·backend·
host/source 검사·배타 lease를 사용한다. resident 코드/번들/서비스/Store 상태는 바꾸지 않는다.
정확 ID의 기동만 수행하며 recreate, 삭제, 정책 전환, stop/kill, unit 기동, reconcile은 없다.
이 helper는 정상 manager의 자동 기동 Executor와 구분되는, 별도 검토·허용된 수동 복구 경로다.

## 실행 위치와 공급

- 대상: 승인된 Harbor 운영 호스트의 root 서비스 문맥. Python `-I -S -B`, 최적화 없음.
- 사전 신뢰 대상: interpreter/stdlib, installed bootstrap, 별도 helper와 entry adapter의 검토된 바이트.
- `harbor_stopped_recovery_entry.operate()`는 이미 신뢰된 bootstrap 객체를 받는 프로그램 호출 경로다.
  독립 CLI·설치기나 자기 인증 기능이 아니다. 실행 wrapper와 정확 입력은 해당 현장 회차에서 준비한다.
- adapter는 외부 helper hash/metadata → installed bootstrap의 bundle/source11개 검사와 compile →
  `VerifiedImporter` → bundle 재검사/writer 검사 → 설치된 구성 조립 → 검증된 helper bytes 실행 순서다.
  현재 경로에서 임의로 찾은 `.py`를 먼저 import하지 않는다. wrapper 자체의 검토를 helper hash로 대체하지 않는다.
- 기존 Store와 같은 부모 아래 고정 형제 `<store.path>.stopped-recovery`를 사전에 준비한다.
  owner root:root/0700·directory/file/writer context는 설치된 bundle과 동일하다. 파일은0600,
  ACL/추가 xattr/심볼릭 링크를 거부한다. 자동 mkdir/chmod/chcon/삭제는 하지 않는다.
  이 디렉터리의 실제 생성 label과 보존 경로도 쓰기 전 확인한다.

호출 계약(입력 목록이며 실제 요청 예제가 아님):

| 입력 | 결속 근거 |
|---|---|
| helper_path/helper_spec | 별도 검토한 helper 바이트의 외부 SHA256·mode·gid·SELinux |
| bundle_path/bundle_sha256/bundle_context | 현재 설치·검토된 bundle, 자동 새 hash 채택 금지 |
| state_pin | 실제 H6 완료 state의 canonical SHA256 |
| stop_pin | 아래27개 실제 raw record SHA256의 정렬된 집합 digest |
| operation/execute | inspect는 execute=False/stop_pin 없음, recover는 execute=True/stop_pin 필수 |
| deadline | 승인한 실행 예산을 실제 시작 시각에 결속한 monotonic deadline |

`inspect`도 같은 manager lease와 controller lock을 취득한다. 상태/receipt/Engine POST는 쓰지 않지만
잠금 I/O가 있으므로 임의의 일반 읽기 경로로 표시하지 않는다. manager는 disabled/inactive/dead여야 한다.

## 단계별 실행과 성공 판정

1. 현재 비중첩과 실제 요청/DB 연결 유휴를 확인한다. manager가 clean RUN이고 10개 healthy일 때
   기존 허용된 경로로 manager를 disable/정상 stop한다. 앱은 이 조치로 정지하지 않는다.
2. 별도 확정된 H6 종료 예산으로 기존 `graceful-stop`을 실행한다. 역순9개 정상 신호와
   각 claim/실제204 ACK/exited done, logger 유지, 완료HOLD를 확인한다.
3. helper `inspect`로 설치 gate·현재 generation·정지9/loggerhealthy와 최근 연속9토큰의
   claim/ACK/done **27개**를 확인한다. 해당 실제 state/record hash를 회차 입력에 결속한다.
   합성 pin·이전 회차 pin·예전 PR44 request를 재사용하지 않는다.
4. 명시적 `recover`는 같은 lease/lock 아래 동일 입력을 재검사한다. 고정 형제 디렉터리에
   `<state_pin>-attempt.json`을 O_EXCL+fsync로 먼저 생성한다. 다른 nonce/출력 폴더로 우회할 수 없다.
5. postgresql→redis→registry→registryctl→core→portal→jobservice→trivy-adapter→proxy 순으로
   각 intent → 최신 host/설정/manager/세대/상태 검사 → 정확 ID start POST 1회 → 실제204 ACK →
   healthy 관측을 보존한다. 이미 기동한 prefix는 healthy, 아직 기동하지 않은 suffix는 exited여야 한다.
   logger는 계속 running/healthy이며 TCP 관측도 통과해야 한다.
6. 9개 모두 healthy이고 원 HOLD state hash가 같으면 complete receipt를 남긴다.
   정상 반환은 `APPS_RECOVERED_HOLD_PRESERVED`, 수동 receipt29개, 원 Store/stop27개 불변이다.
   검사 기록은 실제 운영 회차에서 별도 회수·해시/readback한다.
7. **회차가 정상 완료된 경우만**, 기존 명시적 `reconcile`로 동일 HOLD hash/10healthy를 확인하고
   RUN으로 전환한 뒤 manager를 enable/start한다. unit/PID/세대·10healthy·정책9no/logalways·
   추가 기동0을 독립 조회한다. 복구 helper 자체는 이 후속을 자동 수행하지 않는다.

복구 기동 상한/앱 건강 대기/전체 복구 상한/관측 유효기간/관측 간격은 **설치된 Plan**만 사용한다.
호출자의 deadline은 episode 상한을 줄일 수만 있다. 수동 helper에는 실패 재시도가 없다.
H6 stop 예산과 전체 작업창은 별도 실제값이다. 기존 주소 변경 예산을 종료 예산으로 전용하지 않는다.

## 실패·재실행·원복

- 기록 실패·상태/소스/정책 변화·세대 변화·시간초과·healthy 실패는 즉시 다음 변경을 중단한다.
  시작된 일부 앱, 원 HOLD, 기존 stop 원본, 새 attempt/intent/ACK/healthy 파일을 보존한다.
- 304/오류/응답 불명확은 성공 ACK가 아니다. 나중에 healthy여도 ACK를 소급 생성하지 않는다.
  클라이언트 timeout은 daemon 동작 취소가 아니다. 재시도·자동 stop/kill/recreate/rollback은 없다.
- 새 프로세스도 동일 state pin의 attempt가 있으면 재기동하지 않는다. 파일/형제 폴더를 지우거나
  이름을 바꾸어 우회하지 않는다. 부분 파일도 보존한다.
- complete 저장 실패나 예산 초과 후에는 전체 healthy라도 **이 helper의 성공으로 간주하지 않는다**.
  원본과 실제 상태를 대조하고 별도 명시적 처리안을 마련한다. 기존 `reconcile`은 이 별도 디렉터리를
  검사하지 않으므로 외부 실행 wrapper는 실패 이후 reconcile/manager 시작을 자동 연결하면 안 된다.
- 부분 H6는 이 helper 대상이 아니다. 실제 ACK가 있는 미완료 readback은
  [기존 readback 정산 경로](harbor-recovery-stop-readback.md)의 범위만 적용한다.
  ACK 없는 timeout·새 세대·부분 복구는 별도 현장 복구 판단이 필요하다.
- Docker daemon/VM 재시작은 별도 작업이다. H6 실패를 해소하려는 재시작/스냅샷 복원으로 대체하지 않는다.

## 검증 범위

MOCK은 실제 operator stop이 만든 모의27개 기록을 사용하여 복구9개와 별도 reconcile을 연결한다.
누락 ACK, 부분 stop, pin/세대/설정/정책 변화, lease 경합, 기록 실패, 늦은 응답, 건강 실패,
재실행을 주입한다. Linux 파일 시험은 실제 FD/O_EXCL/fsync와 **모의 SELinux 속성**을 사용한다.
별도 entry 시험은 실제 verified importer와 모의 catalog/reader를 사용한다.
실제 Docker·SELinux service·H6·재부팅·최종 인수 검증은 별도이며 이 코드/CI로 완료 처리하지 않는다.
