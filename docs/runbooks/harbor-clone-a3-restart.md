# Harbor A3: 현재 IPv4 후보의 Docker restart 1회 관측

CODEX_ASSISTED. baseline #13 / code #17 / evidence #166·#168 후속.
**새 실행 코드의 exact HEAD 독립 리뷰와 실행 인계 판단이 필요하다.**
이 문서 작성·CI·#168 편입은 Docker 재시작 실행 승인이나 Runtime 결과가 아니다.

## 목적과 고정 범위

18:17:27~29 KST `check-current`는 메타데이터 조건 확인에 성공했다. 해당 후보의
Docker daemon 재시작 후 자동기동 여부를 판단할 원본을 수집한다. 주소 후보가 logger 준비
경쟁까지 해소한다고 가정하지 않는다. 현재 healthy IPv4 후보를 재생성하거나 원복하지 않는다.

- 대상은 `D:\FDS-Isolated-Lab\harbor01-20261008\harbor01-test.vmx` 작업 사본만.
  UUID는 #17 clone guard로 확인, root/hostname harbor01/NIC 없음/원 Compose SHA 동일 필수.
- `systemctl restart docker.service` 정확히 1회. VM reboot, app 수동 start,
  Compose up/down, pull, 볼륨 변경, 보안 변경, 자동 복구는 수행하지 않는다.
- 승인 trial.py SHA `0a79b3b70d18211fcacb94903332b81e71168ade18225909ed4d53e26be3d8c4`,
  observer.py SHA `ac9d42efbcd4f18effc2bcd7a819af29d7cc6aaa5cbd13c94fbd05e37f39e1e1` 고정.
  root 내부 새 회차 폴더로 읽은 바이트를 복사한 뒤 로드한다. 기존 승인 파일은 수정하지 않는다.

## 호스트와 전달 선행조건

1. 실행 창과 작업자 한 명을 기록하고, 다른 콘솔에서 Docker/앱을 조작하지 않는다.
2. 고정 스냅샷 `before-address-A2-20261008-1500`의 생성 완료(15:17:11 KST VMX 로그) 및
   실제 스냅샷 파일 존재를 호스트에서 다시 확인한다. 스냅샷 복원은 미시험이며,
   스냅샷 명칭이나 manifest 일치만으로 복원 성공을 주장하지 않는다.
3. 원본 A2/A2R1/현재 확인 결과를 host에 먼저 회수·해시 검수한다. 스냅샷 이후 게스트 파일은
   복구 시 사라질 수 있다. 보존 위치와 host 검사 시각을 인계 기록에 남긴다.
4. 승인 HEAD의 driver + trial.py + observer.py를 root 전용 bundle로 전달·해시 확인한다.
   HGFS 위에서 Python을 직접 실행하지 않는다. guest의 임시 HGFS mount를 모두 해제하고
   host sharedFolder.maxNum=0 / HGFS 비활성 / NIC FALSE를 다시 확인한다.
   자동 mount `/mnt/hgfs`도 남아 있으면 실행기가 거부한다. 다른 파일시스템은 해제하지 않는다.
5. `--confirm-host-gate`는 위 호스트 확인을 수행한 작업자의 확인 표시다. 게스트가
   호스트/스냅샷을 자동 인증했다는 뜻이 아니다. 확인 전 이 인자를 전달하지 않는다.

## 실행 및 증적

승인/전달 후 기존 server08 VM 콘솔에서 sudo 암호를 직접 입력한다.
아래는 절차 형식이며 **현재 실행할 명령을 발급한 것이 아니다**.

```bash
sudo python3 -I /root/<approved-a3-bundle>/clone-daemon-restart.py \
  --bundle /root/<approved-a3-bundle> \
  --confirm-host-gate before-address-A2-20261008-1500
```

- root lock은 실행 중 driver 동시 실행을 막는다. `/root/hbr-a3-docker-restart.claim`은
  새 작업 폴더를 만들어도 두 번째 재시작을 차단한다. claim은 삭제/재사용하지 않는다.
- 먼저 #17 `check-current`를 fresh 실행한다(전체 subprocess 최대180초). 현재 상태가
  봉인 after와 동일해야 하고 버전/보안/volume/xattr/listener를 재검사한다.
  Docker LiveRestoreEnabled=false도 확인한다. true이면 시험 목적을 충족할 수 없어 변경 전 중단하며 설정을 바꾸지 않는다.
- boot ID와 Docker unit ActiveState/SubState/MainPID/InvocationID/시작 monotonic 시간을 기록한다.
- 승인 observer를 독립 프로세스 그룹으로 먼저 시작한다. 15초 안에 첫 표본이
  10개 healthy/동일 ID/IPv4 listener를 보여야 한다. 준비 실패 시 재시작하지 않는다.
- 재시작 직전 clone/mount guard·boot ID·현재 상태·unit을 다시 확인하고 영구 claim을 남긴다.
  T0(epoch+monotonic_ns+boot ID)를 디스크에 기록한 뒤 재시작 명령을 한 번 제출한다.
- 재시작 명령 대기90초. timeout rc124는 systemd job 취소/완료를 뜻하지 않는다.
  rc130/127/기타 실패도 자동 retry/cancel하지 않고 관측을 계속한다.
- observer는 37표본, 표본 사이5초, 개별 Docker/ss 조회 각4초 상한이다.
  정상 응답 시 약3분이며 조회 지연에 따라 길어진다. observer 시작 기준 총500초 상한이다.
  시각은 첫 관측부터의 창이며 T0 이후 정확히180초를 의미하지 않는다.
  deadline 초과 시 **우리 observer 프로세스 그룹만** 종료하고 부분 원본을 보존한다.
- 종료 후 unit/state 원본, 동일 boot ID, 새 Docker InvocationID 및 T0 이후 unit 시작 시각,
  동일 컨테이너 ID·image·mount·logging·restart·ports, 10개 healthy, profile 보안 조건,
  volume inventory, IPv4 listener를 확인한다. 일반 조회 각20초 상한.
  후속 검사는 수집→판정 두 단계다. boot/unit/state, engine/compose/security/Enforcing,
  영향3개 label, volume9개 inventory·xattr 각각, listener/live-restore, 마지막 guard를
  독립 수집한다. 앱 Exited, state 파싱 실패, 특정 volume/label/xattr 조회 실패가 다른 항목을
  건너뛰지 않는다. state가 없어도 재시작 전의 검증된 ID/volume 이름으로 조회를 시도한다.
  command rc가 비정상이면 부분 stdout은 그대로 보존하며 그 항목을 정상 수집으로 취급하지 않는다.
  수집을 마친 뒤 기존 건강·보존·버전·보안 기준으로 판정한다.
- T0(epoch 초 내림)부터 조회 시점까지 동일 boot의 Docker unit journal을 private로 수집한다
  (30초 상한). 기록된 `/proc` boot UUID를 엄격히 검증하고 `_BOOT_ID=<32hex>` 필드로 고정한다.
  일부 journalctl의 `-b <하이픈 UUID>` 인자 해석 문제를 피하며 현재 boot/전체 journal로 자동 대체하지 않는다.
  원문에는 민감정보 가능성이 있으므로 검수 없이 GitHub에 올리지 않는다.
  Compose 렌더링 및 raw stderr도 private 유지한다.

회차 폴더는 `/root/hbr-a3-*`. result.json은 원자 교체·fsync로 명령별 argv/rc/시각,
T0/boot/unit/상태/오류를 기록한다. observation.jsonl은 원본 표본과 footer,
observer stdout/stderr, 명령별 stdout/stderr를 보존한다.
후속 항목은 postcheck_capture(COLLECTED/ERROR), postcheck_validation(PASS/FAIL/NOT_EVALUATED),
postcheck_errors(item/phase/error_code)에 구분해 기록한다. 필수 수집 오류가 하나라도 있으면
postchecks=FAIL이며, 해당 자료가 없는 판정은 NOT_EVALUATED다. 이 표의 PASS는 항목별 검사값이고
AUTOSTART/AC 인수 PASS가 아니다. 저장 장치 자체의 기록 실패·강제 종료까지 수집 완료를 보장하지 않는다.
SIGKILL/전원 종료로 완결 파일이 없을 수 있으므로 claim/부분 원본도 증적이다.

## 판정 및 실패 처리

`OBSERVATION_COMPLETE_REVIEW_REQUIRED`는 필요한 수집·postcheck가 끝났다는 뜻이다.
observer rc2는 일시 query error를 포함한 완결 관측일 수 있어 무조건 실패/성공으로 바꾸지 않는다.
driver는 항상 AUTOSTART=NOT_EVALUATED / SYSLOG_INGESTION=NOT_TESTED / AC_CLOSE=NOT_EVALUATED로 남긴다.
실제 자동기동 판단은 표본·T0·unit/journal·수동 복구 부재 기록을 함께 독립 검토한다.

재시작 전 실패는 `STOP_BEFORE_RESTART`. claim 뒤의 실패/불확실성은 `STOP_RECOVERY_REQUIRED`다.
관측기 실패, postcheck 실패, journal 실패는 나머지 독립 수집을 가능한 범위에서 계속한다.
어느 실패에서도 Docker/앱을 다시 시작하거나 원복하지 않는다. 재시작 후 unhealthy 후보는
#17 profile restore의 조건에 해당하지 않으므로 그 명령을 실행하지 않는다.

실패 시 **회차 원본과 claim을 host로 회수·검수한 뒤** 고정 스냅샷 복구를 별도로 진행한다.
복구 대상 VM/스냅샷을 다시 대조하며 운영 Harbor, 수신 원본 clone, 다른 VM에는 적용하지 않는다.
스냅샷 복구 후 원 주소/상태/격리를 확인하고 이후 시험은 새로 검토한다.

## 검증 범위

STATIC/MOCK: 기존36건 + A3 26건(총62건). HGFS mount·잘못된 unit·첫 표본 드리프트 거부,
현재 identity/mount/health 보존, 전역 claim 중복 거부, timeout/interrupt/명령 실패1회,
observer 조기 종료/timeout/부분 원본 보존, 실패 후 나머지 수집, 자동기동 PASS를 출력하지 않는 분기를 포함한다.
추가 회귀는 실제 postcheck 메서드를 구동해 앱 Exited/비정상 unit/state 실패·파싱 실패/label 부분 출력/
volume1개·xattr1개 실패/복수 오류에서도 모든29개 수집 항목을 시도하고, 자동기동 PASS로
승격하지 않으며 journal 시도까지 이어지는지 확인한다. 실제 systemd/게스트 재시작·복구는 이 모의시험에 포함되지 않는다.

## 2026-10-08 A3 실제 결과와 수집기 보정

[증적 #171](https://github.com/321Team/fds-project-evidence/pull/171)의19:36 회차는 Docker restart rc0이나
앱9개가 IPv4 syslog 접속 거부로 기동하지 못했다. 원본 STOP_RECOVERY_REQUIRED는 유지한다.
원journal 명령도 `failed to add match / invalid argument`로 실패했고, 후속 읽기 전용 조회에서
같은boot·같은시간창을 `_BOOT_ID=<32hex>`로 지정해62행을 확보했다.
이 보정은 journal 수집 오류만 해결하며 logger 준비 순서나 앱 자동기동을 해결하지 않는다.
회귀4건은 실제 회차 UUID/시간창/파일 보존, 잘못된UUID 거부, rc오류/빈journal의 실패 유지,
T0 없는 경우 미조회 경계를 검증한다. 수정 실행기 전체의 새 Runtime 시험은 미실행이다.
기존회차의 claim을 삭제하거나 현재 unhealthy후보를 재시작하지 않는다.
