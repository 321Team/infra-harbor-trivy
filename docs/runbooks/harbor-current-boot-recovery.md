# 고정된 10/11 부팅의 수동 앱 복구

CODEX_ASSISTED. baseline #13의 Phase 1 인수 전 잔여 복구 코드다. 이전 완료 원본과 현재 부팅을 연결하며, 코드 리뷰·병합·실제 적용은 각각 별도다. 이 문서와 코드 존재만으로 실행 허용이나 AC 통과를 선언하지 않는다.

## 확인한 현황과 새 회차의 근거

2026-10-11 22:10~22:32 KST, SERVER01의 exact 격리 복제본
`D:\FDS-Isolated-Lab\harbor01-20261008\harbor01-test.vmx`
(`harbor01-isolated-firstboot-20261008`)을 콘솔 읽기로 확인했다.
UUID `389e4d56-24f0-e2ef-b68f-137a5047788a`, boot
`4b622c3c-4dec-4493-9ff2-8d5de74325d8`, Docker InvocationID
`6fd1b238bedf4dceb5ee3b991e58a89a`다. manager 서비스는 not-found이고
앱9개 exited/unhealthy, logger running/healthy다. 앱9개의 Exit128/State.Error는
기존 syslog `127.0.0.1:1514` connection refused와 같다. 이는 현재 listener의
TCP accept나 실제 로그 저장을 입증하지 않는다.

현재10개 ID/image/project/service/restart/mounts/ports/logging은 완료 원본과
일치한다. profile·볼륨 inventory9개와 AC04 형태도 일치했다. packet test와
SSH 잔여 전체 부재는 확인하지 않았다. U03 관리 접근 NOT_VERIFIED도 유지한다.
근거: [baseline13 직접 읽기 기록](https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-6109579787).

10/9의 완료 result와 사용된 앱 claim은 guest와 host SHA가 일치한다.
기존 `clone-app-recovery.py`를 이번 boot에서 다시 실행하거나 기존 claim을
삭제/변경하지 않는다. 새 코드는 **이전 회차가 정상 완료됐다는 고정 원본**, 그
회차의 claim/work/source 연결, 현재 고정 boot와 daemon, 보존된 전체 구성을
모두 요구한다. 새 파일명만 바꾼 재실행 경로가 아니다.

## 고정 입력과 의존 소스

- 이전 완료 `/root/hbr-app-recovery-ik0dm4a1/result.json`:
  `793ce1ff0e5cfadbdc66450da28d2c66d4365a8cfe0c5df0f8ee508163b06677`.
- 기존 사용 claim `/root/hbr-a3-app-recovery.claim`:
  `b7e6225dcdde9f16bf9624d9e08b1f740a19469eb5c2068ff9597334f4a52e72`.
- 기존 승인 `clone-app-recovery.py` Git bytes:
  `2178a40b948ccc87ee00b3aad29f0b6c4b7054ac4485f0cd588d75d46b46cb0c`.
- 기존 승인 `trial.py`:
  `0a79b3b70d18211fcacb94903332b81e71168ade18225909ed4d53e26be3d8c4`.
- 기존 A3 원본·Docker restart claim·candidate-check-result는 기존 소스의
  정확 경로/SHA를 유지한다. 실제 profile 검증은 기존 `Recovery.profile`과
  동일한 original candidate.before를 사용한다. 현행 mount의 기존7개 z mode는
  완료 after와의 전체 metadata 비교로 별도 보존한다. 검사 함수를 완화하지 않는다.

의존 소스는 root 소유·쓰기 제한·symlink 없는 파일의 고정 bytes를 읽어
메모리에서 실행한다. 원 소스를 변경하거나 전역 CLAIM을 새 파일명으로 바꾸지
않는다. 새 orchestration만 부모의 검증/순서/로그/부분 실패 규약을 재사용한다.

## 실행 전 준비 및 위치

**독립 리뷰 완료와 exact source/bundle 검수, 사용자 실제 실행 허용 후에만**
아래 형식을 사용한다. 아직 package 전달·실제 실행 완료를 뜻하지 않는다.

1. 실행자는 복제본 `server08` 콘솔의 sudo 사용자1명이다. 현재 VM/boot/daemon,
   NIC 없음/HGFS 없음/Enforcing·기존 원본 회수·manager 미설치·다른 작업과
   비중첩을 실행 직전에 재확인한다. 운영 .54/db01 .55는 대상이 아니다.
2. 새 script와 위 두 정확 의존 소스를 같은 `/root/<reviewed-bundle>`에 둔다.
   root 소유, 디렉터리0700/파일0600, symlink 없음, Git LF bytes의 SHA를 대조한다.
   Windows working tree의 CRLF bytes를 Git 공급 SHA와 혼동하지 않는다.
   새 script 자체도 그 bundle 안에서 실행해야 한다. HGFS 실행은 사용하지 않는다.
3. 원복은 자동 stop·재시작·snapshot restore가 아니다. 현재 원본/claim을 유지한
   채 부분 실패를 읽기로 회수하고 정확 실패 회차의 후속 판단을 받는다.
4. 전체 변경 예산900초와 독립 실패 수집3×20초를 남기기 위해 이번 source의
   시작은 **2026-10-11 23:44 KST 이전**이어야 한다. 고정 종료 시각은10/12 00:00
   KST다. 이후 boot/작업창에 이 source를 임의 재사용하거나 제한을 우회하지 않는다.

```bash
sudo python3 -I /root/<reviewed-bundle>/clone-current-boot-recovery.py \
  --bundle /root/<reviewed-bundle> \
  --confirm-host-gate a3-evidence-preserved-no-nic-no-hgfs
```

host-gate는 기존 작업자의 host 보존/격리 확인 표시이며 새 Lead GO·조직 정책이나
실행 승인 대용이 아니다. 과거 회신 수신과 현행 실행 창 확인을 구분한다.

## 실행·정상 판정·중단

기존 `/root/hbr-a3-driver.lock`을 비차단 배타 획득한다. 새로운 고정 boot claim
`/root/hbr-boot-4b622c3c-4dec-4493-9ff2-8d5de74325d8-app-recovery.claim`은
기존 claim과 독립된 현재 회차의 중복 방지 기록이다. 현재 claim이 이미 존재하면
새 요청을 제출하지 않으며, 기존/새 claim 모두 성공·실패와 무관하게 보존한다.

preflight는 현재boot/daemon/격리·이전 완료와 claim 연결·원본 SHA·manager 부재·
AC04 형태·현재10개 metadata·9개 같은 실패·logger healthy/TCP accept·profile과
볼륨 inventory를 요구한다. 준비 실패는 앱 제출0회다. claim은 배타 생성0600 후
파일/부모 디렉터리를 fsync하고 시작 의도를 기록한다. 불확실한 생성/동기화 실패는
claim을 지우거나 다시 생성하지 않는다.

순서는 기존 postgresql→redis→registry→registryctl→core→portal→jobservice→
trivy-adapter→proxy다. 매 앱 전에 고정 세대·구성·logger·원본·manager 부재를
재조회하고, 정확 ID에 `docker --host=unix:///var/run/docker.sock start <ID>`를
최대1회 제출한다. start 직전 작업창/전체 예산을 다시 확인한다. 기존 부모 규약의
start timeout60초/health 대기60초/전체900초를 유지한다. 시작은 앱의 정상 데이터
쓰기를 유발할 수 있으며 데이터 무변경 시험이 아니다. Docker의 기존 always
내부 동작 횟수까지1회로 통제한다고 주장하지 않는다.

정상 표식은 `MANUAL_BOOT_RECOVERY_HEALTHY_REVIEW_REQUIRED PRIVATE=...`, rc0다.
완료 전 전체 healthy·전후 profile/metadata 보존을 재확인한다. 원 argv/rc/시각·
stdout/stderr·source/dependency/과거 pin과 current boot/daemon은 root 전용 새
`/root/hbr-current-boot-recovery-*`에 남긴다. 기록 회수/무결성 대조는 별도다.

preflight 실패는 STOP_BEFORE_CHANGE, 현재 claim 이후 또는 claim이 존재하는
실패는 STOP_RECOVERY_REQUIRED/rc2다. 부분 기동/timeout/세대 변화/원본 불일치/
logger 소실/manager 등장/clock 종료에서 다음 start를 중단한다. timeout은 서버
측 작업 취소가 아니며 자동 retry/stop/rollback은 없다. 실패 후 state/unit/AC04를
독립 수집하며 한 조회의 실패가 다른 수집을 지우지 않는다.

CLI의 root·bundle·source/pin·남은 작업창 검사에서 session 생성 전에 실패하면
Python 오류/비0 종료(일반적으로 rc1)이며 위 session 표식이 없을 수 있다.
이 경우에도 start 제출0회다. 생성된 부분 폴더가 있으면 삭제하지 않고 오류와
실제 원본을 보존한다. 비0 코드를 성공 표식 부재만으로 재시도하지 않는다.

VM/OS/Docker restart, Compose up/down, recreate/pull, policy/logging/security
변경, volume 삭제/relabel, SSH 설치, manager 설치/활성화, 원 claim 삭제,
자동기동·실제 로그 저장·AC04~06 인수·티켓 종결은 이 회차에 포함하지 않는다.

## 검증 경계

새 test는 MOCK이며 현재boot·세대·종료 창·완료 회차/claim 연결·중복 방지·
부분 실패/무재시도·manager/AC04 drift·Linux 파일/디렉터리 fsync 실패를 검증한다.
기존 app recovery 시험도 회귀한다. CI는 실제 guest 복구나 Runtime 허용이 아니다.
현재 exact source의 독립 REVIEW·MERGE·package 공급·RUNTIME·AC는 각각 별도다.
