# Phase 1 승인 입력·보호 저장소·초기 활성화 연결

CODEX_ASSISTED · 2026-10-09. [정책 전환 transaction](harbor-recovery-policy-transition.md)의
후속 라이브러리다. 승인 후보 입력의 결속과 검증, 저장소 메타데이터 검사, 정책 전환 완료 후
명시적 최초 RUN 전이를 구현했다. 후속 [검증 bootstrap/개별 운영 CLI](harbor-recovery-bootstrap.md)를
추가했다. **설치기·상주 실행·unit 등록/enable/start·실제 서버 적용은 아직 없다.**
이 문서는 라이브러리 계약이며 현장 실행 명령으로 사용하지 않는다.

2026-10-13 후속: [작성 context 계약·정책 변경 전 시험](harbor-recovery-writer-context.md)을 적용한다. v1 입력 자동 전환·기존 Store 재사용은 하지 않는다.

## 승인 입력의 경계

`load_bundle(path, expected_sha256, expected_context, deadline)`은 외부에서 받은 정확한
SHA-256·SELinux context와 root:root/0600 메타데이터로 JSON 파일을 읽는다. 현재 파일에서
기준 해시를 자동 생성하거나 기준과 다른 관측값을 재등록하지 않는다. 해시 일치는 무결성 확인이며,
사람의 승인·회차 GO 자체를 증명하지 않는다. 호출자는 그 입력과 행위에 대한 승인을 별도로 확보해야 한다.

스키마 `fds.harbor.recovery.bundle.v2`은 다음 항목만 받는다.

| 항목 | 필수 내용 |
|---|---|
| `host_policy` | 기존 Linux provider의 전체 호스트·격리·AC04·Engine·Compose·파일 pin |
| `plan` | Plan의 모든 필드, 정확한 10개 ID·지문·시간/재시도 예산·execution binding |
| `manager` | 준비된 `fds-harbor-recovery.service`의 fragment/drop-in pin |
| `source` | 40자리 검토 커밋, `/opt/fds-harbor-recovery/versions/<commit>`의 11개 모듈 해시 |
| `store` | `/var/lib/fds-harbor-recovery/instances/<32hex>`와 디렉터리/파일 context 및 독립 관측한 `writer_context` |

중복 JSON 키·누락/추가 필드·일부 source pin·기존 A3 경로 재사용을 거부한다. bundle 자체를
host 파일 해시에 포함하는 자기 참조도 거부한다. source의 모든 해시는 host 파일 pin과 같아야 한다.
host policy뿐 아니라 코드 릴리스·상태 namespace·준비 unit·저장소 context까지 execution binding에
포함한다. 어느 항목이 바뀌어도 이전 Plan/RUN을 그대로 재사용할 수 없다.

`build()`는 이 입력으로 실제 Linux provider, Docker adapter, ProtectedStore, 정책 transaction,
초기 Activation, Executor를 구성할 뿐이다. directory/state/journal을 생성하거나 Docker API를
호출하지 않는다. 매 실제 관측 전후에는 bundle 파일을 다시 검증하고 provider가 source pin을 검사한다.

**신뢰 경계:** 이 모듈을 import한 Python 코드·인터프리터·bootstrap은 이미 신뢰된 설치물이어야 한다.
import 후 해시 검사는 앞서 실행된 Python을 소급 인증하지 않는다. 후속 설치기는 정확한 코드 출처,
보호된 import 경로, interpreter/표준 라이브러리 신뢰, unit의 실행 명령과 입력 pin 전달을 연결해야 한다.
이 PR은 그 설치 단계까지 완료했다고 주장하지 않는다.

## 저장소와 중단 증적

`ProtectedStore`는 Linux에서 준비된 root 소유 디렉터리만 받는다. 실제 builder는 uid/gid=0을
고정하고, 테스트에만 비특권 uid/gid를 사용한다. 상위 경로를 fd와 `O_NOFOLLOW`로 순회하며
소유자·타 사용자 쓰기·POSIX ACL을 확인한다. 저장 디렉터리는 정확히0700, 파일은0600이어야 한다.
저장 디렉터리/파일의 xattr은 정확한 `security.selinux` 하나만 허용하며 승인 context와 대조한다.
상위 공유 디렉터리에는 ACL 차단을 적용하되 context 자체를 고정하지는 않는다.

기존 nonblocking flock, symlink/hardlink 거부, fsync·원자 교체, O_EXCL claim을 유지한다.
같은 lock 안에서 허용 이름의 기록만 검사하며 최대4096개로 제한한다. 오래된 claim/audit을 자동
삭제하거나 토큰·재시도 이력을 초기화하지 않는다. 보관 한계에 도달하면 현장 보관/세대 이관 절차가
필요하며 이 모듈은 임의 회수하지 않는다.

`state-*.pending` 또는 `policy-*.pending`이 남으면 기존 상태 읽기는 가능하지만 모든 새 쓰기와
정책 transaction/활성화를 차단한다. 자동 승격·삭제·재처리하지 않는다. 새 파일의 SELinux label은
준비된 파일시스템에서 부여돼야 한다. label 검사 실패 후 생성된 빈 파일도 남을 수 있으며, 이는
부분 생성 증적이다. 자동 chmod/chown/setxattr/초기화로 복구하지 않는다.

## 설치 후 최초 활성화와 실행 gate

후속 설치기가 명시적으로 준비할 순서는 다음과 같다. 개별 명령은 위 bootstrap 문서를 따른다.

1. 검토된 코드/입력·비활성 unit·보호 경로/label을 준비하고 새 Store를 초기 HOLD로 명시적 초기화한다.
2. 전 단계 정책 transaction을 수행한다. 앱9개 `always→no` readback까지 완료되어 journal이
   `INSTALLED_HOLD`, pending 없음이어야 한다. logger 정책은 변경하지 않는다.
3. `activation.arm_initial(deadline, explicit=True)`는 같은 lock에서 초기 State인지 확인한다.
   fresh 호스트/입력/정책 검증, 전환 당시와 같은 boot/daemon, 10개 running/healthy·logger TCP,
   manager loaded/inactive/dead/disabled를 확인한다. 시간이 남고 코어가 승인하면 요청 audit을
   먼저 보존하고 RUN/ARMED 상태를 저장한다. **이 호출은 앱이나 unit을 시작하지 않는다.**
4. 서비스 enable/start와 그 후 실제 관측은 별도 후속 설치 단계다. 활성화된 Executor는 open,
   각 RUN tick, logger reconciliation 때 완료 journal을 확인한다. 누락·손상·원복 중/완료 journal은
   `INSTALLATION_GATE_FAILED` HOLD로 처리하며 observe/start 전에 멈춘다.

초기 활성화는 기존 HOLD 사유·사용된 토큰·재시도 이력을 지우는 경로가 아니다. Executor의 종전
직접 `arm_initial()`도 이 builder에서는 거부한다. 운영자 HOLD는 설치 gate 실패 중에도 요청할 수
있지만, 파일 무결성/쓰기 오류는 그대로 오류로 남는다. 저장 실패 시 RUN 성공으로 보고하지 않는다.

정책 원복은 기존 규약대로 manager 중지·controller HOLD·동일 세대·건강 상태·확정된 변경 목록을
확인해 명시적으로 수행한다. 원복 후 journal/claim을 보존하므로 같은 저장소를 다시 초기 활성화할 수
없다. 불확실한 pending 해소나 일반 장애 reconciliation은 후속이며 기록 삭제로 우회하지 않는다.

## 검증과 완료 한계

`python3 -B -m unittest discover -s tests/recovery-core -v`

모의시험은 외부 해시/필수 입력/binding 변경, 실행 전 설치 gate, 초기 활성화 제한, 저장 실패를
검증한다. Linux에서는 실제 fd·권한·flock·fsync·원자 교체를 사용해 정책 전환→초기 활성화→
운영자 HOLD→역순 정책 원복을 연결하고 claim 보존을 확인한다. 해당 시험의 Docker 응답은
합성이며 SELinux/ACL 조회도 주입한 값이다. CI가 실제 enforcing SELinux 권한 또는 실제 Harbor
기동을 검증한 것은 아니다.

현장 입력 생성·독립 리뷰, 신뢰된 bootstrap 설치·상주 실행, unit 설치·enable/start, 실측 예산,
실제 SELinux 접근 허용, Docker 재시작/VM 재부팅·syslog 수신·원복 인수는 남아 있다.
RUNTIME/AUTOSTART/SYSLOG_INGESTION은 이 변경에서 **NOT_RUN**이다.
