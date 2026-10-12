# 운영 Harbor 주소 반영 순서·부분 실패 처리

CODEX_ASSISTED · baseline#13. `scripts/production/harbor_address_sequence.py`는
운영 주소 반영의 **호출 순서와 판정 모듈**이다. Docker/Compose 호출·파일 journal·
보호 입력 공급기·CLI는 포함하지 않으며, 이 파일을 실행해도 서버를 변경하지 않는다.
시험의 메모리 journal/가짜 backend는 실제 환경에서 사용할 수 없다.
기존 clone 실행기/UUID/NIC guard, PR44 고정 boot·claim, manager 정책/설치에는 변경이 없다.

## 기존 관측과 구현 목적

2026-10-12 운영 읽기에서 앱9개 exited128/unhealthy·restart always, logger만 healthy였다.
기존 검토 override의 변경은9개 syslog 주소 `localhost`→`127.0.0.1`뿐이다.
기존 clone trial은10개 healthy와 격리를 요구하므로 그대로 소비할 수 없다.
운영 snapshot 이름/위치·UUID 연결·250GiB 포함·차분 체인과 여유 공간은
[수신 기록](https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-6117436976)에 있다.
현장 현재값·실제 복원/정상 서비스 보장·이번 실행 허용은 그 수신 사실과 다르다.

첫 앱부터 차례대로 재생성하고, 그 앱의 보존 대조·건강 확인이 끝나야 다음 앱으로 간다.
기존 수동 복구와 같은 순서: postgresql, redis, registry, registryctl, core, portal,
jobservice, trivy-adapter, proxy. logger에는 재생성을 요청하지 않는다.

## 모듈 입력과 외부 신뢰 계약

`Sequence(plan, backend, journal).run(deadline_mono=...)`를 한 번 호출한다.
plan에는 기본값이나 운영 fixture가 없다. 다음 값은 **입력 명세**이며 실행 request가 아니다.
실제 boot·작업창·기한·예산·SELinux label·대상·승인자를 생성하거나 자동 학습하지 않는다.

| 입력 | 생산/대조 책임 |
|---|---|
| `binding_sha256` | 검토된 운영 provider가 정확 hostname/product UUID/boot/Docker InvocationID·Engine/도구 신뢰·네트워크/AC04/SELinux·manager 부재 등 현행 보호 경계를 검증한 값. 이번 모듈은 그 의미를 직접 확인하지 않음 |
| `inputs_sha256` | 검토된 주소 후보와 전체 Compose/env/도구·보호 경로/공급물의 결속. 해시 일치만으로 신뢰 경로나 실행 허용을 증명하지 않음 |
| `baseline` | 정확10개 서비스의 ID/image/보존 hash/전체 logging/restart/status/health/exit/error hash. 운영의 실패한9앱과 healthy logger 상태를 명시 |
| `preservation_sha256` | 실행 adapter가 전체 설정·명령/env·mount/volume/ports·보안/label 등 보존 대상의 검토된 투영을 계산. 재생성으로 달라지는 ID/정당한 생성 metadata의 취급은 별도 검토 필요. 임의 제외/Mode 예외 자동 확대 금지 |
| `health_seconds`, `io_seconds`, `poll_seconds`, `observation_max_age` | 서비스별 health 및 입출력/관측 예산. 유한 양수, bool 거부. 과거 clone의 예산을 운영 기본값으로 재사용하지 않음 |
| `deadline_mono` | 이번 프로세스/boot에 결속한 실행 종료 한계. 현장 adapter가 별도 승인된 실제 창과 연결해야 함 |

`backend.observe(deadline)`는 fresh10개 투영과 IPv4 logger 준비 상태를 반환한다.
읽기 시작~종료 사이 관측이어야 하며 설정·세대/보호 경계와 입력 결속이 같아야 한다.
이 provider는 State의 running/restarting/dead/paused 일관성, 실제 volume inventory와
image 고정·보호 공급물 소비를 검증해야 한다. 모듈이 임의 callback의 사실성을 증명하지 않는다.

`backend.recreate(service, expected_id, plan_sha256, deadline_mono)`는
정확한 기존 ID와 검토 입력을 변경 직전에 대조하고 **그 앱만 최대1회** 재생성한다.
no-deps/pull 금지/build 금지/volume 유지 등 실제 명령·옵션과 환경은 adapter 검토에서 고정한다.
여러 앱을 묶어 실행하거나 내부 retry·daemon restart·정책 변경·무조건 start/stop을 넣지 않는다.
주소 외 설정을 바꾸는 보호 공급 방법을 이 PR의 승인을 근거로 허용하지 않는다.
반환 rc0은 요청 도구의 성공일 뿐이다. 새 ID와 healthy·보존 일치가 따로 필요하다.
callback 진입 뒤 예외/기한 초과·상태 불명은 후속 쓰기를 중단한다.

모든 실제 I/O는 전달받은 절대 기한을 구현해야 한다. Python callback이 돌아오지 않는 경우
본 모듈이 강제로 중단하지 못하며, Compose client 중단이 Docker 쪽 변경 취소를 보장하지 않는다.
명령이 늦게 끝나도 다음 앱으로 넘어가지 않는다. supervisor의 불명 결과 인수 경로가 필요하다.

## 기록과 실패 순서

실제 journal은 외부에서 준비한 root 전용/검토된 label·ACL/경로의 append-only 구현이어야 한다.
전체 run 동안 nonblocking 배타 lock, `begin(plan_hash)`의 미사용 회차 O_EXCL claim과
파일·디렉터리 fsync, `append`의 fsync/단일 writer, 실패 후 writer 사용 거부가 계약이다.
기존 파일/부분 기록 발견은 `FileExistsError`로 거부하며 새 회차로 자동 우회하지 않는다.
`harbor_address_journal.Journal`은 아래의 Linux 구현을 제공한다.
메모리 시험과 Linux 임시 파일 시험 모두 실제 운영 전원 장애·SELinux 검증은 아니다.

1. 미사용 회차를 확보하고10개 시작 상태를 대조한다.
2. 앱마다 변경 의도를 영속화한 **뒤** 전체 상태·기한을 다시 대조한다.
3. 전송 전 실패는 그 서비스의 결과 사건 없이 STOP. callback 진입 뒤 실패는 불명/실패로 인수한다.
4. rc0 뒤 새 ID/원 image·보존 hash·restart·주소만 변경한 logging을 대조하고 제한된 health 관측을 한다.
   대기 중 새 ID가 또 바뀌면 중단한다. 다음 앱은 이전 완료 앱의 healthy 유지와 미수행 앱의 원 상태도 확인한다.
5. 9개 완료 후 최종 전체 상태·기한을 확인한 뒤 durable COMPLETE를 기록한다.
   COMPLETE는 기한 내 마지막 관측의 완료를 뜻하며 fsync가 기한을 넘겨 반환해도 STOP을 덧붙이지 않는다.
   쓰기 실패는 완료가 아니며 writer를 폐기하고 부분 파일을 보존한다.
   로그 실제 수신·업무 데이터·자동기동·H6/AC는 별도다.

callback이 반환했으나 호출 기한이 지났으면 `RECREATE_RESULT(outcome=LATE)`를 남긴 뒤
DEADLINE으로 중단한다. ACK/healthy로 승격하거나 다음 앱을 호출하지 않는다. 실제 서버 성공 여부는 불명이다.

| 반환 | 인수 의미 |
|---|---|
| `STOP_BEFORE_CHANGE` | **이번 호출**의 recreate callback 진입 전 중단. 다른 주체/이전 회차의 변경이 없다는 뜻은 아님 |
| `STOP_EXISTING_HISTORY_REQUIRES_REVIEW` | 이전/부분 기록이 있어 쓰기0. 기존 회차의 실제 결과를 별도로 인수해야 함 |
| `STOP_RECOVERY_REQUIRED` | 이번 callback을1회 이상 진입했거나 완료 기록 확인 실패. 부분 상태/원본 보존 후 별도 복구 판단 |
| `ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED` | 관측 제공자가 보고한9개 새 ID/healthy·보존 일치까지 확인. 현장 adapter 신뢰·실제 로그/데이터·인수는 자동 완료하지 않음 |

`claimed_services`와 `transport_entered_services`를 구분한다. 전자는 durable intent 뒤
아직 미전송일 수 있고, 후자도 서버 수신/변경 성공의 증거는 아니다.
process crash/KeyboardInterrupt에는 claim/intent를 남기고 자동 resume하지 않는다.
`journal_recorded=false`이면 운영자가 반환 결과도 독립 경로에 보존해야 한다.
raw inspect·env·예외 원문은 반환/기록하지 않는다. 오류는 고정 코드로 제한한다.

## 실제 적용 전 잔여

- root 보호 입력/렌더링 소비·정확 ID 조건부 재생성·전체 보존 투영을 제공하는 실제 adapter 구현/시험.
- Linux journal의 실제 보호 경로 준비/독립 기록·부분 실패 수집 연결.
- 실제 snapshot 이후 변동·현재 대상/세대·비중첩 재대조, 실행 예산 확정과 정확 소스 검토.
- 구체 변경·중단/복구 범위 허용. 원 주소 복귀 재생성은 기존 IPv6 실패를 되살릴 수 있으므로 정상 복구 보장이 아님.

자동 retry·stop·restart·down/pull·volume 삭제·snapshot restore·사용 claim 삭제는 없다.
소스 승인을 운영 변경/manager 설치/AC 인수로 확대하지 않는다. 원본/기존 snapshot은 보존한다.

로컬 검증: `python3 -B -m unittest discover -s tests/production-address -v`.
Linux CI는 synthetic backend와 실제 root 전용 임시 파일 journal을 사용한다. guest/Docker 접속0.

## Linux journal 사용 계약

`Journal(absolute_path, expected_selinux=exact_context_bytes)`를 Sequence에 전달한다.
경로·label은 실행 전에 검토한 실제 입력이며 이 모듈이 생성하거나 자동 학습하지 않는다.
None은 SELinux xattr가 없는 별도 검토 플랫폼(CI 등)에만 쓸 수 있고, 실제 label이 있으면 거부한다.
운영의 Enforcing 상태를 바꾸거나 None으로 우회하지 않는다. 파일과 마지막 디렉터리는 같은 검토 context를 요구한다.

- 모든 부모를 fd-relative/O_NOFOLLOW로 열고 root 소유·group/other 쓰기 금지·ACL/예상 밖 xattr 부재를 대조한다.
  마지막 디렉터리는 root:root0700, 파일은 root:root0600/regular/nlink1이다. chmod/chown/relabel이나 자동 보정은 없다.
- `writer.lock`을 flock LOCK_NB로 회차 전체 잠근다. 잠금 파일 교체·외부 append/size 변경을 확인한다.
  디렉터리에는 lock 외 어떤 파일도 없어야 begin 가능하다. 이전 claim·미완성 파일·알 수 없는 파일은 보존/거부한다.
- `run.claim` O_EXCL → 파일 fsync → 디렉터리 fsync → events O_EXCL/디렉터리 fsync → BEGIN fsync 순서다.
  모든 사건은 append-only JSONL/순번/이전hash/현hash와 fsync로 결속된다. 같은 객체는 회차1회만 사용한다.
- 기록은 고정 kind/reason/outcome·서비스·ID/hash·순서 목록만 허용하며 임의 문자열 필드/예외 원문을 거부한다.
  INTENT→RESULT(ACK)→APP_HEALTHY 순서와 COMPLETE/STOP terminal을 검사한다.
  저장 오류 후 writer를 재사용하거나 STOP으로 부분 파일을 수리하지 않는다.
- 부분 쓰기/프로세스 종료 시 claim과 torn tail은 그대로 남는다. 재생·새회차 자동 우회·삭제 도구는 없다.
  수집기는 원본 파일/크기/해시 및 호출자 결과를 별도 보존해야 하며, 기록 일부가 유효하다고 현장 성공으로 단정하지 않는다.
- flock은 협조하는 실행기 간 배타 제어다. 별도 root 관리 작업을 막는 수단이 아니므로 현장 비중첩 확인은 계속 필요하다.
  fsync는 운영 스토리지/전원 손실 내구성을 별도로 시험한 결과가 아니다.

후속 현장 읽기에서 대상이 이미 healthy라면 중단9개 전제의 plan을 만들지 않는다.
정상 서비스의 정지·재생성 허용 및 실제 경로는 별도 대조하며 이 journal 추가로 실행 범위를 넓히지 않는다.
