# Worker Robot 회전 코드 검토·실행 경계

CODEX_ASSISTED · 2026-10-15. **새 코드의 독립 리뷰용 후보이며 실행 지시가 아니다.**
책임 티켓은 [baseline #13](https://github.com/321Team/fds-project-baseline/issues/13)이다.
분류는 운영 쓰기와 보안 통제가 포함된 코드/문서 혼합 변경이다. Pre-check 예외를 적용하지 않는다.
[리뷰 정책](../REVIEW_POLICY.md)에 따라 작성자 외 적격 검토자의 정확 HEAD 검토와 Lead의 병합 판단이 필요하다.
기존 PR65는 `.50` guard/동일 코드 입력 전환만 검토했으며 이 새 코드를 승인하지 않았다.

## 저장소 경로와 검토 순서

소스는 [scripts/preparation/worker-rotation-20261015](../../scripts/preparation/worker-rotation-20261015/)에 있다.
기존 설치 관리자·bootstrap·guard·정책 소스는 변경하지 않는다.

| 순서 | 경로와 책임 | 검토할 실패 경로 |
|---|---|---|
| 1 | rotation-adapter-r2/rotation_contract.py, rotation_adapter.py | 실제 입력·순서·receipt·변경 상한, 중단/부분 실패, 명시적 조건부 복구 |
| 2 | rotation-adapter-r2/linux_host.py, input_supply.py, launch.py | TLS/HTTP 완전성·보호 도구·Secret/Pod/파일, credential 소유·회수, import 전 외부 pin |
| 3 | rotation-orchestration/orch_contract.py, orch_endpoint.py | 단회 발급·name claim·응답 유실·정확 권한/metadata·발급 원본 보호 |
| 4 | rotation-orchestration/orch_relay.py, orch_launch.py, prepare_commands.py | 기존 strict SSH 경로·4호스트 stage/공급/회수·부분 전달·절대 기한 |
| 5 | public-deployment-preparation/public_deploy.py, prepare_delivery.py | 공개60사본/단계 JSON 공급·별도 읽기, no-overwrite/no-follow·inode·ACL/SELinux·기한 |
| 6 | 각 디렉터리 test_*.py, tests/recovery-core/test_worker_rotation_publication.py | 합성 정상/실패/응답 유실, 경로 재배치 및 기존 CI 연결 |

17개 Python 소스와 3개 manifest, 공개 CA, DRAFT 양식6개, 공개 도구 pin1개는 고정 후보와 같은 bytes다.
상대 형제 디렉터리를 유지했으므로 runtime 코드 경로 수정은 없다. `.gitattributes`는 OS 간 자동 줄바꿈 변환을 막는다.
실제 배치 때 코드 디렉터리는 r2 정확7파일, O 정확5파일만 사용한다. 테스트·이 문서·DRAFT를 함께 설치하지 않는다.
로컬 과거 산출물 생성기3개는 워크스페이스 snapshot 경로에 의존하므로 게시 대상에서 제외했다.
과거 로그/ZIP/diff/검토 원본은 보존하며 이 PR에 원본 증적으로 다시 편입하지 않는다.

## 고정물과 검토 이력

| 구성 | 검토 당시 ZIP SHA256 | runtime manifest SHA256 |
|---|---|---|
| r2 | 510de8bf14cea04d67773b9170c741f78bf96ad6efeeab70ab1f839d4234497c | 0bf529d53e03cae160caebc4e3637c45502d8b621c0b08e8af49f62b75ccf247 |
| O | b95c2dec7f3a4cb4b454679b3e67b09267165db2e79c44d33477a0973ab7d71d | 08abcec219753ecd6d8ab622d706cb7b5cac08993911cd9cde4f2abd0e77191f |
| D1 | 7b864e095222c52905623edfe8f4434363cd215c410941c926c0b889129fdb59 | 9e04aef03466e1021ea6d32914f91a2f9dab84b3ccd543f55da7cf74e4aaa2a6 |

ZIP은 이 PR에 포함하지 않으며 위 값은 기존 검토 묶음 식별자다. 새 source mapping은
[SOURCE_PINS.json](../../scripts/preparation/worker-rotation-20261015/SOURCE_PINS.json)으로 확인한다.
해시 일치는 무결성이고 실제 동작/승인/인수의 증거가 아니다.

기존 로컬 기술 검토는 r2 B1/B2 해소, O 새 차단 없음(검토자51), D1 새 차단 없음(검토자20)이었다.
작성자 모의시험 r2 181/O48/D1 47과 검토자 시험 수를 합산하지 않는다.
AI 보조 로컬 기술 검토는 사람의 독립 승인이나 GitHub APPROVED가 아니다.
최종 PR에는 새 HEAD와 CI 결과를 별도로 기재해야 한다.

## 로컬 재현과 CI

저장소 루트, Python3.11 이상, stdlib만 사용한다. 아래는 합성 모의시험이며 서버/API/credential을 사용하지 않는다.

```text
python -B -m unittest discover -s tests/recovery-core -p test_worker_rotation_publication.py -v
```

기존 `harbor-recovery-core.yml`의 model job이 같은 discovery 경로를 사용한다.
기존 workflow/권한/Runner 설정은 변경하지 않는다. 게시 전인 지금 새 PR CI는 NOT RUN이다.
다른 기존 전체 시험을 로컬에서 반복하지 않는다. 원본 candidate builder는 실행하지 않는다.
`TOOL_PINS_CANDIDATE.json`은 2026-10-15 15:13~15:18 관측의 공개 pin을 재사용한 시험 입력이다.
그 안의 provenance 경로는 당시 로컬 증적 위치이며 이 PR에서 현재 호스트 상태를 보증하지 않는다.
실제 stage에서 정확 bytes·보호 사본/FD·라벨·버전을 다시 검증해야 한다.

## 실제 실행 위치·범위

후보는 control01과 Worker3의 root 보호 경로, ansible01의 기존 server01_ansible/strict SSH 경로를 사용한다.
목표 후보는 system/fds repository Pull-only 30일의 `robot$worker-20261015-r1`다.
기존 worker ID2·push ID3 삭제/Refresh, push 회전, `.102` 예외 회수, k3s/legacy Secret 처분은 범위 밖이다.
실제 발급 ID·비밀값·boot·시각·담당·invocation·작업창은 아직 결속하지 않았다.
코드의 고정 SA/Secret UID·host·도구와 현장 값이 다르면 기대값을 조용히 교체하지 않고 STOP한다.

1. 실제 담당/새 범위·수치·비중첩 창과 정확 입력을 결정한다. 준비30분+회전75분=105분은 제안이며 미예약이다.
2. 실제 host/boot/UID·GID·보호 부모 inode/device/ACL/SELinux·시각·name claim/단계 경로를 읽기 대조한다.
3. D1으로 공개 코드/단계 JSON을 배타 공급하고 실제 receipt를 받은 뒤 별도 읽기로 검증한다.
4. control01 콘솔에서 admin 암호를 표시/저장/전달 없이 입력해 O issue를 최대1회 수행한다. POST intent/claim을 먼저 보존한다.
5. 발급 응답과 현재 ID·권한·만료를 확인해 실제 plan을 결속한다. DRAFT/null은 실행할 수 없다.
6. ansible01 relay의 4 stage → 보호 credential4공급 → r2 Worker3 → APP Secret/Pod3 → MON-api Secret/Pod1 → MON-node Secret/Pod1 → worker01 파일/Pull 순서다.
7. 정상/부분 상태와 actor 종료·복구 필요 여부를 판정한 실제 closeout 뒤, 소유가 입증된 임시 credential4쌍만 회수한다.

준비·실행·실패 처분의 정확 argv/입력 SHA는 검토된 실제 입력을 로컬 생성기에 넣어 만든다.
`prepare_commands.py`는 명령/JSON 생성기이며 서버 설치기가 아니다. `prepare_delivery.py`는 공개 script 생성기이며 실행하지 않는다.
actual script 전체 SHA·외부 manifest pin·배치 결과는 정상 보호 경로에서 대조한다. 자체 해시 문자열만으로 출처를 승인하지 않는다.

## 알려진 한계와 필수 실행 구분

**D1 N1 — 생성/배치/소비 기한:** 공개 입력의 전체 의미·유효기간은 로컬 생성 시 O/r2 계약으로 확인한다.
배치기는 D1 deadline과 공개 bytes·host/boot를 검사하며 내장 입력의 유효기간을 다시 판정하지 않는다.
따라서 배치 PASS를 후속 action의 현재 유효성/실행 허가로 보지 않는다.
실제 공급 직전과 소비 전에 해당 action 기한을 확인하고, 만료 시 새 시각/claim을 임의 변경하지 않는다.
전송 중 내부 입력이 만료되면 PUBLIC_SUPPLIED 원본은 유지하되 입력 만료/소비 미실행으로 분리한다.
rotation에 이미 결속된 과거 prep는 active=False 계약을 유지한다. 이후 모든 회전 단계에 과거 prep 창을 재강제하지 않는다.
새 issue에는 active prep, stage/공급/변경에는 plan·supply_until/mutation_until/end, closeout에는 실제 관측 freshness와 plan end가 적용된다.

**D1 C1/C2 — 별도 현장 확인:** D1 exact code-dir 검사는 발급 name claim·runtime 관리 경로의 부재/정상 존재까지 보증하지 않는다.
issue 전 부재, issue 후 실제 verified claim, stage 전/후·공급/소비/회수 중의 expected state를 별도 읽기로 확인한다.
issue/stage/supply/retire를 조회용으로 실행하지 않는다. claim 삭제·새 invocation 우회·합성 receipt를 만들지 않는다.
실제 Linux FD/SELinux/SIGALRM/SSH 종료·호스트 장애는 모의시험으로 검증되지 않았다.

**O N1 — 30일 만료 검증:** duration30과 POST/GET 만료 일치는 별도 30일 산술 검증과 다르다.
실제 POST 시작/응답 시각, 서버/control 시각·timezone·달력 의미를 대조한다. 임의 ±2초 허용치를 만들지 않는다.
1일/365일 등 명백한 모순 또는 시계 근거 부족이면 공급 HOLD이며 재POST/Refresh/만료값 수정으로 우회하지 않는다.

**O N2 — 부분 credential 공급:** credential이 있으나 marker/SUPPLIED가 없으면 정상 retire는 소유를 입증하지 못할 수 있다.
재공급·claim 삭제·retire 반복을 하지 않는다. 공개 metadata/소유 marker/remote actor를 읽어 현재 상태부터 판단한다.
일치하는 소유 marker가 있더라도 별도 최소 회수 범위의 판단이 필요하고, 소유 불명/만료 상태를 강제로 지우지 않는다.
control01의 발급 응답/비공개 body는 root 보호 원본으로 보존하며 `/run` 임시 credential 회수와 구분한다.

## 중단·복구·완료 판정

불일치·예상 밖 상태/HTTP·TLS·인증 오류·시간 초과·응답 유실·중단이면 다음 변경을 멈추고 부분 파일/claim/원본을 보존한다.
자동 재시도·새 claim/시간으로 우회·자동 원복·기존 ID2/3 삭제·보안 완화는 하지 않는다.
r2 조건부 소비자 원복은 별도 실제 복구 결정, 현재 ID2 enabled/미만료 관측, 정확 before/after와 남은 상한이 필요하다.
응답 유실로 after 원본이 없거나 외부 변경·계정 만료가 있으면 자동 덮어쓰기를 하지 않는다.
자기 tag/Pod도 nonce·UID·spec·image ID 소유 확인 없이 지우지 않는다.

단계 완료는 실제 원본·rc·동일 대상/입력과 연결한다. 기존 앱 Ready나 health200은 새 Pull 인증 성공이 아니다.
STATIC/MOCK·CI·사람 독립 REVIEW·MERGE·공개 배치·발급/회전 RUNTIME·최종 AC는 각각 기록한다.
이 PR 게시/병합은 실제 서버 실행이나 전체 Harbor 인수의 완료조건을 대신하지 않는다.
