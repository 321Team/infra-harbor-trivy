# Store 작성 context 검증과 관리자 재활성화 준비

CODEX_ASSISTED · 2026-10-13. [PR60 실제 실패·원복](https://github.com/321Team/infra-harbor-trivy/pull/60#issuecomment-6142397545)의 후속 코드/실행 계약이다. 이 문서의 절차는 운영 실행 완료나 재활성화 승인이 아니다.

## 원인과 코드 경계

CLI가 만든 Store 파일과 systemd가 만든 `manager.lock`의 SELinux user가 달랐다. 기존 검사는 전체 파일 context 불일치를 정확히 거부했지만 정책 전환 뒤에야 발견했다. 파일 소유자·mode·해시 및 CLI의 생성 시험만으로 서비스의 작성 경로를 검증할 수 없다. 잠금 파일 사전 생성만으로는 다음 `state-*.pending`/claim 생성 실패를 막지 못한다.

bundle v2는 `store.writer_context`에 **관측·검토된 프로세스 전체 context**를 추가한다. `directory_context`, `file_context`와 별개이며 파일 라벨에서 추정하지 않는다. 이 값은 기존 Store scope → execution binding → Plan digest에 결속된다. v1/v1 production 입력은 새 코드에서 거부하고 자동 보정하지 않는다. 새 소스와 입력은 새 package로 준비한다. 기존 v1 설치물·실패 Store·claim은 원형 보존하며 새 Store로 이관한다.

`ProtectedStore`는 쓰기/생성으로 파일을 열기 **직전마다** 호출 스레드의 `/proc/thread-self/attr/current`를 정확 대조하고 `attr/fscreate`가 비어 있는지 확인한다. 첫 controller/manager lock, state pending, audit, policy/stop claim에 동일하게 적용한다. 읽기 불가·다른 context·fscreate override는 파일 생성 전 실패한다. 이미 열린 fd를 사용하는 루트 공격자를 격리하는 장치는 아니다.

`verify-writer`는 검증된 bootstrap/입력으로 이 프로세스 조건만 읽어 확인한다. Store/Engine 객체를 만들거나 Store 파일을 열지 않는다. 출력 `STORE_WRITER_VERIFIED`/`creation_probe=STILL_REQUIRED`는 **실제 파일 생성 시험의 성공이 아니다**. 기존 `verify`는 계속 입력/코드 무결성만 확인한다. `state`는 controller lock을 열 수 있으므로 같은 writer 경로를 사용한다.

기존 전체 SELinux 파일 라벨·ACL·owner/mode·symlink/hardlink·pending·O_EXCL/원자 저장 검사를 유지한다. 프로세스 context가 맞아도 실제 생성 라벨이 틀리면 오류와 부분 파일을 보존한다. `runcon`, `setfscreatecon`, SELinux 비활성화, 라벨 일부 무시, 두 context 무조건 허용, claim 삭제로 우회하지 않는다.

## 정책 변경 전 실행 경로와 시험

운영 CLI와 resident를 동일한 검증된 systemd **service** 실행 경로로 맞춘다. 단순 `sudo` 또는 `--scope`가 동일 context라는 전제를 두지 않는다. systemd transient service는 service manager가 시작하지만 scope는 호출자의 실행 환경을 상속한다. [systemd 원문](https://github.com/systemd/systemd/blob/main/man/systemd-run.xml)을 기준으로 대상 버전에서 옵션을 확인한다. 실제 context는 각 프로세스 내부 관측으로 대조한다.

아래는 실행 형식이며 실제 request가 아니다. 대상·절대 경로·각 회차 이름·해시·예산은 관측 및 기존 승인 값으로만 채운다. 환경 확장과 shell 실행을 사용하지 않는다. root/group, interpreter/label, unit hardening과 파일 접근 조건은 resident 설정과 대조하고, transient `SELinuxContext=` 강제 지정으로 맞추지 않는다.

```text
<검증된 systemd-run> --system --wait --pipe --service-type=exec
  --expand-environment=no --unit=<해당 명령의 고유 unit 이름>
  --property=User=root --property=Group=root --property=UMask=0077
  --property=Restart=no
  <검토된 Python> -I -S -B <검토된 bootstrap> verify-writer
  --bundle <v2 입력 경로> --sha256 <검토 해시>
  --context <bundle 라벨> --timeout <확정 예산>
```

`--wait` 종료까지 확인한다. 클라이언트 시간 초과/접속 종료가 transient 프로세스 종료를 보장하지 않는다. 응답 불명 시 해당 unit/job/PID·증적을 조회하고 중복 호출하지 않는다. 자동 강제 종료나 재시도는 추가하지 않는다.

1. **읽기 대조:** 실제 호스트/boot/설정·현재10개 상태·정책·manager disabled/inactive·원복 Store/claim 보존·작업 비중첩을 확인한다. 서비스 journal의 예전 context는 재현 근거이며 현재 검증을 대체하지 않는다.
2. **분리된 scratch 준비:** 검토된 코드와 실제 사용 예정 파일시스템/부모 조건 아래 빈 전용 시험 디렉터리를 준비한다. 정확 경로는 v2 `store.path` 뒤에 `.writer-probe`를 붙인 형제 디렉터리다. bootstrap은 이 경로를 만들거나 label을 보정하지 않는다. 운영 Store/claim을 사용하지 않는다. 디렉터리 label과 생성 파일 label을 별도로 확인한다. 경로·실행 시간·예산·관측값을 실측 전 package에 자동 채우지 않는다.
3. **첫 service 프로세스:** 위 호출 형식의 operation을 `probe-create`로 바꾸고 `--execute`를 명시한다. 동일 root/interpreter/실행 profile에서 process context와 fscreate를 확인하고 ProtectedStore의 초기 HOLD, controller/manager flock, state 원자 저장, audit와 O_EXCL 충돌 거부를 시험한다. 실제 SELinux Enforcing, uid/gid/mode/xattr, 종료코드·원본 증적을 수집한다. Docker/API/provider 및 운영 unit을 호출하지 않는다. 실제 또는 합성 앱 claim을 만들지 않는다.
4. **두 번째 service 프로세스:** 별도 transient service에서 `probe-reopen --execute`를 사용한다. 앞선 HOLD state를 읽고, 다른 PID·manager lease 획득·새 state/audit의 생성·원자 교체를 검증한다. PID 재사용도 보수적으로 거부한다. 첫 audit가 보존되고 원 운영 claim 해시가 그대로인지 별도 대조한다. 성공 상태는 `WRITER_PROBE_REOPENED`이며 같은 probe의 재생성/반복 reopen은 거부한다. 동일 프로세스의 연속 호출만으로 통과시키지 않는다.
5. **운영 입력 확정:** 두 프로세스의 writer/file context·코드 해시·경로 조건이 일치한 증적을 v2 입력과 연결한다. scratch 성공도 전체 Runtime/자동복구 성공은 아니다. 새 Store의 initialize/정책/arm/hold/원복 및 resident에 같은 writer 경로를 적용한다. 정책 변경 **이전**에 차단사항을 해결한다.

## 정상·중단·복구 판정

정상: actor 검증, 두 프로세스의 생성/읽기/잠금/저장/claim 보존이 모두 rc0이고 실제 메타데이터가 승인값과 일치한다. 그 후에만 별도 허용 범위의 정책 전환과 관리자 활성화를 진행한다. H6·재부팅·장애 주입은 이 시험에 포함하지 않는다.

하나라도 실패·경로/코드/profile 변경·시간 초과·응답 불명이면 정책 전환 전에 중단한다. scratch의 부분 파일과 로그를 보존하고 실패 run을 덮어쓰거나 자동 정리하지 않는다. 이미 원복한 운영 Store는 HOLD/ROLLED_BACK 그대로 둔다. 새 writer 경로에서도 HOLD/원복 조건을 충족하지 못하면 강제 쓰기나 파일 라벨 변경 없이 별도 복구 판단으로 넘긴다.

## 검증의 한계

Linux 회귀시험은 실제 fd/flock/원자 교체를 쓰지만 SELinux process/file 응답은 합성이다. context 검사 무력화 시 음성시험이 실패하는지도 확인한다. CI와 이 검사는 enforcing SELinux의 실제 domain/file transition을 보증하지 않는다. 위 두 프로세스 현장 시험은 해당 코드의 독립 리뷰·병합·검토 설치 후 수행하고, 통과 전 재활성화하지 않는다.
