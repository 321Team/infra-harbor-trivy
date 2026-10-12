# 운영 Harbor 주소 변경 — 일회성 진입점과 감독 계약

CODEX_ASSISTED · 2026-10-12 · baseline#13 · PR49 후속.
기존 Sequence/보호 입력/증적에 CLI와 독립 OS 기한을 연결한다. 실제 운영 launch/package,
작업 예산, 보호 경로/label을 생성한 실행 번들이 아니다. 설치·서비스 시작·앱 변경은
이 코드의 정적/모의/CI 성공과 별도로 실제 source/input을 대조한 뒤 수행한다.

## 진입 경로와 신뢰 전제

`scripts/bootstrap/harbor_address_bootstrap.py`는 Linux root, Python 3.10 이상,
`-I -S -B`와 최적화 비활성을 요구한다. 운영 interpreter/stdlib/bootstrap 자체는
먼저 신뢰된 설치 경로에서 검증해야 한다. 시작 후 자기 hash 검사는 이 전제를 대신하지 않는다.

외부에서 검토한 launch SHA256/context를 받아 root0600 파일을 읽고, source 15개의
정확 bytes·hash·mode·root 소유·SELinux·단일 link·보호 부모/경로를 검사한 뒤 모두 compile한다.
그 후에만 메모리의 검증된 code를 import한다. 프로젝트 sys.path/pyc를 쓰지 않는다.
선행 import, 미등록 프로젝트 모듈, reload, launch 재읽기 차이는 거부한다.
소스 수치/label을 live 상태에서 자동 승인하거나 허용치를 넓히지 않는다.

공통 호출 형태(아래 변수는 확인된 회차 값으로 공급하며 기본값은 없음):

```bash
"$PYTHON" -I -S -B "$BOOTSTRAP" verify \
  --launch "$LAUNCH" --sha256 "$LAUNCH_SHA256" \
  --context "$LAUNCH_CONTEXT" --timeout "$READ_SECONDS"
```

| operation | 동작 / 변경 범위 |
|---|---|
| verify | launch 구조·검증 source의 로딩까지; host/package/앱 미조회 |
| preflight | 보호7JSON·현행 host/앱 대조 → fd/private HOME Compose config → 재대조; supervisor 미검증, claim/up 없음 |
| ready | 설치된 미기동 unit의 공통 설정 검사 → preflight와 같은 읽기/렌더 → unit 재검사; claim/start/up 없음 |
| unit | 정확 launch에서 unit text만 출력; 설치/reload/start 없음 |
| apply --execute | 일치하는 실행 중 unit/cgroup 안에서만 세션1회; journal/evidence 쓰기와 앱9개 각 최대1회 |
| inspect | 보호 package/source와 증적 판독; claim 삭제/재실행 없음 |

`apply` 외 `--execute` 사용과 `--execute` 없는 apply는 거부한다. 오류 출력은 고정 원인이다.
private Compose/env/inspect/payload 내용, 예외 원문을 stdout/stderr로 내보내지 않는다.

## launch 입력 계약

schema는 `fds.harbor.address-launch.v1`이다. 아래 필드는 모두 필수이며 이 문서는 명세다.
샘플의 boot·대상·시간·label·예산을 실제 package에 채우지 않는다.

| 필드 | 공급할 실제 검토값 |
|---|---|
| source | directory, 검토 revision(40hex), 정확15모듈별 sha256/mode/gid=0/selinux |
| interpreter, bootstrap | 각각 실제 절대 path와 spec(sha256/mode/gid=0/selinux) |
| session | package_path/package_sha256/package_context 및 journal/evidence/private 각각 path/context |
| budgets | prepare_seconds, mutation_seconds, collection_seconds, termination_seconds |
| supervisor | 회차별 `fds-harbor-address-…service` 이름과 실제 unit 파일 context |

15모듈은 기존 SOURCE_MODULES 14개와 harbor_address_launch다. source는 검토한 revision의
파일 bytes와 외부에서 대조한다. revision 문자열 자체를 코드 무결성 증거로 쓰지 않는다.
interpreter/bootstrap/15 source pin은 package의 host-policy pinned_files와도 일치해야 한다.
package/journal/evidence/private 경로는 서로 같거나 부모/자식일 수 없다.
기술 파서 상한은 예산 합계86400초이며 실제 작업 예산을 부여하는 기본값이 아니다.

unit hash와 package/launch 사이의 순환을 만들지 않는다. unit은 **외부 pin으로 고정한
launch에서 결정적으로 계산**하고 UnitGuard가 별도로 매회 검증한다. 이 새 unit hash를
그 launch가 가리키는 package에 역으로 넣지 않는다. 기존 Docker/guard unit pin은 유지한다.

## 독립 OS 기한

생성 unit은 `/run/systemd/system/<검토한 이름>`의 root0644 runtime 파일이다.
Type=exec, Restart=no, KillMode=control-group, SIGTERM 뒤 지정 종료 예산 후 SIGKILL,
RuntimeMaxSec=준비+변경+수집, 무작위 추가시간0, root/UMask0077/cwd `/`다.
Install/enable/ExecStopPost/자동 재시작은 없다. After는 기존 Docker/guard의 순서 참조이며
Requires로 꺼진 서비스를 시작하지 않는다. 표준입력은 null이고 출력은 고정 요약만 journal로 간다.

Type=oneshot에는 RuntimeMaxSec가 적용되지 않아 exec를 사용한다.
KillMode=control-group은 unit에 남은 프로세스 전체를 종료 대상으로 삼는다.
근거: [systemd v257 service](https://github.com/systemd/systemd/blob/v257/man/systemd.service.xml),
[systemd v257 kill](https://github.com/systemd/systemd/blob/v257/man/systemd.kill.xml).

적용 직전/host 대조 전후에 unit text/hash/context, 실제 설정/기한, self MainPID,
InvocationID/시작 세대, drop-in 없음/reload 불필요, cgroup v2 소속을 확인한다.
`systemctl show`는 빈 `EnvironmentFiles` 구조체 배열을 `--all`에서도 출력하지 않는다.
따라서 이 항목의 누락만 빈 목록으로 읽는다. 먼저 검토 launch와 EnvironmentFile 지시문이
없는 결정적 unit의 bytes/context를 고정하며, 다른 속성 누락·중복·알 수 없는 속성,
비어 있지 않은 환경 파일 목록, drop-in 또는 reload 필요 상태는 계속 거부한다.
근거: [systemd v257 EnvironmentFiles 출력 구현](https://github.com/systemd/systemd/blob/v257/src/systemctl/systemctl-show.c#L1196-L1212).
기한은 현재 Python 시각이 아닌 ExecMainStartTimestampMonotonic에서 계산한다.
단독 CLI/잘못된 unit/재시작으로 기한을 새로 얻는 경우에는 세션 변경에 진입하지 않는다.

`ready`는 `apply`와 같은 UnitGuard 설정 파서를 사용한다. 정확 launch/unit pin, loaded 상태,
소유자·기한·종료 방식·drop-in/reload 없음·NRestarts=0을 공유하여 실행 직전에 처음 발견되는
설정 차이를 앞당겨 확인한다. inactive/dead/MainPID=0/시작 시각0인 미기동 unit만 받으며,
실행 중 프로세스의 PID/InvocationID/cgroup은 아직 검사할 수 없어 `running_identity=NOT_TESTED`로
보고한다. 실제 apply는 기존 실행 세대 검사를 계속 수행한다. ready 성공을 기동 시험이나 AC로
확대하지 않으며, 과거 실행한 회차의 증적을 지워 ready를 다시 통과시키지 않는다.

이 감독은 커널의 uninterruptible I/O가 즉시 끝난다는 보장이나 Docker rollback이 아니다.
Compose client가 종료돼도 Docker daemon이 이미 수락한 작업은 계속될 수 있다.
OS 중단은 evidence.closed 작성 전 일어날 수 있으므로 그 경우 UNKNOWN/부분 상태를 보존한다.
SIGKILL 이후 같은 회차 start/claim 재사용으로 이어가지 않는다.

## 현장 순서와 중단/인수

1. 기존 허용 범위에서 정확 harbor01/10.1.93.54의 fresh 신원·보호 설정·10healthy·원본과
   복구점 연결을 대조한다. 현재값/허용 근거가 없는 항목은 미확정으로 남긴다.
2. 검토한 interpreter/stdlib/bootstrap/source를 신뢰된 root 경로에 배치하고 bytes/metadata를
   확인한다. 검토한 실제7JSON을 빈 package 경로에 공급한다. private/journal/evidence
   경로도 계약대로 준비한다. 기존 claim/원본/과거 raw와 원 Compose는 덮어쓰지 않는다.
3. launch 입력을 독립 대조한 뒤 verify → preflight를 수행한다. 기대 hash/label/세대 불일치,
   config 오류·출력 제한·남은 시간 부족이면 다음 단계0. preflight는 운영 앱을 바꾸지 않는다.
4. unit 출력 bytes를 위 runtime 경로에 배치·검증하고 검토한 설정을 로드한다.
   `systemd-analyze verify` 성공은 문법 확인뿐이다. unit 설치/기동은 이 문서가 실행하지 않는다.
   같은 bootstrap 호출에서 operation만 `ready`로 지정하여 설치 상태·host·렌더를 재대조한다.
   실패하면 start하지 않는다. 이 읽기 단계는 기동하지 않아 실행 예산을 시작하지 않는다.
   기존 운영 변경 허용과 일치하는 source/input/비중첩을 확인한 후 해당 unit을 **1회** 시작한다.
5. ADDRESS_APPLIED_HEALTHY_REVIEW_REQUIRED·evidence seal·앱별 rc/health·보존·주소 상태와
   원본 hash를 대조하고 private 증적을 회수한다. collection.complete=false는 없어지는 old ID
   조회 실패일 수 있으므로 원인별로 판단한다. rc0만으로 최종 AC/자동기동을 판정하지 않는다.
6. 실패/기한 초과/부분 상태는 다음 앱 변경 없이 보존한다. inspect와 승인된 읽기로 실제 상태를
   확인해 담당자에게 인수한다. 자동 stop/retry/restore/claim 삭제/VM 복원은 없다. 수동 복구가
   필요하면 실제 부분 상태와 기존 복구점의 데이터 시차를 대조한 구체안으로 진행한다.

위 순서는 실제 보호 경로·예산이 대입되기 전에는 운영 실행 명령 묶음이 아니다.
새 AC/전체 회신 Gate를 추가하지 않는다. manager/H6·worker 확인·최종 인수는 별도 잔여다.

## 이번 검증과 남은 실제 확인

- STATIC/MOCK: 15검증 source import, launch drift/중복 JSON/경로 및 unit 설정 변조,
  잘못된 PID/cgroup/기한·재시작 세대, apply 전 중단, 읽기 preflight/ready, 렌더 후 unit 변경,
  이미 시작한 회차 거부, 변경/수집 기한 분리를 시험한다.
- Linux CI: 임시 root 경로의 실제 fd/hash/권한/link/추가 xattr와 isolated Python 실패 출력을 시험한다.
  별도 `FDS_TEST_SYSTEMD=1` 단계는 CI에만 임시 unit을 설치하고 실제 systemd 출력/실행 세대와
  기한 도달 시 다른 process group의 하위 프로세스까지 종료되는지 검사한다. systemd/cgroupv2가
  없으면 해당 CI 단계는 skip 대신 실패한다. payload·예산·SELinux label은 시험용이며 Docker와
  운영 서버에는 접속하지 않는다. 실행 결과는 해당 HEAD의 CI에서 별도 확인한다.
- PR49 비차단 판독 지적: sealed 상태에 CALL_END 없는 CALL_INTENT/PROCESS_INTENT/RESULT가
  남으면 invalid/UNKNOWN으로 거부한다. 정상 호출 경로를 변경하지 않는다.
- RUNTIME_READ_ONLY(2026-10-12 16:12 KST): 실제 Compose5.6.0 SHA
  `1c90a477e132d768ebd29338f75e9f3a039d2be45e28b316f4f617488dd718c8`의
  `/proc/self/fd/<opened-fd> version --short`가 HOME 없는 env/cwd `/`에서 rc0이었다.
  실제 systemd257/cgroupv2도 읽기로 확인했다. 관측한 Docker unit 값은 새 회차 예산이 아니다.
- 미실행: 실제 private HOME config/up, supervisor 설치/기한 도달 시 전체 프로세스 종료,
  실제7JSON 공급·앱 변경·manager/H6/AC. 의존 앱 restart 시 중간 STOP 가능성에 대한
  기존 clone 리허설 권고는 유지하되 자동 clone 기동이나 새 필수 인수조건으로 바꾸지 않는다.
