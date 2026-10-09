# Phase 1 검증된 코드 로딩과 명시적 운영 명령

CODEX_ASSISTED · 2026-10-09. [승인 bundle](harbor-recovery-approved-bundle.md)의 후속이다.
책임 범위는 P1-HBR-01의 격리 복구 준비다. `scripts/bootstrap/harbor_recovery_bootstrap.py`를
추가했고 실제 게스트에는 설치/실행하지 않았다. 상주 실행·unit 등록/enable/start·graceful stop·
일반 장애 reconciliation·현장 Plan 생성은 계속 잔여다.

## 실행 전에 검증하는 범위

기존 bundle 라이브러리는 Python import 이후 입력과 source pin을 검증했다. 이번 진입점은
프로젝트 모듈을 import하기 전에 외부에서 받은 bundle SHA-256·context와 root 파일 메타데이터를
대조하고, 그 bundle이 지정한 9개 source의 정확한 바이트를 모두 읽어 검증한다. 전부 해시/구문
검사를 통과해야 import를 시작한다. 하나라도 실패하면 후보 모듈을 실행하지 않는다.

검증한 바이트를 메모리에서 compile/import하며 파일 경로를 다시 열어 코드를 실행하지 않는다.
대상 namespace에 이미 로드된 모듈, 미등록 `harbor_recovery_*` import, reload를 거부한다.
프로젝트 경로를 `sys.path`에 추가하지 않고 `.pyc`도 사용/생성하지 않는다. 실행 입력은 이후
기존 bundle 로더의 전체 schema/Plan/execution binding 검사와 실제 관측 전후 검사도 받는다.

파일 판독은 Linux fd/nofollow, 상위 경로 소유/쓰기/ACL, 파일 단일 link·정확한 mode/gid·context·
xattr·크기·해시·읽기 전후 메타데이터를 대조한다. JSON은 최대8MiB, 각 source는1MiB다.
bundle은 source 수집 전후 동일 바이트인지 다시 확인한다. 오류를 고치려고 파일 권한·label을
변경하거나 현재 파일의 해시를 새 승인값으로 채택하지 않는다.

**남는 신뢰 기반:** bootstrap 파일 자체, Python 실행 파일·표준 라이브러리·동적 라이브러리는
별도로 검토해 신뢰된 경로에 설치해야 한다. 자기 코드를 실행한 뒤 자기 해시를 확인하는 것으로
그 신뢰를 대체하지 않는다. 다른 root 작성자를 완전히 차단하는 보안 경계도 아니다.
이번 CLI는 bootstrap 설치나 OS/Python 변경을 수행하지 않는다.

## 환경과 호출 계약

- 실제 실행 환경: 승인된 대상 Linux, Python3.10 이상, euid/egid0, 보호된 bundle/코드/상태 경로.
  현재 게스트의 Python 호환성을 확인하거나 새 버전을 설치한 것은 아니다.
- Python은 `-I -S -B`로 시작하고 최적화 옵션은 사용하지 않는다. 옵션이 틀리면 argparse/json
  같은 표준 모듈을 import하기 전 중단한다. `-I`는 환경·사용자/스크립트 경로 유입을 줄이고,
  `-S`는 site 초기화, `-B`는 bytecode 파일 쓰기를 막는다.
  [Python 실행 옵션](https://docs.python.org/3/using/cmdline.html)과
  [importlib loader 계약](https://docs.python.org/3/library/importlib.html)을 따른다.
- `--bundle`, `--sha256`, `--context`, `--timeout`을 모두 명시한다. 시간값은 유한한0초 초과
  600초 이하이며 회차의 검토된 예산을 전달한다. 600초는 코드 입력 상한이며 현장 성공 예산이 아니다.
- `verify` 외에는 `--execute`가 추가로 필요하다. 이는 오입력 방지이며 사람의 Runtime 승인 증명이
  아니다. 코드 리뷰/회차 GO/콘솔 복구·비중첩은 기존 절차로 확인한다.

호출 형식만 표시한다. 아래 placeholder를 임의 관측값으로 채워 실행하지 않는다.

```text
<검토된 Python> -I -S -B <신뢰된 bootstrap.py> <operation>
  --bundle <승인 JSON 경로> --sha256 <외부 승인 SHA256>
  --context <승인 context> --timeout <검토된 초> [--execute]
```

## 개별 명령과 정상 판정

| operation | 수행 / 성공 표기 |
|---|---|
| `verify` | 입력·코드 검증만. builder/Store/Engine 관측 미호출. `INPUT_SOURCE_VERIFIED`, Runtime NOT_RUN |
| `initialize` | fresh 대상/격리/입력/원 정책/전체 healthy·disabled manager 확인 후 새 Store 초기화. `INITIAL_HOLD_CREATED` |
| `policy-install` | 기존9개 policy 전환·readback. `INSTALLED_HOLD`만 rc0. 자동 arm/서비스 시작 없음 |
| `arm` | 완료 journal·동일 세대·healthy·비활성 manager를 재확인하고 최초 RUN 저장. `INITIAL_ARMED`; 컨테이너/unit 시작 아님 |
| `hold` | Executor resume/open 후 운영자 HOLD를 audit/저장. `OPERATOR_HOLD`; 컨테이너 stop·프로세스 종료 아님 |
| `policy-rollback` | 이미 HOLD인 상태에서 확정된 변경만 역순 원복. `ROLLED_BACK`만 rc0 |

`initialize`도 읽기 전용 명령은 아니다. 사전 관측을 통과해야 lock/state 파일을 만들며, 기존
기록이 있으면 초기화하지 않는다. 바로 뒤 policy-install은 자체 fresh 관측을 다시 한다.
하나의 명령이 다음 명령을 자동 호출하지 않는다. install 성공 뒤에는 앱9개 policy가 `no`인
유지보수 구간이므로 활성화·서비스 인수 또는 명시적 원복까지 포함한 현장 계획이 필요하다.

종료코드0은 위 명령의 한 단계 성공만 뜻한다. `verify`나 `arm` 성공을 AUTOSTART/서비스 설치
완료로 해석하지 않는다. 정책 transaction이 HOLD로 반환해도 명령을 오류(rc2)로 보고한다.
입력/권한/전송/저장 오류는 STOP·rc2, 사용자 인터럽트는130이다. 출력에는 고정 단계·사유 코드와
필요한 source/bundle 식별만 남기며 예외 원문·Compose/Engine 원문·환경정보를 노출하지 않는다.
argparse 사용 오류는 help/rc2로 끝나고 프로젝트 모듈을 로드하지 않는다.

## 중단·복구

- 실패하면 같은 변경 명령을 맹목적으로 재실행하지 않는다. 기존 intent/claim/journal/`.pending`
  및 원본 증적을 보존한다. CLI는 임시파일을 지우거나 상태를 초기화하지 않는다.
- `hold`는 이미 전송한 Docker 요청을 취소하지 않는다. 기존 lock이 busy이면 오류로 종료한다.
  deadline은 새 동작·관측의 예산이며 커널 fsync나 이미 전송한 요청의 강제 취소 약속이 아니다.
- policy-install/arm 실패 뒤 자동 rollback·start·Docker restart를 실행하지 않는다. 원복은
  기존 조건(확정된 변경, pending 없음, 동일 세대, 건강 상태, manager 중지, HOLD)에서만
  별도 `policy-rollback`으로 요청한다. 조건이 맞지 않으면 복구 판단으로 넘기고 원문을 유지한다.
- `hold`/원복도 승인 입력이나 저장소가 손상되면 실패한다. 무검증 우회나 강제 정리 명령은 없다.
  현장 콘솔 인수와 손상 증적 해석 절차는 별도 실행안에 포함해야 한다.

## 검증과 남은 연결

`python3 -B -m unittest discover -s tests/recovery-core -v`

시험은 모듈 실행 전 전체 검증 실패, 후속 경로 변경과 무관한 검증 바이트 로딩, namespace 주입,
명령별 호출/실행 표시, deadline, 오류 출력 제한, 상태 생성 전 host/policy gate를 확인한다.
Linux CI는 실제 fd/파일·mode·hardlink/symlink/FIFO·변경 감지를 시험한다. xattr/SELinux 값은
합성이며 실제 enforcing SELinux나 Harbor 서비스 시험이 아니다.

남은 순서: bootstrap/코드/입력의 검토된 설치 → 명시적 상주 실행·unit 수명주기와 graceful stop →
일반 HOLD reconciliation → 현장 입력/실측 예산·원복점 → 허용된 격리 자동복구·로그 저장 시험.
unit이 bundle 해시를 포함하고 bundle이 unit 해시를 포함하는 순환 pin을 만들지 않도록 후속 설치
입력 구조를 검토해야 한다. 이번에는 실행용 unit을 발행하지 않는다.
