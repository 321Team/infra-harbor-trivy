# Harbor 주소 변경: r2 실패 후 코드 수정 계약

CODEX_ASSISTED. 이 문서는 코드와 입력 명세이며 실제 실행 package, 신규 작업창 또는 Runtime 승인이 아니다. 기존 r2 원본/사용 claim/부분 객체/복구 기록은 보존한다. MON 우선 현장 회차와 병렬로 가능한 작업은 로컬 수정·시험·리뷰뿐이다.

## 재현 원인과 수정

| 실제 관측 | 코드 수정 | 남는 한계 |
|---|---|---|
| 조회 20초가 DB 재생성 전체 기한에도 적용됐다. 클라이언트 종료 뒤 DB가 늦게 정상 종료됐다. | maintenance.v2는 `recreate_seconds`를 앱별로 필수 입력받고 조회 `io_seconds`와 분리한다. 건강 대기는 성공 응답 후 시작한다. 각 단계는 기존 절대 변경 종료시각을 넘지 못한다. | 시간 증가는 smart shutdown 완료를 보장하지 않는다. 활성 연결이 계속되면 종료도 계속 대기할 수 있다. |
| 정상 endpoint 교체가 veth 경로 전체 해시를 바꿨다. | host.v3는 Docker network ID·정확한 10개 endpoint·PID namespace·MAC·양쪽 ifindex/link_index·bridge 소속이 모두 일치한 veth의 정확한 커널 link-local 경로 3종만 동적값으로 취급한다. | 이름/개수/bridge만 같다는 이유로 제외하지 않는다. 알 수 없는 경로·추가 endpoint·추가 bridge member는 중단한다. |
| network IPAM 사용량이 구성으로 비교됐다. | `Status.IPAM.Subnets`의 정수 `IPsInUse`, `DynamicIPsAvailable` 값만 정규화한다. | subnet, counter 존재 여부, driver, ID, IPAM 설정, 옵션, 알 수 없는 필드는 계속 비교한다. |

DB 종료 전략 입력은 `db_shutdown = {strategy: preserve-smart, effective_signal: SIGTERM, on_timeout: stop-and-handoff-no-retry}`다. 실제 baseline 및 실행 model의 유효 signal과 대조한다. 자동 SIGINT/SIGKILL 전환, 연결 강제 종료, DB 의존 서비스 선행 정지, 자동 복구를 추가하지 않는다. PostgreSQL의 smart shutdown은 기존 연결 종료를 기다린다([공식 문서](https://www.postgresql.org/docs/14/server-shutdown.html)).

## 새 실제 입력에서 확인할 항목

기존 예산을 재해석하거나 숫자를 자동 채우지 않는다. `recreate_seconds` 9개, DB 종료 전략, 전체 변경/수집/종료 예산의 관계를 실제 실행안에서 검토한다. 새 budget이 있어도 총 상한은 늘어나지 않는다. 지속 연결이 있는 환경은 검증된 연결 종료 절차 또는 별도 종료 전략이 확보되지 않으면 성공을 약속할 수 없다. 이 PR은 그 정책을 결정하지 않는다.

host.v3는 기존 host.v2 필드에 `network_scope`(정확 network 이름 → `{id, bridge}`)와 `tools.nsenter`(실제 경로·mode·SELinux·SHA256)를 추가한다. network digest는 `network_projection`, route digest는 검증된 endpoint의 `route_projection`으로 계산한다. 새 module `harbor_address_network`를 source manifest와 bootstrap 허용 목록에 포함한다. 실제 관측에서 확보하지 않은 값은 생성하지 않는다.

namespace 조회는 pinned host `nsenter`와 `ip`만 사용하고 읽는 동안 namespace fd를 고정한다. 부모 프로세스와 host namespace를 변경하지 않고 자식만 대상 network namespace에서 link를 조회한다. 실제 OS/SELinux/systemd 환경에서 이 읽기 경로의 허용 여부와 조회 예산은 적용 전 확인해야 한다. 보안 통제를 완화해 통과시키지 않는다.

old maintenance.v1 및 host.v1/v2의 순수 검증/과거 증적 해석은 보존하지만 새 `ProtectedSession`은 maintenance.v2만 허용한다. 이전 source/launch/package를 새 입력으로 덮어쓰지 않는다. 과거 증적은 해당 버전의 고정 source와 inspect 경로로 확인한다. 새 경로·source pin·package·launch·unit의 정확한 결속은 별도 실행 준비 항목이다.

## 적용 순서와 중단·복구

1. 코드·Linux CI·동일 담당자 독립 리뷰를 완료한다. 이는 적용/병합 완료를 뜻하지 않는다.
2. Harbor 현장 회차 재개 시 MON 실제 종료/비중첩과 현재 세대·전체 10개 상태를 확인한다. r2가 남긴 미기동 DB 때문에 정확 service 집합이 11개이면 변경 전 거부한다. 별도 검토·허용 없이 삭제하거나 선택에서 숨기지 않는다.
3. 실제 새 입력과 DB 연결 종료 가능성/중단 후 복구안을 함께 검토한다. 새 준비 경로에서 서비스 실행 환경의 저장소·label, protected input, actual Compose render, 새 network 조회를 검증한다. 예산/실제값 누락 시 앱 변경 전 중단한다.
4. 승인 범위의 새 단회 실행만 시작한다. 성공 판정은 새 ID·주소·전체 보존·건강·증적의 모두 일치이며 H6/worker/E2E/AC는 별도다.
5. CLI timeout, 늦은 응답, 불명확 결과는 `STOP_RECOVERY_REQUIRED`와 `daemon_effects_may_continue=true`로 인계한다. 호출 종료 또는 healthy 첫 관측을 Docker 작업 취소/무변경 증거로 보지 않는다. 다음 앱 및 자동 재시도 없이 원본·claim·부분 상태를 보존한다. 후속 실제 읽기/복구 범위는 해당 실행안과 사용자 허용에 따른다.

## 검증 범위

- STATIC/MOCK: v2 예산 경계, 성공 응답 이후 건강 대기, 절대 기한, 늦은 daemon 효과와 사용 claim 재실행 거부, 읽기 기한, 기존 입력 거부, network/route 양성·음성 경로.
- CI: 기존 전체 회귀 및 실제 systemd 시험을 유지한다. disposable Ubuntu runner에서 실제 bridge/veth/netns와 pinned peer 조회·커널 route 비교, 전용 PostgreSQL16 cluster의 활성 연결 → smart stop 요청 → 클라이언트 timeout → 연결 종료 후 DB 정상 종료를 시험한다.
- Linux 시험값은 합성 시험 자극이다. systemd/SELinux 일부 대역, PostgreSQL16, Docker 없는 분리 시험은 운영 Harbor의 Docker29/Compose5.6/PostgreSQL14 통합 리허설을 대신하지 않는다.
- RUNTIME/AC: 이 수정 회차는 Harbor 현장 미실행이다. 전체 리허설/실제 입력 대조가 남으며 코드·CI·리뷰 PASS를 Runtime 무결함 보장으로 표현하지 않는다.
