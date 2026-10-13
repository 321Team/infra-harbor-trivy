# DB 보존 후 잔여 8개 주소 변경 계약

CODEX_ASSISTED. 코드·입력 계약이며 실제 실행 package/승인 또는 Runtime 성공 증적이 아니다.
PR55 r3에서 DB 재생성만 rc0로 끝난 뒤 보존 비교가 중단된 사례를 대상으로 한다.
PR57의 생성 메타데이터/DNS 비교 수정 위에 연결한다. 원래 실패 결과는 그대로 보존한다.

## 범위

- 새 plan schema: `fds.harbor.production-address-db-preserved.v1`.
- 고정 순서: redis → registry → registryctl → core → portal → jobservice → trivy-adapter → proxy.
- 새 DB와 log는 변경하지 않는다. 정확 10개 inventory, 전체 Config/HostConfig·mount·network와
  건강 상태를 계속 확인한다. DB의 PID·StartedAt·FinishedAt·RestartCount 변경도 중단 조건이다.
- 기존 9개 schema는 유지한다. 임의 부분집합, 자동 resume, 이미 바뀐 앱 재호출은 지원하지 않는다.
- manager 설치, restart 정책 변경, H6/자동복구 시험, Push/Pull/E2E, AC는 별도 잔여다.

## 새 실제 입력 준비

실행자는 기존 승인 범위·현재 비중첩을 확인하고, 실제 운영 상태를 읽어 새 7파일 package를 준비한다.
boot/작업 시각/경로/context/해시/labels는 관측·확정된 실제 값만 사용한다. 이 문서에는 기본값이 없다.

1. plan baseline은 새 DB ID·새 syslog 주소와 나머지8개 기존 ID·옛 주소를 담는다.
   DB/log 포함10개 모두 running/healthy여야 한다. health_seconds/recreate_seconds 키는 정확8개다.
   `db_shutdown`, 사용자 order/skip 목록, DB 예산은 허용하지 않는다.
2. base는 이전 고정 base의 DB syslog 주소만 이미 적용된 새 값으로 반영한다.
   candidate는 이 base에서8개 logging 주소만 변경한다. DB/log 정의와 그 외 값은 보존한다.
   model은 기존 external 자원·legacy bind 변환을 적용한다. 원 Compose/env 파일을 덮어쓰지 않는다.
3. preservation의 after_labels/auto_hostnames/auto_addresses/after_host_mounts는8개 범위다.
   DB의 생성 메타데이터나 동적 주소를 다시 허용하지 않는다. 모든 단일앱 depends_on 라벨은 빈 값이다.
4. host.v3·mount profile·원본/도구/source 핀·보호 설정은 현재 실제 관측으로 대조한다.
   신규 모듈 `harbor_address_continuation`도 bootstrap/launch/source 핀에 포함한다.
5. `prior_execution`은 아래 **외부에서 검토한 핀**으로 원본을 참조한다. 해시는 권한을 부여하지 않는다.

| 필드 | 계약 |
|---|---|
| package | path·sha256(manifest bytes)·context |
| launch | path·sha256(파일 bytes)·context |
| dispatch | path·sha256(기존 dispatch claim bytes)·context |
| evidence | path(디렉터리)·sha256(evidence.closed bytes)·context |
| plan_sha256 / source_revision | 이전 plan의 canonical SHA256 / 이전 launch의 source HEAD |
| sequence_record / database_record | 실제 sealed 기록의 정수 인덱스. 새 DB inspect는 sequence 결과 이후 |

ProtectedSession의 preflight/ready/apply 공통 생성 단계에서 기존 package 무결성·launch 연결·dispatch 핀,
sealed 전체 체인/파일을 읽기 검증한다. 정확 DB1개 PROCESS_INTENT·rc0/COMPLETED와
STOP_RECOVERY_REQUIRED/IO_OR_ADAPTER_FAILURE, claimed/entered=DB·healthy=[] 결과만 허용한다.
기존 DB inspect의 실제 새 ID/전체 보존 필드와 새 baseline을 대조하며, 나머지9개는 이전 baseline과 연결한다.
rc0 직후 수집한 봉인 DB inspect는 running/starting 또는 running/healthy를 허용한다.
starting은 당시 관측 사실로 보존하며 성공으로 고치지 않는다. 현재 baseline은 running/healthy·exit0·Error 빈 값이어야 한다.
두 관측의 ID·전체 설정·mount/network·PID·StartedAt·FinishedAt·RestartCount는 그대로 일치해야 한다.
과거 unhealthy/정지/오류, 현재 starting/unhealthy, 같은 ID의 재시작은 계속 거부한다.
DB 생성 라벨 depends_on 수정만 명시 반영하고 PR57의 DNS 정규화를 사용한다.
동일 host/boot·docker/guard 세대가 요구된다. 다른 세대 또는 다른 부분 결과는 새 설계·검토가 필요하다.

새 package/journal/evidence/private 경로는 이전 입력·증적·journal/private와 같거나 상하위이면 거부한다.
사용된 claim을 삭제하거나 재사용하지 않는다. 새 plan hash에 결속된 Journal/Transport만 고정8개 순서를 허용한다.
오프라인 journal 조회 시에도 검증한 plan schema에서 `order=ORDER[1:]`를 선택해야 한다.
기존 9개 조회의 기본 계약은 변경하지 않는다.

## 실행 순서와 중단

정확 source와 실제 package를 독립 리뷰한 뒤 기존 trusted bootstrap의 verify → preflight →
unit 설치/ready → 새1회 apply 절차를 사용한다. 각 단계의 구체 경로·작업 시각은 별도 실제 실행 카드에 기록한다.
별도 총예산을 늘리지 않으며 이미 확정한 예산만 실제 launch에 결속한다.

각 앱은 새 durable intent → fresh 전체 상태 대조 → 단일앱 no-deps 재생성 최대1회 →
rc0/전체 보존/10개 healthy·network ready 순으로 다음 앱에 진입한다. 성공 결과는 이번8개만 보고한다.
DB/log 상태 변화, 경로·세대·설정 불일치, 읽기/증적 오류, timeout/결과 불명 시 다음 변경을 중단한다.
claim/부분 상태/원본을 보존하며 자동 재시도·start/stop/delete·강제 연결 종료·snapshot 복원은 없다.
실패 후 실제 살아 있는 ID와 상태를 읽고 그 시점의 최소 복구안을 판단한다.

## 검증의 한계

정적·모의·Linux CI의 파일/journal/evidence 통합 검증은 실제 Docker29/Compose5.6 운영 실행이나 AC가 아니다.
prior 증적은 새 claim 전 읽기 검증하며, 실행 중에는 새 고정 package와 현재10개/host 보존을 지속 확인한다.
독립 root 쓰기 주체에 대한 원자적 잠금이나 Docker가 수락한 작업의 취소를 보장하지 않는다.
삭제된 이전 앱 ID의 수집 실패는 READ_INCOMPLETE로 남기며 전체 인수 성공으로 바꾸지 않는다.
