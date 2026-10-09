# Harbor 단일 기동 주체 후보 — 설계 검토용

CODEX_ASSISTED · 2026-10-09 KST. 상태: **후보 제어 코어 구현·모의검증 / 현장 적용 미수행**.
책임 티켓 [P1-HBR-01 #13](https://github.com/321Team/fds-project-baseline/issues/13),
Lead 이하영, Support 이권욱. 이 문서는 승인 정본이나 실행 설정이 아니다.

**2026-10-09 사용자 인수·진행 결정:** 사용자는 자동복구까지 본인이 인수한 작업이며
복구하기로 결정된 안이므로 별도 Lead 결정이 필요하지 않다고 명시했다. 따라서 이전의
“Lead 결정 대기/구현 GO 대기”를 후속 구현의 선행조건으로 사용하지 않는다.
Phase 1 코드 작성·모의검증을 진행하며, [제어 코어](harbor-recovery-core.md)를 구현했다.
운영 정책의 현장 적합성은 검증 대상으로 남으며 최신 구현 단계는 이 기록과 코드 PR을 따른다.
특정 시간값의 현장 적합성, 코드 독립 리뷰, 실제 설치·시험·인수 완료는 별도로 검증한다.

## Phase 1 인수 전 복구 범위 — 2026-10-09 사용자 확인

현재 프로젝트 단계는 **Phase 1 인수 전**이다. 이 후보의 자동기동·자동복구는
Phase 1 Harbor 복구 및 인수 준비 범위다. 일회 수동 복구가 완료됐다는 이유로
자동복구 보완을 현재 작업에서 제외하지 않는다. 이는 기존 P1 범위 확인이며
신규 AC 발행, 설계 채택, 특정 정책/예산 확정 또는 Runtime 실행 GO가 아니다.

| 구분 | 이번 작업에 적용할 경계 |
|---|---|
| 범위 내 | 원 A3 실패/일회 복구 원본 보존, P1 기동 경쟁 보완, 실패·중단·원복, 기존 P1 보안/로그 설정 보존, 승인된 회차의 자동복구·로그 저장 검증과 결과 인수 |
| 범위 밖 | Phase 2 사전작업, ROSA 연계, P2 source allowlist/전용 principal·Robot, D22 선택, P2 cold-pull 및 해당 환경 구축 |
| 완료 판정 | 기존 P1 요구사항/AC와 허용된 시험 범위로 판단. P2 입력·승인·시험을 P1 복구 선행조건이나 완료조건으로 추가하지 않음 |

**조회·작업 기록 선별 기준:** baseline #13의 최신 댓글이라는 이유만으로 복구 입력으로
채택하지 않는다. 출처의 대상 Phase·책임 범위·대상 환경·승인 행위를 먼저 확인한다.
P2 인계는 존재 여부만 별도 업무로 구분하며 이 복구의 backlog·PR·정책·실행 번들에
반영하지 않는다. 복구 PR에는 P1 변경·근거·검증·잔여를 명시하고 범위 밖 요청은
해당 업무에 남긴다. 타 담당자의 P2 인계 원문을 삭제하거나 이 작업의 승인으로 바꾸지 않는다.

일회 복구/증적 #191 완료와 자동복구 후보의 상태는 분리한다. 범위 내 잔여는
코드·모의검증·독립 리뷰 → 이어진 작업창/복구점/원문 보존 확인 →
허용된 P1 격리 자동복구·실패·원복·로그 저장 시험 → 증적 및 P1 관련 결과 판단이다.
각 단계의 승인·시험 결과는 별도로 기록하며, P1 프로젝트 전체 인수 완료로 확대하지 않는다.
현재 단일 관리자 후보는 위 사용자 인수·진행 결정에 따라 구현한다. §7의 과거 결정 요청을
추가 승인 대기로 재사용하지 않는다.

## 1. 결론과 근거

권장 후보는 **logger는 Docker가, 앱 9개는 전용 호스트 관리자가 담당**하도록
컨테이너별 기동 주체를 분리하는 것이다. 앱 9개의 Docker restart policy는 `no`로
전환하고 관리자만 시작·재기동 의도를 발행한다. logger의 현행 정책·로그 경로와
Docker 앞의 AC04 guard는 유지한다. 같은 앱에 `always`와 관리자를 동시에 두지 않는다.

이 방식은 현재 정책을 바꾸므로 A2/A3의 보존 계약 안에서 실행할 수 없다.
새 후보 회차에서 정책 변경·실패 동작·복구를 검토하며, 기존 A3 실패를 소급 통과시키지 않는다.
당일 작업창 17:00 연장은 일회 복구 작업의 합의이며 영구 설치·새 재부팅 시험 승인으로
확대하지 않는다. 이후 사용자가 작업창 연속 진행을 허용했다. 고정 종료시각을 새로 만들거나
과거 만료 번들을 재사용하지 않으며 검증된 코드·원복 절차로 후속 단계를 진행한다.

확인한 자료:

| 원본 | 확인 사실 / 한계 |
|---|---|
| [A3 증적 #171](https://github.com/321Team/fds-project-evidence/pull/171) | Docker restart rc0 이후 앱 9개가 IPv4 syslog 연결 거부로 실패. logger가 나중에 healthy여도 이미 실패한 앱의 기동 성공을 보장하지 않음 |
| [복구 소스 #26](https://github.com/321Team/infra-harbor-trivy/pull/26) | 승인 HEAD `07a1f8d4a087657cba9e7a0ba49b7c3a489c02aa`, merge `a7a005eaecd5aab359d7f4118cdb448582d8e301`; 제한된 일회 start이며 영구 관리자 아님 |
| [복구 증적 #191](https://github.com/321Team/fds-project-evidence/pull/191) | 2026-10-09 14:59:04~15:03:44 KST, 앱 9개 각 1회 start, 종료 시 10개 running/healthy; AUTOSTART/SYSLOG_INGESTION 미시험 |

복구 증적의 내용 기준 커밋은 `e1f6786975b8440f952c2126a0811b050546180a`다.
증적 #191은 2026-10-09 15:56:29 KST 병합됐다. 이후 참조는
[병합본 수집회차](https://github.com/321Team/fds-project-evidence/tree/0e4120a3163b00b85f16c44a84030ad303b86627/evidence/P1-HBR-01/clone-app-recovery-20261009)를
사용한다. 병합된 main의 커밋을 고정한 링크이며, 증적 편입을 설계 채택으로 해석하지 않는다.
동일 수신본의 Engine 29.8.0, Compose 5.5.1은 시험 호환성 입력이며 새 버전 채택 결정이 아니다.
수동 복구 성공은 **준비된 logger 뒤에서 앱을 시작하는 경로가 해당 회차에 성공**했다는
근거다. 관리자 장애·새 boot·daemon restart·로그 저장을 검증한 것은 아니다.

공식 자료와 해석:

- [Docker restart policy](https://docs.docker.com/engine/containers/start-containers-automatically/):
  Docker는 restart policy 사용을 권장하고 같은 컨테이너에 호스트 관리자를 중첩하지 말라고
  경고한다. `no`는 자동 재시작하지 않으므로 이를 선택하면 장애 후 재기동 책임까지 대체해야 한다.
- [Compose startup order](https://docs.docker.com/compose/how-tos/startup-order/):
  `service_healthy`는 Compose 기동 경로의 의존성 대기에 쓰인다. 따라서 이 문서는
  Compose를 호출하지 않는 daemon 자동 복구를 `depends_on`만으로 고쳤다고 판단하지 않는다.
- [Docker syslog driver](https://docs.docker.com/engine/logging/drivers/syslog/):
  현행 TCP syslog 목적지를 유지한다. UDP·다른 driver·전달 mode 변경은 후보 범위 밖이다.

## 2. 대안과 선택 조건

| 대안 | 판단 |
|---|---|
| `sleep` 또는 Compose depends_on만 추가 | daemon 경로의 기동 책임·실패 후 재시작을 해결하지 못하므로 제외 |
| 앱 `always` 유지 + 실패 앱 start 보정 서비스 | 이중 관리자 및 수동 stop 오인 위험이 있어 제외 |
| TCP logger를 Docker 밖으로 이전 | 앱 Docker policy를 유지할 대안. 로그 배치·보존·권한·SELinux·기존 Harbor log 경로 변경을 별도로 수용할 경우 재검토 |
| 앱의 단일 호스트 관리자 | 현 logger와 syslog 경로를 유지하는 우선 후보. 아래 수명주기 계약과 실패 시험을 충족할 때만 채택 |

이는 가장 적은 코드라는 뜻이 아니다. 전체 장애 수명주기를 구현·유지할 비용을 작업 책임자가
수용하지 못하면 logger 외부화 대안을 다시 비교한다. 준비 환경 확장을 위해 SSH/NIC나
새 VM을 먼저 만들지 않고, 기존 수신 자료로 계약과 로컬 모의검증을 먼저 완성한다.

## 3. 변경·보존 경계

| 대상 | 후보 변경 |
|---|---|
| 앱 9개 | postgresql, redis, registry, registryctl, core, portal, jobservice, trivy-adapter, proxy의 restart policy만 `no`로 변경 |
| Compose 생성 경로 | 원본 + 기존 loopback override + 새 policy override를 명시적으로 소비하는 단일 운영 경로. 관리자는 create/up/pull을 수행하지 않음 |
| 호스트 | 전용 관리자·지속 상태·배타 lock·unit 및 명시적인 운영 인터페이스 추가. 아직 파일명/unit 설정은 미구현 |
| logger | 기존 ID·이미지·restart policy·볼륨·로그 저장·전송 설정 유지, 관리자에서 start/stop/restart하지 않음 |
| 보존 대상 | 앱 ID·이미지·볼륨·TLS·포트·logging·SELinux Enforcing·AC04 guard/allowlist·원 A3/복구 claim과 증적 |

기존 컨테이너 policy만 바꾸는 경로를 우선 구현한다. Compose override가 있다는 사실만으로
현 컨테이너 변경을 주장하지 않는다. compose prepare 또는 재생성 후 policy가 `always`로
돌아오면 관리자는 시작을 거부하고 drift를 보고한다. 재생성·업그레이드·새 ID 등록은
별도 유지보수 동작이며 자동으로 새 ID를 승인하지 않는다.

관리자는 root 소유·타 사용자 쓰기 금지의 고정 실행 입력만 읽고 정확한 ID로 동작한다.
Docker 소켓은 사실상 높은 권한이므로 임의 명령·shell 보간·자유 형식 경로를 입력받지 않는다.
lock은 한 관리자만 허용하고, state/intent/결과는 원자 저장 및 fsync하며 비밀정보는 제외한다.
다른 root 세션의 직접 변경을 기술적으로 완전히 차단했다고 주장하지 않는다.

## 4. 기동·장애 수명주기 계약 (모두 제안)

지속 상태에는 desired state(RUN/HOLD), 버전·ID·구성 해시, 마지막 boot/daemon 실행 ID,
작업 intent/결과, 재시도 예산과 실패 사유를 기록한다. 최초 설치값은 HOLD다.
새 boot에서도 수동 HOLD를 지우지 않는다. 승인된 RUN 상태에서만 자동기동 경로가 열린다.

| 상황 | 필수 동작과 중단 기준 |
|---|---|
| 최초 활성화 / RUN 상태 새 boot | Docker active, AC04 guard active 및 Requires/After, SELinux, 정확한 ID·구성·policy를 확인. logger healthy와 `127.0.0.1:1514` TCP 준비 뒤 정해진 순서로 앱 시작 |
| 시작 순서 | postgresql → redis → registry → registryctl → core → portal → jobservice → trivy-adapter → proxy. 각 앱 healthy 후 다음 단계로 이동 |
| logger 미준비 | 유한 대기 후 FAILED/HOLD. 새 앱 start 0회, Docker/logger 재시작 반복 금지 |
| start timeout / 결과 미확인 | intent를 보존하고 추가 start 금지. 서버 작업 취소로 해석하지 않음. 조회로 상태를 확정할 때까지 재시도 금지 |
| 시작된 앱의 정상·비정상 exit | desired RUN, 완료된 이전 intent, 동일한 구성, logger 준비 확인 후 제한된 재기동. exit 0도 대상. 예산 초과 시 HOLD |
| healthy → unhealthy, 프로세스 실행 중 | 현재 always가 health만으로 복구하는 것처럼 가정하지 않음. 자동 kill/recreate 대신 degraded 경보와 후속 기동 중단; 운영자 판단 |
| logger가 실행 중 소실 | 새 start 차단·degraded 기록. 실행 중 앱을 일괄 stop하지 않음. 기존 앱 로그 손실/블로킹 및 재연결 동작은 별도 시험에서 확인 |
| 명시적 전체 stop | HOLD를 먼저 영속화하고 신규 start 차단 후 역순으로 graceful stop. stop 실패·timeout은 기록하고 자동 kill/삭제 금지. 재부팅 후에도 HOLD 유지 |
| 관리자 프로세스 장애 | 앱을 일괄 중지하지 않음. 관리자 재기동 시 로그/실제 상태를 대조. 미완료 intent·이벤트 유실·외부 stop 여부가 불명확하면 HOLD; 불명확한 start 반복 금지 |
| Docker 중단·재시작 | 불통 중 새 명령 금지. 이전 unit 소멸을 인지하고 새 InvocationID를 별도 세대로 기록. RUN이면 전체 gate부터 다시 시작, HOLD면 유지. 이전 세대 미확인 intent는 재사용 금지 |
| 외부 직접 stop/update/recreate | 관리자 명령 밖의 관리 변경은 지원 경로가 아님. 확인되는 drift는 HOLD. 정상 exit와 직접 stop을 구분하지 못하는 경우 자동 재시작이 수동 의도를 되돌릴 수 있으므로 운영 인터페이스 사용을 채택 조건으로 명시 |

대기·재기동 예산 제안: 개별 API 조회 20초, start 60초, logger 준비 120초,
앱 healthy 60초, 한 번의 전체 기동 900초. 앱 exit 재기동은 앱별 300초 동안 최대 3회,
최소 5초 간격으로 제한한다. 대기 전체에 monotonic deadline을 쓰며 자식 명령의 남은
시간을 제한한다. 예산과 HOLD는 관리자 재시작으로 초기화하지 않는다. 이전 boot에서
진행 중이던 재시도 제한 구간이나 미완료 intent가 있으면, 새 boot에서 남은 예산을
안전하게 결속할 수 없을 때 HOLD한다. 완료된 정상 회차의 RUN은 새 boot에서 새 기동 회차로
진행할 수 있지만, 이전 HOLD나 실패 예산 소진을 새 회차로 우회하지 않는다.

이 예산은 기존 `always`와 동등하지 않은 **새 제안**이다. 후보 코드/모의시험 입력과
현장 확정값을 구분하고 유한 재기동·unhealthy·수동 stop·logger 소실 동작을 검증한다. 격리시험별 일회 claim과
상주 관리자 상태는 분리하며 A3/일회 복구 코드를 상주 서비스로 재사용하지 않는다.

## 5. 설치 전환과 원복 계약

실제 실행 자료는 다음 코드 PR에서 정확한 파일·명령·해시·계정·경로·회차와 함께 작성한다.
아래는 실행 명령이 아니라 구현해야 할 transaction 순서다.

1. 기존 실행/복구 원문, 현재 RUN 상태와 ID·policy·Compose·unit 해시를 보존한다.
   과거 A2 snapshot을 현재 복구 상태의 백업으로 사용하지 않는다. 원복 자료와 현재 복구점의
   확보·검수 없이 daemon restart/VM boot 시험을 시작하지 않는다.
2. 다른 변경 세션이 없는 유지보수 상태에서 관리자를 **disabled/HOLD**로 준비한다.
   승인된 불변 필드 및 복구 baseline과 다르면 적용 전 중단한다.
3. 앱 9개의 기존 policy를 journal에 기록한 뒤 각각 변경하고 재조회한다.
   일부만 변경된 상태에서 관리자 활성화 금지. 실패 시 변경 완료 ID만 원 policy로 복원하고
   검증한다. 불통으로 원복이 불확실하면 그대로 HOLD·부분 결과를 남긴다.
4. Compose override를 포함한 유일한 운영 경로와 실제 policy 9개를 함께 검증한 뒤에만
   명시적인 RUN 전환을 허용한다. 이미 healthy인 앱을 불필요하게 재시작하지 않는다.
5. 원복 시 먼저 HOLD 저장, 관리자 신규 intent 차단 및 정지 확인 후 원 policy/파일을 복원한다.
   manager와 `always`가 동시에 동작하는 구간을 만들지 않는다. 기존 앱은 무조건 stop하지 않으며
   데이터·컨테이너·볼륨을 삭제하거나 과거 snapshot으로 자동 되돌리지 않는다.
6. 원복은 정책 원상복구일 뿐 A3의 기동 경쟁 해결이 아니다. 원복 직후 Docker/VM 재시작으로
   성공을 가정하지 않는다. 결과가 불확실하면 재시도 없이 증적 회수와 새 복구 판단으로 종료한다.

## 6. 최소 시험과 완료 판정

| 단계 | 필수 확인 | 완료 의미 |
|---|---|---|
| STATIC/MOCK | 단일 owner, 설치 부분 실패/원복, intent 배타성, logger 지연, start timeout 후 뒤늦은 성공, 모든 exit/health/수동 HOLD/프로세스 장애/daemon 세대 전환/예산 경로 | 구현 계약 검증, 실제 Harbor PASS 아님 |
| 격리 정상 | 고정 baseline → 후보 policy 확인 → 승인된 Docker restart 1회 → 로그 준비 뒤 앱 시작 → 10 healthy·ID/구성 보존 | 해당 restart 회차만 검증 |
| 격리 음성 | logger 미준비를 별도 승인 방식으로 주입, start 0/유한 종료/원인 보존, gate 복원 후 명시적 재개 | 실패 시 시작 차단 검증 |
| 관리자·앱 실패 | 정상/비정상 exit, unhealthy, 수동 stop, 관리자 종료·재기동, start 응답 유실, 예산 초과 | 각각의 회차·기대값별 검증. 정상 1회로 대체 불가 |
| 새 boot | 복구점·원문 보존 후 별도 허용된 shutdown/boot, RUN 자동기동 및 HOLD 유지 | 부팅 경로 검증 |
| 로그 저장 | 고정된 무비밀 표식의 발생 → 기존 TCP syslog 경로 → 실제 대상 파일 저장을 tag·시각·컨테이너 ID·해시로 결속 | TCP accept/healthy와 별개의 SYSLOG_INGESTION 판정 |
| 원복 | 관리자 정지 후 원 policy/파일 확인, claim·증적·데이터 보존 | 원복 계약만 검증 |

로그 표식 주입 방식·대상 파일·기존 태그 보존·기대 저장 시간은 실제 logger 설정을 검토한
코드/시험 PR에 고정한다. TCP에 직접 표식을 보낸 것만으로 앱→Docker logging driver 경로를
검증했다고 하지 않는다. host 서비스가 Docker 상태를 보았다는 것과 애플리케이션 기능 정상도
구분한다. 격리 클론 결과를 운영 TLS/Push/Pull·실제 AC04 패킷/AC 인수로 확대하지 않는다.

설계 문서 작성 시점에는 원인·대안·수명주기·원복·시험 계약까지 준비됐다.
현재는 사용자 인수·진행 결정에 따라 제어 코어·모의시험을 구현하고 있다.
영속 상태·직렬 실행 계층·logger-only HOLD 해제에 이어 Docker projection·Unix API adapter를 구현했다.
실제 호스트 보안/구성 provider와 설치 경로는 미연결이며 Docker Runtime 시험은 하지 않았다.
잔여: 현장 보안/구성 관측·설치·원복·unit 구현, 일반 장애 reconciliation, 독립 코드 리뷰, 격리 RUNTIME,
Phase 1 관련 적용·결과 인수. 최신 검증 단계는 코드 PR을 따른다.

## 7. #27 리뷰 보완 및 당시 결정 요청 이력 — 2026-10-09

[설계 PR #27](https://github.com/321Team/infra-harbor-trivy/pull/27)의 이하영 리뷰는
`a11151e84f5c441164afcb9394d3817e61032b70` 문서 편입을 승인했다.
당시 리뷰는 설계 채택·예산 확정·구현 GO를 별도 결정으로 남겼다. 이후 사용자가
인수·진행을 명시했으므로 해당 대기는 현재 선행조건이 아니다. 기존 §4 시간 제안값의
현장 적합성과 Runtime 결과를 코드/모의시험만으로 확정하지 않는 경계는 유지한다.

### 기동시간 원본 대조

병합본 `received/result.json`의 각 start 명령 시작 시각부터, 이후 state 조회에서
처음 running/healthy가 관측된 명령 종료 시각까지 계산했다. start 호출 자체의 시간과
조회 간격을 포함하므로 애플리케이션이 healthy로 바뀐 정확한 순간이나 연속 계측값이 아니다.
원본 SHA256은 `793ce1ff0e5cfadbdc66450da28d2c66d4365a8cfe0c5df0f8ee508163b06677`이며
수신 manifest 247개 항목을 재대조한 뒤 계산했다. 새 게스트 명령은 실행하지 않았다.

| 앱 | start → 최초 healthy 관측(초) | 원본 start / state stdout |
|---|---:|---|
| postgresql | 30.815 | 030-start-postgresql / 046-state |
| redis | 30.824 | 052-start-redis / 068-state |
| registry | 30.834 | 074-start-registry / 090-state |
| registryctl | 30.817 | 096-start-registryctl / 112-state |
| core | 30.883 | 118-start-core / 134-state |
| portal | 30.837 | 140-start-portal / 156-state |
| jobservice | 30.863 | 162-start-jobservice / 178-state |
| trivy-adapter | 30.896 | 184-start-trivy-adapter / 200-state |
| proxy | 31.120 | 206-start-proxy / 222-state |

표의 파일은 모두 병합본 `received/` 아래 `.stdout` 확장자다. 앱별 표본은 1회뿐이며
기존 데이터를 이용한 수동 복구다. cold boot·DB migration의 상한, p95/p99, 60초의 운영
적합성을 추정하지 않는다. **구현 후보에서는 앱별 health 예산을 명시적 입력으로 검증하고,
현재 60초는 모의시험용 제안값으로만 유지**하는 것을 권고한다. cold boot 실측 전 운영
확정값으로 고정하지 않고, migration은 일반 자동기동과 분리된 유지보수 절차로 검토한다.

### logger 주소 대조와 남은 검사

수신 `result.json`의 before/after 앱 9개는 모두 driver=syslog,
syslog-address=`tcp://127.0.0.1:1514`이며, 저장소의
[loopback override](../../config/harbor/compose.logging-loopback.override.json) 9개 서비스와
일치한다. 이는 복구 시점 inspect 값과 저장소 override의 대조다. 현장 원본 Compose와
새 override를 실제 병합한 유효 설정까지 검증한 것은 아니다.

구현 전 입력 검증은 원본 Compose + loopback override + policy override의 유효 설정,
승인된 ID의 실제 logging 설정, 관리자 TCP 목적지를 비교해야 한다. 주소뿐 아니라
driver·tag·기타 옵션 및 서비스 집합을 확인하고, 기본값 보정으로 차이를 숨기지 않는다.
불일치 시 policy 변경/앱 시작 전에 중단한다. 환경변수·Secret 전체를 증적에 내보내지 않는다.

### 당시 요청한 Lead 결정 — 사용자 진행 결정으로 대체된 이력

| 결정 항목 | 권장안 | 현재 상태 |
|---|---|---|
| 기동 주체 | logger=Docker 유지, 앱9=단일 호스트 관리자 후보로 구현·모의검증 | 사용자 진행 결정, 별도 Lead 대기 해제 |
| 정책 의미 | §4의 유한 재시도, 지속 HOLD, unhealthy 시 자동 kill 금지, 수동 stop 전용 경로를 후보 계약으로 사용 | 후보 코드/시험에서 검증 |
| 시간 예산 | §4 값은 모의시험 입력, health는 앱별 입력화; 운영값은 cold boot 근거로 별도 확정 | 기술 검증 잔여, 구현 착수 차단 아님 |
| 이번 착수 범위 | 코드 작성·로컬 STATIC/MOCK 및 코드 PR. 실제 설치/재시작과 구분 | 구현 착수 |

위 표는 #28에서 작성했던 요청과 후속 상태를 연결한다. #27/#28/#29의 당시 문서 리뷰를
소급하여 구현 승인으로 바꾸지 않는다. 진행 근거는 사용자의 후속 명시적 결정이며,
추가 결정 문서 PR을 반복하지 않고 코드와 실패 경로 시험을 구현한다.
