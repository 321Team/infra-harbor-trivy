# Phase 1 상주 복구 관리자 준비

CODEX_ASSISTED · 2026-10-09. Bootstrap 후속이며 실제 게스트 설치/실행은 NOT_RUN이다.

## 계약

- `serve --launch /etc/fds-harbor-recovery/launch.json --context <승인 label> --timeout <초> --execute`만 상주 경로다. 동일한 Linux/root/Python3.10+/`-I -S -B` 조건을 유지한다.
- launch anchor는 root:root0400, 단일 파일·보호된 상위 경로·정확한 SELinux context/허용 xattr를 요구한다. 내용은 정확히 version1, bundle 절대 경로, 외부 승인 bundle sha256, bundle context다. bootstrap/해당 anchor는 외부 승인·해시 검증을 거쳐 설치해야 하는 신뢰 기반이다. 자기 파일의 해시로 자기 신뢰를 증명하지 않는다.
- bundle은 unit과 source10개를 pin한다. unit에는 bundle hash를 넣지 않고 고정 anchor 경로만 전달한다. 순환 해시를 만들지 않는다. 실행 중 anchor 바이트가 바뀌면 HOLD 후 종료하며 새 승인을 자동 채택하지 않는다. 기존9파일 bundle은 새10파일 코드 집합과 호환되지 않아 재작성·리뷰가 필요하다.
- 시작 전 실제 자기 unit의 MainPID, InvocationID, FragmentPath/dropins, Docker/AC04 Requires·After, Docker PartOf와 미반영 변경 유무를 검사한다. root에서 CLI를 임의 직접 호출해 관리자가 된 것으로 인정하지 않는다.
- 별도 manager.lock을 프로세스 수명 동안 보유한다. 짧은 controller lock과 분리해 이중 상주 실행을 막고 HOLD 명령의 정상 잠금 시도를 허용한다. pending/claim/미완료 health wait는 기존 resume gate로 HOLD된다.
- 1초 간격의 관측이며 각 관측/기동의 기존 deadline을 유지한다. HOLD는 rc2로 종료, 자동 arm/reconcile/재전송 없음. host 검사 또는 저장 실패도 증적을 보존하고 중단한다.

## 종료와 unit

`harbor_recovery_service.unit_text(...)`는 unit 문자열만 생성한다. 설치·daemon-reload·enable/start/stop 호출은 없다. 입력 경로/label의 삽입과 비정상 예산을 거부한다. 시작/종료 예산은 현장 실측으로 검토해야 하며 샘플값을 GO로 사용하지 않는다.

- Type=exec, root, UMask0077. Requires/After=docker 및 AC04 guard. PartOf=docker, WantedBy=docker 및 multi-user.
- Restart=on-failure이나 rc2/130은 RestartPreventExitStatus로 반복하지 않는다. StartLimit도 둔다. signal/crash 뒤 재시작되어도 원본 Store의 resume 판정이 우선한다.
- SIGTERM/SIGINT handler는 flag만 설정한다. 신규 tick, intent 후, claim 후, 마지막 fresh 관측 후 POST 직전에서 확인한다. 이미 시작한 요청을 취소했다고 주장하지 않는다. 검사 직후 도착하는 신호와 이미 전송된 요청 사이의 원자적 취소를 보장하지 않는다.
- clean manager 종료는 RUN을 보존해 승인된 Docker/VM 재시작 후 이어갈 수 있게 한다. 저장된 intent/claim/health wait가 있으면 새 프로세스가 HOLD한다. 종료 신호 수신을 앱 stop으로 해석하지 않는다.
- ExecStop은 없다. 앱/Harbor logger는 Docker 소유이며 manager cgroup의 강제 종료 대상이 아니다. TimeoutStopSec는 최대 관측·start·영속 저장 여유를 포함해 정해야 한다. 개별 시간 예산은 글로벌 작업창 한도 해제와 별개다.
- 현장에 설치하기 전 systemd 버전/의존성 동작·SELinux·Python·완전한 승인 bundle·원복점 확인 및 독립 코드 리뷰가 필요하다. [systemd.service 원본](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.service.xml), [systemd.unit 원본](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.unit.xml)을 기준으로 한다.

## 검증과 잔여

테스트는 중복 manager lease, signal 안전 경계, 변경된 anchor, 잘못된 소유 unit, 고정 serve 입력, 실행 전 source 로딩, 순환 없는 unit 렌더링을 확인한다. Linux 파일/잠금 시험과 합성 Docker/SELinux 입력이며 Harbor RUNTIME 증적이 아니다.

다음 단계는 명시적 HOLD 재판정·graceful stop, 검토된 설치 입력 조립과 변경 원복, 격리 AUTOSTART(Docker restart/VM boot) 및 SYSLOG_INGESTION 각각의 실제 시험이다. 정책 전환/원복과 unit 설치/활성화는 이 PR로 실행되지 않는다.
