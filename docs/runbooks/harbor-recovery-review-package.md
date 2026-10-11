# Phase 1 설치 전 검토 패키지 및 격리 시험표

CODEX_ASSISTED · 2026-10-09. 기존 구현의 오프라인 검토 준비다. package 생성은 승인·설치·Runtime GO가 아니다.

## 패키지 생성

신뢰된 로컬 checkout의 `scripts/preparation/harbor_review_package.py`를 승인된 비공개 작업 경로에서 사용한다. 게스트에는 이 도구를 설치하지 않는다. 입력은 version1, 완전한 bundle 객체, runtime 객체다. runtime은 python 절대 경로, bootstrap_context/bundle_context/launch_context, bundle_path, startup_seconds, shutdown_seconds를 모두 명시한다.

```text
python -B scripts/preparation/harbor_review_package.py
  --input <검토한 완전한 입력 JSON>
  --input-sha256 <별도 보존한 입력 해시>
  --output <기존에 없는 비공개 출력 폴더>
```

source11개 바이트·컴파일 가능 여부·승인 후보 pin, unit 내용/hash, 전체 execution binding, 중복 없는 목적 경로와 최소 종료 예산을 대조한다. source11개, bootstrap, manager.service, bundle.json, launch.json, INSTALL_PLAN.json을 생성한다. 기존 출력은 덮어쓰지 않으며 실패 시 부분 폴더도 보존한다. 입력·파일 해시를 무결성 확인으로만 사용한다.

목적 경로는 버전별 source 및 bootstrap, `/etc/systemd/system/fds-harbor-recovery.service`, 보호된 bundle/launch로 제한한다. INSTALL_PLAN은 root/mode/context/hash와 기존 외부 입력·Store를 기록하지만 설치 명령을 실행하지 않는다. unit은 launch 고정 경로, launch는 bundle hash, bundle은 unit/source hash로 연결해 순환을 피한다.

생성기에 실제 호스트 관측/기본 승인/샘플 host/default 예산/SSH/프로세스 실행/서비스 변경 기능은 없다. 실제 입력이 없으면 생성하지 않는다. 테스트가 만드는 package는 SYNTHETIC이며 제출 증적으로 쓰지 않는다.

CLI는 로컬 Git의 한 HEAD commit에서 source와 bootstrap blob을 직접 읽고 입력 revision과 일치시킨다. 로컬 Git 조회만 수행하며 fetch/checkout/네트워크는 없다. 미커밋 파일을 승인 commit 소스로 표시하지 않는다.

2026-10-10 후속: [수신 패키지 검사](harbor-recovery-package-receipt.md)는 기존 INSTALL_PLAN의 별도 보존 SHA256으로 전송된16파일과 source·bootstrap/unit·bundle/launch 결속을 읽기 전용 대조한다. 새 승인값을 학습하거나 게스트 설치를 하지 않는다. 이 결과를 현장 metadata·승인·Runtime PASS로 확대하지 않는다.

## 실제 패키지 생성에 아직 필요한 현장 입력

| 구분 | 필요한 원본과 판정 |
|---|---|
| 호스트·격리 | fresh guest hostname/product UUID/boot ID, VMware NIC·HGFS 없음, 게스트 주소·라우트·마운트, root/SELinux Enforcing |
| Python·신뢰 기반 | Python3.10 이상 및 실행 파일/stdlib 공급 경로·버전, bootstrap 외부 해시 검증·설치 주체 |
| Engine·logger | Docker API/profile/storage, Docker InvocationID, 전체10 exact ID/immutable fingerprint/health/원 정책, logger1514 TCP |
| 보호 입력 | canonical self-contained Compose JSON·empty env 등 기존 host schema의 입력·tools/units/hash/mode/gid/context·ACL/xattr, AC04 nft 정본 |
| 새 설치 위치 | 기존 경로 충돌 없음, 새 Store namespace, 실제 파일 생성 시 context 유지 가능 여부, 원본과 분리된 복구점 |
| 예산·행위 | 각 앱 health/start/logger/episode 및 종료 예산의 실측·검토값, 정확한 HEAD/package·설치/정책 전환/arm/unit lifecycle/시험 행위 범위 |

기존 사용자 소유 Harbor YAML을 root 소유로 바꾸거나 현재값을 자동 승인값으로 등록하지 않는다. 새 보호 입력 후보와 원본 Compose의 의미 동등성은 검토 대상이다. code review와 input review가 모두 필요하다. interpreter·SELinux 준비가 안 되면 거기서 중단하며 통제를 낮추지 않는다.

## 설치·원복 검토 순서

1. 완전한 입력 원본·수집시각·외부 승인 hash를 고정하고 offline package와 차이를 검토한다. 이 단계까지 로컬 작업이다.
2. 구체 Runtime 승인 뒤 새 파일만 배치한다. 기존 목적 파일이 하나라도 있으면 자동 덮어쓰기 없이 STOP이다. 디렉터리 소유/권한·ACL/xattr·파일 hash/label을 실제 확인해야 한다. 2026-10-11 후속 [파일 배치 적용기](harbor-recovery-file-install.md)는 검토한 request·실제 준비된 디렉터리/label이 있어야 실행 가능하며, 입력 및 filesystem label 확인 전 현장 쓰기를 허용하지 않는다.
3. unit은 disabled 상태로 준비한다. daemon reload 이후 정확한 fragment/dropins/의존성·MainPID0·미진행 job을 확인한다. bundle verify 성공은 이 준비의 무결성 확인이지 동작 성공이 아니다.
4. initialize→policy-install→arm을 각각 실행하고 단계별 원본/rc/readback을 보존한다. 실패하면 다음 명령을 하지 않는다. 앱9 policy=no 유지보수 구간은 서비스 인수 또는 별도 정책 원복까지 관리한다.
5. 승인된 enable/start 뒤 자기 unit/lease·전체 healthy·Store 상태를 확인한다. 기존 Docker/VM 재시작 claim과 A3 원본을 재사용하지 않는다.
6. 설치 전 실패는 실제 새로 생성한 파일 목록과 해시를 남긴다. Runtime 이후 실패는 먼저 HOLD/단일 복구 인수, logger 및 데이터 보존. 확정된 정책 변경만 기존 정책 원복 조건으로 처리한다. 미확정 claim/pending/변경 파일은 삭제하지 않는다. 자동 전체 uninstall은 없다.

## 격리 시험 및 증적 매트릭스

모든 행의 현재 상태는 NOT_RUN이다. 한 번에 한 행만 수행하고 실패·복구·원본 회수까지 끝낸 뒤 다음 행으로 간다. 현재 전체 작업창 종료 제한은 없지만 개별 회차 budget은 유지한다.

| 순서 | 시험 | 필요한 성공 증적 / 중단 조건 |
|---|---|---|
| H0 | fresh 읽기 사전 점검·복구점 | 위 현장 입력·대상 단일성·격리·콘솔. 누락/드리프트면 변경 없이 중단 |
| H1 | disabled 설치·정책 전환·초기 arm | 원 정책/바이트 metadata, 단계별 journal/claim, apps9 no/logger always, manager 시작 전 RUN. 부분 실패는 확정 범위만 원복 |
| H2 | 상주 시작·중복 실행 차단 | 정확 unit/PID/InvocationID·1개 lease·전체 healthy, 두 번째 manager의 무변경 거부 |
| H3 | 승인된 Docker restart1회 | 원 ID 보존·새 daemon ID·logger 준비 이후 dependency order·건강 deadline·unit 재개. ACK만으로 건강 PASS 금지 |
| H4 | 승인된 VM reboot1회 | 새 boot ID·동일 코드/입력·격리 유지·manager startup·전체 건강·복구 시간 |
| H5 | 장애/HOLD·명시적 healthy 재판정 | 사전 검토된 장애 주입만 사용, 원 state/claim/예산 보존, exact state hash·전체 fresh healthy·RUN 전환. unknown을 ACK로 소급하지 않음 |
| H6 | 별도 승인된 graceful stop | HOLD 먼저, reverse9 SIGTERM, 각 ACK+exited readback, logger 유지, 실패 후 다음 요청0건. 원복 재기동은 별도 승인 경로 |
| H7 | 실제 SYSLOG_INGESTION | 고유 시험 marker·보낸 시각/출처·logger 저장 파일의 동일 marker·수신시각/hash. TCP 열림/healthy만으로 저장 성공 판정 금지 |
| H8 | 회수·인수 | 최종 서비스/정책/Store/임시 전달경로 상태, rc·시간·명령·대상·source/package 해시, private raw→sanitized evidence 연결·리뷰 |

H3/H4 PASS 전 AUTOSTART 완료, H7 전 LOG 수집 완료, H8 전 전체 AC 종결을 선언하지 않는다. 운영 Harbor 배포나 P1 APP Push/Deploy와 별개다. 먼저 로컬/mock/CI로 실패 경계를 검증하고 독립 리뷰를 받아야 실제 대상 시험으로 넘어간다.
