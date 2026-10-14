# Docker daemon 재시작 계약 v3

CODEX_ASSISTED. H3 운영 실패의 기본 bridge 재생성과 DNS 빈 배열 재로딩을 함께 다룬다.
코드/CI 성공은 운영 H3 또는 AC 인수 완료가 아니다.

## 원인과 수정

Docker 기본 bridge는 daemon 시작 때 생성된다([Docker 공식 문서](https://docs.docker.com/engine/network/drivers/bridge/)).
2026-10-14 운영 원본 대조에서 기본망은 Id/Created만 변경됐고,
앱9개 HostConfig는 Dns/DnsOptions/DnsSearch가 null에서 []로 바뀌었다.
기존 시험은 boot/daemon 식별자만 교체하여 이 두 전이를 놓쳤다.

| 입력 | 기존 계약 | 새 계약 |
|---|---|---|
| bundle schema | production.v2 | production.v3 |
| host policy version | 2 | 3 |
| container projection / adapter version | 1 | 2 |
| 사용자 정의 망 | ID 및 구성 고정 | 동일 |
| 기본망 | ID 및 Created도 고정 | 정확 이름 bridge로 조회, docker0·default 옵션·빈 endpoint 및 구성 고정 |
| DNS 세 필드 | 원본 표현 hash | 필드 존재와 타입 확인 후 null만 []로 정규화 |

기본망 새 ID는 유효한 64자리 hex여야 한다. IPAM/옵션/기타 필드, 물리 NIC·링크·라우트,
Harbor endpoint 소유 증명은 유지한다. 동일 관측 중 기본망 ID가 바뀌면 거부한다.
기본망에 컨테이너나 kernel bridge 포트가 있으면 거부한다. 사용자 정의 망 재생성을 승인하는 기능은 없다.
DNS의 비어 있지 않은 값·순서·다른 HostConfig 필드는 그대로 hash한다.
필드 누락이나 잘못된 타입은 거부한다.

clone v2(host1)와 production v2(host2)는 기존 hash·동작을 유지한다.
v3의 bundle/host/source/adapter 결속은 다른 버전의 plan·Store와 혼용할 수 없다.
producer, receipt 검사, bootstrap, installer 사전검사, runtime 및 policy backend가 같은 버전을 사용한다.

## 검증

- test_daemon_lifecycle_contract.py: 두 변화 동시 발생 → 앱9개 순서대로 각각1회 → 건강 → 재개 시 추가 start0.
  실제 DNS 변경·사용자망 변경·기본망 설정/endpoint 변화·동일 관측 내 교체·버전 혼용은 거부한다.
  실패 뒤 남은 claim과 HOLD, producer부터 runtime까지 결속도 검사한다.
- 기존 recovery / production-address 전체 회귀: 공유 projection과 host의 기존 계약 회귀를 확인한다.
- daemon-reload CI: SHA256로 고정한 공식 Docker29.8.2, 별도 socket/data/exec root,
  비어 있는 Linux network namespace에서 실제 daemon을 정상 종료·기동한다.
  외부 이미지를 받지 않고 저장소의 작은 Go 프로그램을 scratch rootfs로 import한다.
  실제 Engine/inspect/네트워크/시작/건강/Store를 사용한다.
  host 신원·Compose/systemd/AC04/SELinux 입력과 설치 gate는 CI fixture이므로 운영 서비스 프로파일의 검증은 아니다.
  운영 환경이나 호스트의 기본 Docker daemon을 재시작하지 않는다.

실제 CI 실행 결과와 exact HEAD는 PR에 기록한다. 미실행을 PASS로 표시하지 않는다.

## 운영 후속 순서와 중단 조건

1. 정확 HEAD의 전체 변경·집중/회귀/실제 daemon 시험을 묶어 독립 검토한다.
2. 병합 후 새 소스의 package producer로 현재 운영 원본을 대조하여 v3 입력을 준비한다.
   `default_bridge.sha256`은 `digest(default_bridge_projection(actual_row))`,
   container fingerprints는 `project(..., fingerprint_version=2)`,
   execution binding은 bundle의 `fingerprint_version(obj)`로 계산한다.
   기존 입력을 숫자/현재 hash만 바꿔 실행하지 않는다.
3. 사용한 기존 Store·claim·실패 원본은 보존한다. 새 namespace 및 실제 설치/전환 범위를 구체화하고
   기존 승인과 실패 후 중단 범위에 맞춰 검토한다. 여기에는 실제 package/시간/boot/라벨/예산 기본값이 없다.
4. 설치 및 실제 writer context·daemon 전후 네트워크/DNS 사전 비교 후 허용된 별도 운영 회차를 수행한다.
   현재 manager 실패 상태의 복귀와 H3 재시험은 별도 실행 결과로 남긴다.

불일치·응답 불명·시간 초과 시 후속 변경을 중단하고 부분 상태/claim을 보존한다.
이 수정은 자동 원복·재시도·claim 삭제·정책 재학습·보안 설정 완화를 추가하지 않는다.

