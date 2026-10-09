# Phase 1 격리 클론 호스트 검증 provider

CODEX_ASSISTED · 2026-10-09. #32 Docker adapter의 후속 구현이다. 읽기 검증 모듈과 시험만 추가하며 설치·정책 변경·새 Runtime 실행 명령은 제공하지 않는다. P1-HBR-01 자동복구의 기존 사용자 인수 범위이고 Phase 2 입력은 없다.

## 구현 범위

`scripts/recovery/harbor_recovery_host.py`의 `HostProvider(policy, engine)`는
`DockerBackend`가 요구하는 호출 가능한 provider다. 승인 기준이 없는 경우 생성할 수 없고,
관측한 현재값을 승인 기준으로 자동 등록하지 않는다. 독립 검토된 정책 로딩·Plan 생성과
설치 진입점은 다음 단계이며, 테스트 fixture의 정책/UUID/해시를 현장 입력으로 쓰면 안 된다.

- Linux root, 정확한 hostname/UUID, boot ID, 물리 NIC 없음, HGFS 마운트 없음 확인.
- 게스트 링크는 loopback/bridge/veth만 허용하며 IPv4/IPv6 전체 테이블의 default route를 거부.
- SELinux Enforcing, AC04 guard active/exited, Docker active/running, Requires/After 확인.
  systemd fragment/drop-in 목록·바이트 해시를 고정하고 NeedDaemonReload=yes를 거부.
- AC04 table은 승인된 JSON shape 해시와 비교. handle과 counter의 packets/bytes만 비교에서 제외.
  최초 조회값을 기준으로 삼지 않는다. 이 비교는 허용 정책의 패킷 실측이나 AC04 전체 인수와 다르다.
- Engine `/version`, `/info` GET의 명시된 version/API/daemon ID·storage·security profile 비교.
  선택 API가 MinAPIVersion~ApiVersion에 포함돼야 한다. 실제 호스트 버전 채택을 새로 결정하지 않는다.
- Compose 직접 실행 파일·관련 입력을 고정하고 `config --format json`의 구조 해시, 서비스10개,
  logger always/앱9 no 및 앱 TCP loopback syslog를 확인한다.
- 모든 보호 파일은 root 소유, 승인 mode/gid/SELinux label·SHA256, 일반 파일·단일 hardlink를 요구한다.
  모든 상위 경로는 root 소유/그룹·기타 쓰기 불가/심볼릭 링크 없음 및 POSIX ACL 없음을 요구한다.
  socket은 승인된 mode/gid/label·root 소유와 전후 inode를 확인한다. Engine root peer 확인도 유지한다.
- 수집 전후 identity·generation·보안 gate·입력 해시/socket을 다시 확인한다. 시작 monotonic 시각을
  유지하며 완료 시각으로 신선도를 연장하지 않는다. provider의 정책 전체 해시는 Plan 실행 binding에 포함된다.
- 고정 읽기 명령만 구성하고 shell을 사용하지 않는다. 환경 상속을 차단하며 출력/전체 시간 상한을 적용한다.
  실패 시 읽기 보조 프로세스 그룹만 정리한다. Docker/VM 서비스에 종료 신호를 보내지 않는다.
- raw Compose 환경값·Engine 원문·stderr는 메모리 안에서만 처리한다. 반환은 HostSnapshot,
  실패는 고정 HOST_VERIFICATION_FAILED다. 민감정보가 예외 메시지로 전파되지 않는다.

## 필요한 설치 입력과 현재 제약

정책 스키마는 `validate_policy`에 고정돼 있다. 설치기는 다음을 구체 승인 입력으로 준비해야 한다.

1. clone UUID/hostname, API/socket, Engine profile, AC04 rule shape, systemd 원문/의존성.
2. root 0700 입력 디렉터리, 직접 Compose 실행 파일과 systemctl/nft/ip/getenforce 실제 파일,
   self-contained Compose JSON 파일들, 명시적인 환경 파일의 SHA·mode/gid/SELinux label.
3. 정책 JSON과 실행 코드의 검토 HEAD/해시를 검증한 로더, provider.binding과 engine.binding을
   연결한 Plan 및 기존 불변 컨테이너 지문/상태. policy 변경 시 기존 RUN 재사용 금지.

Compose 입력은 **완전히 해석된 JSON**만 허용한다. include/extends/env_file/build 및 top-level
configs/secrets를 거부하고, 추가 interpolation/env-resolution을 하지 않는다. 기존 사용자 소유
`/home/server08/harbor` YAML을 그대로 이 함수에 넣는 경로가 아니다. 원본과 override의 검토된
유효 설정을 보존·대조한 뒤 root 보호 경로에 준비하고, 이후 유일한 운영 진입점에서도 같은
설정을 소비하는 작업이 설치기 범위다. 이 과정의 절대 bind 경로, 비밀값, `$` 문자 의미 보존과
Compose 호환성을 현장 검증해야 한다. 원본 chmod/chown으로 우회하지 않는다.

기존 symlink 기반 `/var/run` 또는 도구 경로는 통과하지 않는다. 실제 canonical 경로를 승인 입력에
고정한다. ACL이 필요한 환경에서는 임의 제거하지 않고 다음 변경에서 명시적 정책을 검토한다.
현재 구현은 ACL이 없는 좁은 설치 profile이며 ACL 예외를 자동 허용하지 않는다.

guest 검사로 VMware VMX의 NIC/HGFS 설정 자체나 다른 root 작성자 배제를 증명하지 않는다.
회차 시작 시 호스트 측 격리와 콘솔/복구 인수를 별도 확인한다. 임의 root의 동시 수정에 대한
원자적 전역 잠금이나 TOCTOU 완전 차단을 제공하지 않는다. symlink/파일/세대 변화는 가능한 경계에서
거부하며, 별도 작성자 비중첩 조건을 유지한다.

Store의 state/claim/audit/pending 전체 ACL·xattr 검사, 설치/부분 원복·unit·정식 운영 CLI,
일반 HOLD reconciliation·graceful stop은 아직 후속 작업이다. 이 provider의 입력 파일 검사를
그 항목들의 완료로 확대하지 않는다. 이전 state/pending/claim을 삭제하거나 자동 승격하지 않는다.
5초 max_age와 전체 실행/건강 예산은 실제 파일 크기/호스트 수집 시간을 측정한 뒤 확정한다.
현재 호스트에서 이 모듈을 실행하거나 해당 예산을 검증하지 않았다.

## 검증과 실패 처리

`python3 -B -m unittest discover -s tests/recovery-core -v`로 기존 회귀와 provider 시험을 실행한다.
합성 호스트 정상/보안·설정·generation drift, adapter 연결 실패 시 POST 0회, 출력 비밀정보
비노출을 검사한다. Linux CI에서 임시 파일의 nofollow/hash/hardlink/FIFO, 읽기 명령 환경 격리·
출력 상한·timeout/프로세스 정리를 확인한다. CI에는 SELinux enforcing/실제 Docker/Harbor가 없다.
root 소유·SELinux xattr 분기는 합성 stat/xattr 입력으로 검증하며 실제 호스트 통과 증적이 아니다.

검증 실패 시 HostSnapshot을 반환하지 않고 다음 start를 차단한다. 정책을 현재값에 맞추거나
재시작/권한 변경으로 자동 복구하지 않는다. 기존 executor가 HOLD/원 intent를 보존한다.
설치가 아직 없어 코드 롤백은 PR/파일 반영 이전으로 돌아가는 범위이며 서버 원복 명령은 필요 없다.

참고: [Compose config의 병합·해석 계약](https://docs.docker.com/reference/cli/docker/compose/config/),
[Docker Engine API](https://docs.docker.com/reference/api/engine/version/v1.53/),
[systemctl show의 기계 판독 출력](https://www.man7.org/linux/man-pages/man1/systemctl.1.html).
