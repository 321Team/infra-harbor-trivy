# 운영 Harbor 자동복구 입력 연결

CODEX_ASSISTED · 2026-10-13. 운영용 **코드·입력 계약**이다. 실제 운영 정책,
설치 패키지, 작업창, 정지 예산을 생성하거나 확정한 문서가 아니다.
주소 변경 PR55의 고정 boot/시간 요청과 상주 자동복구 입력은 서로 다르다.

## 바뀐 동작

기존 격리 복제본 provider는 물리 NIC/default route를 거부하므로 운영에서 사용할 수 없었다.
주소 변경 provider는 앱 전체 실행 상태와 특정 boot를 요구하므로 부팅 직후 정지된 앱의
복구에 재사용할 수 없다. 이 변경은 기존 start-once/claim/HOLD 상태 전이를 유지하면서
운영 네트워크 검증을 별도 provider로 연결한다.

| 입력 | 복제본 경로 | 운영 경로 |
|---|---|---|
| bundle schema | `fds.harbor.recovery.bundle.v1` | `fds.harbor.recovery.bundle.production.v1` |
| host policy version | 1, 기존 binding 유지 | 2, 별도 binding |
| NIC/라우트 | 기존 격리 검사 | 검토된 정확한 NIC·bridge·라우트 projection |
| 앱 상태 | 기존 계약 유지 | 고정 기존 ID의 running/exited/created만 허용 |
| boot/daemon | 현재 세대 조회 | 현재 세대 조회, 재부팅 때 정책 재등록 없음 |
| package/receipt/install/build | 기존 연결 | 같은 검증기를 거쳐 운영 provider 선택 |

운영 unit은 network-online.target 뒤에 시작한다. 이것은 네트워크 검증을 대신하지 않는다.
manager의 PID/InvocationID/의존성 검사, 보호 경로·파일 해시/SELinux/AC04/Engine/Compose
검사와 수집 전후 재검증을 그대로 유지한다. manager 중단에 앱 종료를 연결하지 않으며
`ExecStop`도 추가하지 않는다. H6는 기존 명시적 operator stop 경로의 역순 종료·ACK/readback·
중복 claim 차단을 소비한다. 앱 재생성/삭제·운영 정책 자동 등록·실패 자동 수선은 없다.

## 운영 입력의 추가 부분

`host_policy.network`는 다음 **명세**이며 예시 값을 운영 입력으로 채우면 안 된다.

- `physical_interfaces`: 정렬된 정확한 물리 NIC 이름 목록.
- `interfaces`: loopback·물리 NIC·등록 bridge 이름별 `production_link_projection` SHA256.
- `bridges`: 정확한 Docker network ID별 name, bridge, `_net_network_projection` SHA256.
- `routes_sha256`: 고정 라우트 projection SHA256. 검증된 앱 veth의 EUI64 link-local
  정상/DAD 진행 중 라우트만 제외하고, 등록 bridge의 `linkdown` 표시만 정규화한다.
- `ids`: log와 앱9개 기존 ID. Plan ID와 같아야 하며 모두 서로 달라야 한다.
- `tools.nsenter`와 대응 `files`의 실제 경로/해시/소유·권한/SELinux 입력도 필요하다.

veth 소유권은 Docker endpoint MAC와 독립 조회한 컨테이너 network namespace의
양쪽 ifindex/link_index, bridge membership을 모두 대조한다. 이름이나 개수로 추정하지 않는다.
namespace fd를 유지해 PID 교체가 다른 namespace로 조회를 돌리지 못하게 하고 조회 후 재확인한다.
낯선 NIC/veth/endpoint/route, 다중 연결, host networking, DAD 실패, 입력/세대 변화는 거부한다.
정지 컨테이너도 등록 network 한 개에만 연결되어 있어야 한다.

ifindex는 재부팅 때 바뀔 수 있어 고정 지문에서 제외한다. bridge carrier 상태·알려진 timer/
FDB 개수와 `tso_max_size` 처리 능력 값만 정규화하며 MTU/GSO/MAC/STP/주소 생성 설정 등
나머지 필드는 보존한다. Linux CI에서 실제 bridge의 TSO 상한이 포트 추가 시
65536→524280으로 바뀌는 거짓 거부를 재현했다. [커널의 TSO 처리 능력 계약](https://kernel.org/doc/html/v6.16/networking/kapi.html)과 대조했으며
필드 존재·양의 uint32 검사를 유지한다. 물리 NIC의 같은 필드는 정규화하지 않는다.
동적 route와 링크 projection은 PR55의 검증 함수를 동일 source catalog 안에 복제했다.
기존 11-module bootstrap 신뢰 목록을 유지하기 위한 선택이며, 향후 공통화 시 양쪽 회귀가 필요하다.

## 적용 전에 남은 실제 확인

1. 독립 리뷰/CI가 통과한 source와 대상 신원, 복구점, 다른 쓰기 작업 비중첩을 대조한다.
2. 변경 후 실제 ID/config/bind/image/network·보호 경로·도구/label을 수집한다. 현재 관측을
   자동 승인 기준으로 등록하지 않는다. 원본·기존 claim·승인 APP/공급 기준을 보존한다.
3. **bridge 자체의 IPv6 주소/라우트는 고정 입력이다.** 이 코드의 DAD 동적 처리는 앱 veth만
   대상으로 한다. bridge 주소가 첫 carrier 때 생성되는 환경에서는 차이가 거부된다.
   첫 부팅·전부 정지·일부 기동·전체 건강 상태의 실제 topology가 이 계약에 들어오는지
   확인하기 전에는 운영 적합/설치 가능으로 판정하지 않는다. 임의 IPv6/보안 설정 변경으로
   맞추지 말고 필요한 경우 별도 근거와 최소 코드 수정을 준비한다.
4. 기존 packet·syslog·DB 의존성 인수 조건과 H6 정상 종료 증적/정지 예산을 확인한다.
   주소 변경 1930초/DB360초/기타30초를 manager나 H6 예산으로 전용하지 않는다.
5. 새 입력 해시로 prepare → receipt → installer preflight를 수행하고 설치·arm·기동은
   해당 실제 입력/작업 범위에 맞춰 진행한다. 코드 리뷰와 모의 성공은 Runtime/AC가 아니다.

실패 시 다음 start/stop을 중단하고 state/pending/claim/부분 상태와 로그를 보존한다.
파일 설치 실패는 기존 설치기의 본인 생성 파일 원복 조건을 적용한다. 이미 실행된 앱에 대한
강제 종료·삭제·claim 제거·스냅샷 자동 복원이나 과거 PR44 요청 재사용은 하지 않는다.

## 검증 구분

`test_production_recovery.py`는 실제 생성자/receipt/bootstrap import와 provider/backend/상태
전이를 합성 Engine·I/O·store로 연결한다. 새 boot/daemon, 정지·일부 기동, 입력 drift,
H6 역순 종료 및 응답 불명확 뒤 재요청 금지를 검사한다.

`test_production_network_linux.py`는 **CI의 빈 Linux network namespace**에서 실제 ip/veth/
namespace fd/DAD/route를 검증한다. Docker metadata와 SELinux label만 합성하며 운영 게스트나
Docker API에 접속하지 않는다. bridge IPv6는 시험 시작에 명시적으로 구성하므로 해당 시험은
실제 운영 bridge의 첫 boot 주소 생성 동작을 증명하지 않는다.

기존 복구 및 주소 변경 회귀도 연결한다. 실제 Docker/Harbor 재부팅, H6, SELinux 적용,
전체 실행 시간 측정, 독립 승인, 병합, 설치, AC는 각각 별도 증적이 필요하다.
