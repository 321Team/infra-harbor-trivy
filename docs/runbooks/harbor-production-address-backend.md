# 운영 Harbor 주소 변경 — Compose 실행부와 전체 설정 대조

CODEX_ASSISTED · 2026-10-12 · baseline#13 · PR47 후속.
이 구현은 `Sequence`에 연결하는 라이브러리다. 실제 Linux 프로세스 호출을 포함하지만
운영 host collector·root 보호 입력 공급·증적 회수의 후속 연결은
[보호 실행 연결](harbor-production-address-protected-runtime.md)에 정리했다. 실제 CLI/OS 감독·현장 입력은 잔여다.
단독 실행 명령이나 현행 운영 request를 제공하지 않는다. 실제 적용·H6·manager·AC는 미수행이다.

## 변경과 호출 순서

- `harbor_address_compose.py`: 전체 주소 변경 범위 대조, 기존 resource 참조 입력,
  검토된 바이너리 fd로 실행하는 제한된 프로세스 호출, 단일 앱 최대1회 transport.
- `harbor_address_inspect.py`: 전체 Config/HostConfig 및 mount/network 보존 비교.
- `harbor_address_backend.py`: 위 두 모듈과 기존 MountPreservation/Sequence 연결.

호출자는 검토된 건강한10개 시작 상태(`fds.harbor.production-address-maintenance.v1`),
실제 journal/미사용 claim, 운영 세대·실행 입력 및 예산을 먼저 공급한다.
기존 stopped schema나 clone 실행기/사용 claim을 자동 변환하지 않는다.
순서는 postgresql→redis→registry→registryctl→core→portal→jobservice→trivy-adapter→proxy다.
logger는 재생성 대상에서 제외하며, 다음 앱 전에 이전 앱의 healthy 유지까지 대조한다.

1. host 보호 경계/입력과10개 inventory를 읽고 중복·추가 서비스/ID 변화를 거부한다.
2. 전체 inspect·volume/label/권한을 비교하고 다시 inventory와 host 입력을 읽는다.
3. Sequence가 durable intent를 기록한 뒤 해당 앱 transport에 진입한다.
4. 검토된 전체 stdin bytes로 Compose config를 읽어 전체 모델과 비교한다.
5. 동일 host/10개 상태를 다시 읽고 정확 기존 앱ID·loggerID·입력·기한을 대조한다.
6. **동일 stdin bytes**를 단일 앱 재생성에 전달한다. 반환 뒤 새ID·설정·mount·health를 검증한다.

Compose API에 기존 ID를 조건부 쓰기로 넘기는 기능은 없다. 직전 대조와 비중첩 운영을 함께
요구하며 이를 원자적 CAS라고 주장하지 않는다. timeout/전송 후 불명/오류면 후속 쓰기를 멈추고
같은 backend/transport 재사용을 거부한다. fork/동시 호출/순서 바꿈도 거부한다.

## 입력과 도구 소비

`execution_model(base, candidate, resource_names=...)`는 먼저9개 logging 주소만
localhost→127.0.0.1인지 전체 필드로 대조한다. 기존 encoder의 생략 bind 생성=false 및
문자열 `$` 이스케이프를 유지한다. 이후 다음 **명시적인 실행 metadata 변환**을 한다.

- 현재 inventory로 확인한 동일 이름의 network/named volume을 `external: true`로 참조한다.
- external network의 `ipam: {}`를 명시한다. Compose5.6.0의 기본 렌더링과 동일하며
  비어 있지 않은 IPAM 입력·새 resource·임의 이름은 거부한다.
- 서비스 설정과 원 Compose 파일은 이 변환에서 바꾸지 않는다.

[Compose5.6.0 create 단계](https://github.com/docker/compose/blob/42f48072bbf92ee9b0e43f9fdf2008d03546e7ca/pkg/compose/reconcile.go)는
컨테이너보다 먼저 network/volume을 정합화한다. 단일 서비스만 지정해도 관리 resource의
차이를 무시하지 않으므로, 기존 참조와 fresh identity/config 검증이 필요하다.
resource 이름을 넘겼다는 사실만으로 그 resource의 존재/불변을 입증하지 않는다.

`PinnedCompose`는 검토된 ELF SHA256·root 소유/안전한 전체 경로·단일 hardlink·ACL/xattr·
실제 SELinux context, 빈 root0700 private config directory를 검사한다.
심볼릭 링크와 쓰기 가능한 부모 경로를 거부하고 fd로 실행해 경로 교체를 피한다.
private directory/바이너리는 호출 뒤에도 대조한다. 경로 생성/권한 변경/재라벨은 하지 않는다.
`context=None`은 SELinux exact 비교가 없는 CI 모드이며 운영 승인값으로 사용하지 않는다.

고정 공통 옵션은 local Unix socket, project harbor, project directory `/`,
`--env-file /dev/null --parallel 1 --ansi never -f -`다.
환경은 고정 PATH/LC_ALL, private HOME/DOCKER_CONFIG, local DOCKER_HOST/API1.56만 사용한다.
현재 계정의 Docker credential/config/plugin 설정을 상속하지 않는다.

재생성 옵션은 `up -d --no-deps --force-recreate --pull never --no-build --timeout -1 <앱1개>`다.
hook/build/deploy/profiles/provider/links/암묵적 신규 볼륨 등 검토 범위를 벗어난 기능은 거부한다.
bind 경로 자동 생성도 허용하지 않는다. stdin에 포함된 값은 stdout/stderr와 함께 비공개다.

`--timeout -1`은 [Compose GetTimeout](https://github.com/docker/compose/blob/42f48072bbf92ee9b0e43f9fdf2008d03546e7ca/cmd/compose/create.go)에서
Engine으로 전달한다. [Docker stop timeout 계약](https://github.com/docker/cli/blob/master/man/docker-run.1.md)에 따라
일정 시간 후 자동 SIGKILL로 승격하는 경로를 피하며, 명시 SIGKILL stop signal도 거부한다.
**전체 실행은 무제한이 아니다.** 호출자 절대 기한/출력 한도를 넘으면 CLI process group만
종료한다. 이미 Docker가 수신한 stop/create/start는 계속 진행될 수 있고, 이 종료가 취소나
서비스 원복을 보장하지 않는다. 이때부터 현행 상태 인수와 별도 복구 판단이 필요하다.

## 전체 보존 비교와 필요한 실제 입력

`FullPreservation`은 원본 private inspect와 아래 검토된 기대값을 받는다.
이전/이후 Config/HostConfig의 **알려지지 않은 필드도** 통째로 비교하며 삭제하지 않는다.

| 입력/변화 | 허용되는 정확한 범위 |
|---|---|
| Env/명령/사용자/보안/포트/health/restart/image | 전체 보존. Env 배열 순서만 정렬하고 중복 키는 거부 |
| 앱 logging | 기존9개 주소만 변경 |
| Compose 생성 labels | 정확 후보에서 도출해 검토한 config hash/version/경로/dependency/replace 값. 임의 새 label/타 label 변화는 거부 |
| Hostname | 명시 auto 목록의 원ID 앞12자리→새ID 앞12자리만 허용 |
| Network | 원 NetworkID·IPAM·옵션·gateway/prefix 등 보존. 동적 EndpointID, 명시 auto 목록의 할당 주소/MAC 및 정확ID 별명만 정규화 |
| HostConfig.Mounts | 기존 prefix 보존, 정확 원 anonymous volume Name/Target/RW의 재참조만 명시 기대값으로 추가 |
| Mounts 배열·label | 기존 MountPreservation으로 fresh profile 검사 후 전체 배열 일치. 앱7개 Mode 변화는 승인된 운영 profile이 있을 때만 소비 |

미수행 앱과 logger는 ID·Config·HostConfig·NetworkSettings 전체가 원 상태와 같아야 한다.
기대한 새ID를 처음 본 뒤 고정하여 중간 재교체를 거부한다.
보존 hash는 검토된 생성 metadata를 포함한 기대 투영의 hash이지 원 raw 파일 SHA가 아니다.
볼륨 이름·metadata 보존은 DB 내용 일관성/업무 데이터 검증을 대신하지 않는다.

`host_provider(deadline)`는 실제로 다음을 검증하고 제한 시간 안에 반환해야 한다.
hash 문자열을 그대로 돌려주는 모의 provider는 운영용이 아니다.

- 정확 host UUID/boot/Docker InvocationID·도구/Engine 버전·SELinux/AC04·현행 network·manager 경계.
- 원 Compose/env·보호 공급물의 byte/hash/owner/mode/context/ACL, 검토된 candidate/preservation 입력.
- 각 image 참조가 기존 image ID를 가리키는지, external resource의 정확 identity/config가 유지되는지.
- IPv4 logger listener, 실제 volume inventory·경로 metadata, 운영 profile/승인 근거와 입력 결속.

이 결과의 schema는 binding_sha256, inputs_sha256, at, logger_ipv4, model_sha256,
preservation_binding, mount_inputs다. at은 이번 조회 안의 monotonic 시각이며,
전후 결과는 at 이외 모두 같아야 한다. 시간·label·승인·profile을 자동 생성하지 않는다.

## 중단·부분 상태와 후속 배치

render/guard 실패는 Compose 변경0. transport 진입은 보수적으로 사용한 시도로 기록한다.
실제 호출 뒤 오류·기한 초과·stdout 한도·설정/볼륨/health 차이는 다음 앱 호출0이다.
재호출·volume 삭제·snapshot restore·주소 원복 재생성은 자동 실행하지 않는다.
기존 journal/claim, 대상별 old/new ID, rc/고정 원인/시각·SHA, 부분 서비스 상태를 인수한다.

프로세스 결과는 bounded private bytes와 비밀값 없는 hash/크기/rc 진단으로 분리한다.
단독 `_private_results`는 메모리 보존이다. 후속 ProtectedSession은 AuditedCompose와
root 보호 디스크 수집/부분 상태 읽기를 연결한다. supervisor/현장 배치는 아직 남아 있다.
현재 source/실행 입력/생성 metadata/profile 검토, 보호 공급·전체 현장 읽기·미사용 회차를
묶은 CLI가 완성돼야 운영 실행 번들로 제시할 수 있다.

## 검증 범위

`tests/production-address/test_compose_backend.py`는 합성 Engine/host/Compose 연결,
9앱 순서·전송 직전 drift·중복/동시/fork·부분 실패·Env/보안/volume/network 보존을 검증한다.
Linux 시험은 실제 pipe/시간 초과/자식 process group·root 임시 경로와 journal을 사용하되
Docker/guest/실제 재생성에는 접속하지 않는다. CI 통과를 Runtime/AC로 표시하지 않는다.

2026-10-12 **15:07 KST 운영 읽기**에서는 실제5.6.0 config 렌더링만 실행했다.
초회 external network의 빈 IPAM 삽입 차이를 재현했고 명시 후 전체 모델이 일치했다.
기존10ID/Config/HostConfig·원 Compose/env5·바이너리·network resource hash 전후 일치,
10healthy를 관측했다. guest 파일 쓰기/컨테이너 변경0이다.
이 읽기는 PinnedCompose의 root private 실행 경로나 실제 up 검증을 대신하지 않는다.
비공개 원본은 업로드하지 않으며 local 수신 hash와 고정 진단만 인계한다.
