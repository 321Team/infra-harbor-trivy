# 운영 주소 변경: 기존 bind와 생성 metadata 입력 대조

CODEX_ASSISTED · 2026-10-12 · baseline#13 · PR50 병합 후 쓰기 전 발견한 결함 수정.
코드 검증, 운영 설정 해석, 실제 재생성, manager/H6/AC는 별도 단계다.

## 발견과 원인

16:55 KST 운영 읽기에서 10개 running/healthy, 기존 bind30개가 HostConfig.Binds에 있고
HostConfig.Mounts는 없음을 확인했다. 앱9개의 bind는27개이고 logger3개는 변경 대상이 아니다.
기존 false 입력은 config 해석에는 성공했지만 생성 단계에서 이 표현을 유지하지 못한다.

- Compose5.6.0은 create_host_path=false일 때 Mount API를 선택한다. 기존 Binds의
  source/target/access/SELinux z와 같은 표현을 유지하려면 기존 legacy 경로를 정확히
  결속해야 한다. Mount API의 BindOptions에는 SELinux 옵션이 없다.
- Compose가 Go map에서 만든 bind/mount 배열의 순서는 고정되지 않는다.
- Engine29.8.2 mount JSON은 ReadOnly=false를 생략한다. 기존 비교기의 필수 필드 가정은
  읽기/쓰기 volume의 기대값을 거부한다. 생략이 readonly=true를 뜻하지는 않는다.
- 운영 앱 volume 하나는 uid/gid10000이다. profile은 이를 명시할 수 있지만 기존 collector가
  최종 _data까지 root 소유를 요구해 읽기를 거부한다. 수정은 읽기/정확 대조이며 chown이 아니다.

원본 구현:
[Compose create.go, 고정 commit](https://github.com/docker/compose/blob/42f48072bbf92ee9b0e43f9fdf2008d03546e7ca/pkg/compose/create.go),
[Engine mount.go, 고정 commit](https://github.com/moby/moby/blob/8af9fe3a36bab3e039862a2ab1cef1880c9b4d03/api/types/mount/mount.go).
실제 읽기에서 기존 ID/Config/HostConfig·원 Compose/env5·도구·network 설정 전후 일치를 확인했다.
원문 env/Config·비밀 파일 내용은 출력/게시하지 않았다.

## 명시적 기존 bind 계약

host-policy schema v2는 기존 v1 필드와 `bind_sources`를 포함한다. 이는 실행 입력 형식의
버전이며 팀 업무 정책이나 새 실행 허용이 아니다. v1에 legacy Binds가 있으면 assemble에서
SESSION_LEGACY_BIND_POLICY_REQUIRED로 중단하여 journal claim이나 up에 진입하지 않는다.

preservation.baseline의 정확10개 HostConfig.Binds를 사용해 주소 외 서비스 필드 비교 후,
기존 source/target/rw 또는 ro/z 또는 Z가 모두 같은 bind만 create_host_path=true로 바꾼다.
추가·누락·중복 target, 임의 source, propagation/recursive 등 다른 옵션은 거부한다.
기존 HostConfig.Mounts가 이미 있는 경우 v2 경로로 임의 전환하지 않는다.
단독 consumer에 true를 주거나 별도 경로 pin 없이 true를 주는 것도 거부한다.

`bind_sources`는 실제 source별 `/`부터 최종 항목까지 관측한 component 목록이다.
각 component의 device/inode/uid/gid/mode/directory/selinux를 검토해 고정한다.
없음·symlink·추가 xattr/ACL·파일 hardlink·group/other writable·특수 mode는 거부한다.
경로를 자동 생성하거나 권한/label을 고치는 명령은 없다. 앱이 쓰는 디렉터리의 내용과
mtime/ctime은 이 metadata 검사 대상이 아니며 파일 내용 보존을 입증하지 않는다.

host 대조와 PinnedCompose의 **각 process 직전/직후**에 이 경로들을 다시 확인한다.
단, descriptor 검사는 Docker가 경로를 여는 순간까지 잠그는 원자적 보장이 아니다.
동시에 권한 있는 다른 주체가 경로를 삭제하면 legacy Docker API가 생성할 수 있는 잔여
TOCTOU가 있다. 기존 비중첩 확인을 유지하며, 변화가 발견되면 다음 앱 변경을 중단한다.
이 한계를 ‘새 경로가 절대로 생성되지 않음’으로 표현하지 않는다.

## 설정 해석과 전체 보존 비교

명시 true를 전달해도 고정 Compose5.6.0의 config 출력에서는 true 필드가 생략된다.
17:09 실제 읽기에서 이30곳의 정해진 직렬화 차이만 적용한 전체 기대 모델과 일치했다.
false는 생략하지 않는다. 출력에서 기대값을 학습하지 않고, render 결과를 up 입력으로
재사용하지 않는다. up에는 검토한 명시 true의 동일 stdin bytes를 사용한다.

HostConfig는 unique-target Binds/Mounts 배열의 순서만 정렬해 비교한다. 옵션·경로·RW·
알 수 없는 필드 값은 그대로 비교하고 중복 target은 두 배열 사이에도 거부한다.
상속 anonymous volume은 기존 이름/target/RW와 정확히 일치해야 한다. false 생략 여부는
별도 검토한 after_host_mounts 입력으로 고정하며 사후 inspect로 채우지 않는다.
기존 7volume Mode ''→z profile 외 effective Mounts 변경은 계속 거부한다.

volume collector는 root 소유 부모를 유지하고 마지막 _data의 앱 소유를 읽어 반환한다.
uid/gid/mode/context는 별도 검토 profile과 반드시 같아야 하며 임의 소유 변경을 허용하지 않는다.

## 실행 순서·중단·검증 한계

1. exact source/input 독립 검토 후 새 버전 코드·보호 입력을 기존 공급물과 다른 새 경로에 준비한다.
   이전 source 공급 marker·PR44 사용 claim·원 Compose·raw/sealed를 덮어쓰거나 재사용하지 않는다.
2. 실제 source/parent metadata와 현재10개 상태를 입력에 결속하고 verify/preflight를 수행한다.
   차이·인증 실패·기한 초과 시 다음 단계0. 사용자가 확정한32분10초 예산을 연장하지 않는다.
3. 검토/병합 뒤 기존 운영 허용 범위의 일회성 unit으로 앱9개 각 최대1회만 요청한다.
   실패 시 다음 앱0, journal/evidence·부분 상태 보존. 자동 stop/retry/restore/chown/relabel0.
4. 실제 새 ID·주소·healthy·전체 보존/원본 hash·sealed 증적을 확인해야 Runtime 주소 변경 결과다.
   source 공급/config rc0/정적·모의·CI 통과는 Runtime/manager/H6/AC 성공이 아니다.

검증은 원본 구현과 운영 metadata 대조, 실제 config 읽기, 합성 Engine/모델과 Linux 임시
root 경로의 fd/권한/xattr 검사로 구분한다. 실제 container create/up·SELinux 변경·데이터 복원은
이 수정의 시험에서 수행하지 않았다. 실제 실행 입력과 독립 검토·병합은 별도 잔여다.
