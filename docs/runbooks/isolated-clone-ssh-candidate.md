# 격리 Harbor clone 전용 SSH — 검토 후보, 설치 절차 아님

책임 티켓: baseline#13. 2026-10-08 23:29 KST 사전 수집 결과를 반영한다.
사용자는 전용 SSH 준비에 착수하도록 지시했다. 이 PR은 설정 생성과 제한된 조회
명령의 소스 검토 범위다. VMnet/NIC/계정/키/방화벽/SSH 설치·reload는 수행하지 않았다.

## 범위와 확인된 환경

- 대상 VM은 `D:\FDS-Isolated-Lab\harbor01-20261008\harbor01-test.vmx`,
  BIOS UUID `56 4d 9e 38 f0 24 ef e2-b6 8f 13 7a 50 47 78 8a`인 복제본이다.
- A3 STOP 및 claim은 보존한다. 기존 `clone-address-trial.py`의 물리 NIC 금지
  guard를 바꾸지 않는다. 관리 NIC 도입 후 기존 A3 실행기를 그대로 쓰지 않는다.
- CentOS Stream 10, SELinux Enforcing, physical NIC/default route 없음.
  Docker bridge는 172.17/16·172.18/16, IPv4 forwarding=1이다.
- 운영 NM 프로파일 두 개가 ens160/autoconnect yes 및 운영IP10.1.93.54를 가진다.
  UUID는 생성기의 `OLD_PROFILES`에 고정했다. **NIC 연결 전에 보존 및 자동 연결
  비활성화가 필요하다.** 기존 bridge/lo 프로파일은 대상이 아니다.
- SSH는 wildcard22, 기존 server08 문맥에서 암호와 forwarding을 허용한다.
  public zone은 cockpit도 허용하고 TCP9090 wildcard listener가 존재한다.
  기존 AC04 DNAT443 규칙은 전용 관리망 격리를 보장하지 않는다.
- 전용 `hbrctl`은 아직 없다. 기존 server08은 wheel/docker 소속이므로 이
  계정을 무인 자동화 최소권한 계정으로 전용하지 않는다.
- 후보 대역은 VMnet2 host-only, host192.168.253.1/24, guest192.168.253.2/24.
  현재 Windows 어댑터는 VMnet1·VMnet8만 확인된다. VMnet2 이름/저장된 registry만으로
  실제 전용망·DHCP/NAT/bridge 부재를 인정하지 않는다. 대역/MAC 할당 미실행.

사전 수집 manifest SHA256:
`e588833f9c7dc339c1ef8bb812a4149754887513b5881e60665c13d1291130b6`.
[수집 리뷰](https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-6062255594).

## 구현한 후보

`render-clone-ssh-plan.py`는 확인된 관리 interface/MAC, 한 개의 Ed25519 공개키,
4시간 이내 만료를 입력받아 **새 로컬 폴더에만** 후보 파일과 manifest를 쓴다.
기존 폴더를 덮어쓰지 않으며 shell/시스템 명령을 실행하지 않는다.
테스트의 ens192/MAC/공개키는 합성 입력이며 할당 또는 실행 증적이 아니다.

| 파일 | 의도 및 설치 전 확인 |
|---|---|
| nft 후보 | 관리 interface의 INPUT은 host→guest22만, OUTPUT은 해당22 응답만 허용. 해당 interface 양방향 FORWARD 전부 drop. IPv6도 마지막 interface drop에 포함. Docker/기존 테이블 flush 없음. |
| firewalld zone 후보 | 관리IP/접속원22 rich rule 외 target DROP. 관리 NM profile에 zone 연결. nft accept 뒤에도 firewalld 등 후속 chain이 처리하므로 두 계층 모두 검사. |
| NM 후보 | 관리MAC/interface에만 결속, autoconnect false, gateway/DNS 없음, IPv6 disabled. no-auto-default는 해당MAC의 자동 DHCP 프로파일 생성을 막기 위한 후보. 기존 운영 프로파일 변경은 생성기가 실행하지 않음. |
| SSH Match 후보 | 관리 LocalAddress에서 전용 사용자/접속원, key-only, root·TTY·forwarding·user rc 금지. root-owned authorized_keys, 외부 키 명령/CA 없음. 강제 명령 고정. |
| 조회 endpoint | identity/network/services만 정확히 허용, 임의 명령·인자·shell·SFTP/SCP·sudo·Docker API 불허. hbrctl의 비특권 UID로 실행. 고정 argv/환경, stdin 차단, 10초 및 만료 timeout. |

원격 Docker 상세 inspect/journal 수집과 Runtime 변경 명령은 이 endpoint에 없다.
추후 필요하면 별도로 검토한 고정 privileged wrapper만 추가한다.
현재 세 명령의 성공을 Harbor 건강 또는 Runtime PASS로 표시하지 않는다.

## 실제 연결까지 남은 필수 단계

1. VMnet2 실제 host-only 설정, DHCP/NAT/bridge 없음, 참여 VM, host adapter .1,
   host forwarding/ICS 부재, 고유 MAC과 guest interface를 확정한다.
   이번 host inventory 범위는 VMware 등록 목록과 두 프로젝트 디렉터리의 VMX이며
   등록되지 않은 모든 디스크/VM을 전수 검사했다는 뜻은 아니다.
2. console에서 NIC 분리 상태로 NM/SSH/firewall 원본과 소유권·모드·SELinux context를
   보존한다. 운영 프로파일 두 개의 autoconnect만 비활성화하고 재조회한다.
3. root 소유·비쓰기 가능한 경로에 endpoint/policy/공개키를 설치할 구체 installer와
   rollback을 별도 구현·검토한다. hbrctl은 wheel/docker/sudo 권한을 받지 않는다.
   계정 잠금/만료/PAM이 publickey 접속에 미치는 영향도 guest에서 확인해야 한다.
4. 기존 sshd Include 순서와 Match 우선순위, TrustedUserCAKeys 등 옵션 지원을
   실제 CentOS에서 `sshd -t` 및 모든 관련 user/local-address/source 조합의
   `sshd -T -C`로 확인한다. 관리IP에서 server08/root/암호/CA key가 거부되어야 한다.
   key 파일은 hbrctl이 읽을 수 있으나 수정할 수 없어야 한다. sshd 현재 전역 wildcard
   listen은 유지되므로 firewall 및 단일NIC 검증이 전제다.
5. nft 구문검사와 firewalld/NM 유효성 검사, 별도 guard의 지속성 및 **링크가
   올라오기 전에 규칙이 존재한다는 보장**을 구현한다. firewalld reload/Docker 재기동/
   VM 부팅 때 보호가 사라지면 fail closed 하도록 해야 한다. 현재 후보에는 이
   lifecycle 구현이 없으므로 파일만 복사해 NIC를 연결하면 안 된다.
6. NIC 없는 전달 단계를 끝내고 HGFS를 닫는다. 새 관리 환경 profile guard에서
   VM UUID·단일 관리NIC/MAC/IP·운영IP/기본경로 부재·방화벽을 검증한다.
   현재 소스는 이 새 Runtime guard를 구현하거나 기존 무NIC guard를 완화하지 않는다.
7. exact SHA 검토 및 단계 범위 고정 후 연결. host key를 사전 지문과 대조하고
   strict host key checking으로 허용 조회·다른 사용자·암호·포워딩·다른 포트·IPv6·
   guest 신규 외부 연결·Docker forwarding 차단을 실제 검증한다.
8. 만료는 endpoint 신규 호출과 실행 timeout에 적용된다. SSH control master 세션,
   계정키·방화벽·NIC까지 자동 철거하지는 않는다. 별도 session teardown/정리와
   재연결 거부 실측까지 준비한 후 Runtime을 시작한다.

## 중단과 복구

예상 밖 운영주소·라우트·NIC·규칙 또는 비허용 접속이 보이면 호스트에서 관리NIC를
먼저 분리한다. 콘솔로 이번 SSH/관리망 변경만 복구하고 원본 비교를 남긴다.
운영 프로파일 autoconnect 원복은 NIC 분리 확인 후에만 한다. Docker restart,
컨테이너 재생성, claim 삭제, snapshot restore는 이 복구 범위가 아니다.

## 검증 범위

Python 입력/명령 거부·만료·파일 무결성 검증과 Linux CI는 STATIC/MOCK이다.
CentOS sshd/nft/firewalld/NM 파서, 실제 계정/키 인증, 패킷 차단, 권한·만료·복구는
미실행이다. `.candidate` 파일/plan.json은 배포 승인이 아니다.

공식 근거: [OpenSSH Match/ForceCommand](https://man.openbsd.org/sshd_config.5),
[NetworkManager profile](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-nmcli.html),
[no-auto-default](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/NetworkManager.conf.html),
[nftables chain verdict](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains).
