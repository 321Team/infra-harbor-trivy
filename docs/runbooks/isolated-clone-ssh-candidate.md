# 격리 Harbor clone 전용 SSH — 설치·세션·복구 검토 후보

책임 티켓: baseline#13. 2026-10-08 23:29 KST 사전 수집 결과를 반영한다.
사용자는 전용 SSH 준비 및 설치·복구 구현에 착수하도록 지시했다. 이 PR은 설정 생성,
제한된 조회와 `hbr-ssh-lifecycle.py`의 소스 검토 범위다.
실제 VMnet/NIC/계정/키/방화벽/SSH 설치·reload는 수행하지 않았다.

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

### NIC 이름의 사전 확정과 실제 확인

무NIC 설치 전에 VMware PCI 슬롯 기반 이름(ens160 등)을 추측하지 않는다.
새 실행 후보는 **전용 이름 `hbrmgmt0`**과 할당할 MAC을 입력으로 사용하고,
`/etc/systemd/network/10-hbr-mgmt.link`에 그 MAC만 매칭하는 이름 규칙을 설치한다.
`NamePolicy=`를 비워 기존 이름 정책보다 명시적 Name을 사용하고,
`MACAddressPolicy=none`으로 MAC을 변경하지 않는다. 이 이름은 적용 전에는
계획값이며, 실제 hotplug 후 이름/MAC/unmanaged/down/주소 없음이 확인되어야 한다.

installer는 기존 인터페이스 이름 충돌, udevadm 부재, 동일 이름 .link 및 drop-in을
4개 systemd network 경로에서 발견하면 쓰기 전에 중단한다. `/etc/systemd/network`
자체가 없으면 기존 INSTALL_PARENT_MISSING으로 중단하며 임의 디렉터리를 만들지 않는다.
NM 자동 연결 차단 후 udev 설정만 reload하고 **udevadm trigger는 실행하지 않는다**.
기존 Docker bridge/veth/lo를 이름 변경하거나 NIC를 설치 코드에서 생성하지 않는다.

더 먼저 매칭되는 다른 .link 또는 udev 규칙 때문에 이름이 달라질 가능성은 실제
CentOS hotplug에서 확인한다. 이름이 예상과 다르면 세션의 NIC_SET 검사가
claim 생성/IP 부여/link up 전에 거부한다. 설치 성공만으로 이름 지정 성공을
주장하지 않는다. 이 경우 NIC 제거 후 콘솔 rollback하고 증적을 검토한다.
rollback은 소유 .link 해시가 변경되면 거부하며, NIC 없는 상태에서 이번 파일만
삭제하고 udev 설정을 reload한다. A3 Docker/VM 재시작은 수행하지 않는다.

2026-10-09 01:08 KST Windows VMnet2 Up/192.168.253.1/24, IPv4 DHCP·IPv4/IPv6
forwarding off, 기본경로 없음, clone NIC FALSE를 확인했다. 이는 NIC hotplug,
인증·격리·만료·rollback 검증을 대신하지 않는다. IPv6 호스트 기본 설정이 일부 남아
있으며 guest IPv6 차단과 패킷 시험은 기존 세션 검증 범위로 유지한다.

| 파일 | 의도 및 설치 전 확인 |
|---|---|
| .link 후보 | 지정 MAC만 전용 이름으로 결속. 이름 충돌/동명 설정/drop-in 거부. NIC 없는 상태에서 설치·reload, 실제 이름은 hotplug 이후 검증. |
| nft 후보 | 관리 interface의 INPUT은 host→guest22만, OUTPUT은 해당22 응답만 허용. 해당 interface 양방향 FORWARD 전부 drop. IPv6도 마지막 interface drop에 포함. Docker/기존 테이블 flush 없음. |
| firewalld zone 후보 | 관리IP/접속원22 rich rule 외 target DROP. 관리 NM profile에 zone 연결. nft accept 뒤에도 firewalld 등 후속 chain이 처리하므로 두 계층 모두 검사. |
| NM 후보 | 원래 MAC 결속 프로파일은 비교 참고용이며 installer가 로드하지 않는다. 설치 설정은 신규 wired 자동 프로파일 생성 금지 및 ethernet 장치 managed=0이다. 잘못된 MAC의 NIC를 꽂아도 DHCP 자동 활성화되지 않도록 범위를 넓혔다. 관리 IP는 별도 세션이 검증 후 일시 부여한다. 기존 Docker bridge/veth 영향은 target에서 재확인한다. |
| SSH Match 후보 | 관리 LocalAddress에서 전용 사용자/접속원, key-only, root·TTY·forwarding·user rc 금지. root-owned authorized_keys, 외부 키 명령/CA 없음. 강제 명령 고정. |
| 조회 endpoint | identity/network/services만 정확히 허용, 임의 명령·인자·shell·SFTP/SCP·sudo·Docker API 불허. hbrctl의 비특권 UID로 실행. 고정 argv/환경, stdin 차단, 10초 및 만료 timeout. |

원격 Docker 상세 inspect/journal 수집과 Runtime 변경 명령은 이 endpoint에 없다.
추후 필요하면 별도로 검토한 고정 privileged wrapper만 추가한다.
현재 세 명령의 성공을 Harbor 건강 또는 Runtime PASS로 표시하지 않는다.

## 설치·1회 세션·복구 코드

- **install:** root/호스트명/clone UUID/SELinux Enforcing/HGFS 없음/물리 NIC 없음을 확인한다.
  기존 설치 이력·계정·그룹·동명 파일/테이블이 있으면 중단한다. 번들 바이트를 같은 소스의
  생성기로 재생성해 대조하고 기존 Ethernet 프로파일 집합도 확인한다.
  `/var/lib/hbr-ssh-control`에 기존 주소/라우트·변경할 autoconnect 값·명령/rc·설치 파일 해시를
  남긴 후 두 운영 프로파일의 autoconnect를 끈다. root 소유 전용 파일·계정·별도 nft 테이블을
  설치하고 NM config reload, firewalld reload, sshd 구문/4개 문맥 검사 후 sshd reload를 한다.
  Docker 재시작이나 NM 연결 활성화는 없다. 정상 결과는 `INSTALLED_LINK_DISABLED`다.
- **session:** 10분 이내 호스트 확인서, 미만료, 설치 파일 해시, 전용계정/그룹,
  물리 NIC 한 개·MAC·unmanaged·주소 없음/down, 기존 운영 autoconnect off, 방화벽
  테이블/zone, 만료 timer, SSH 유효 설정을 확인한다. `session.claim`을 배타 생성한 후에만
  관리 NIC의 IPv6를 비활성화하고 IPv4 주소를 추가한 뒤 link up 한다.
  세션 중 주소/라우트/NIC/방화벽 및 호스트 조건을 반복 확인하며 변동 시 종료한다.
  Docker와 다른 인터페이스의 주소/라우트는 설치 전 기준과 비교한다.
- **만료/종료:** 절대 UTC 시각의 systemd timer와 세션 만료 검사를 병행한다.
  timer/ExecStopPost는 먼저 고정 관리 link를 내리고 전용 사용자 프로세스를 종료한다.
  endpoint 자체도 만료 후 호출을 거부한다. unit은 enable하지 않아 부팅 시 세션이
  자동 시작되지 않는다. `SESSION_STOPPED`는 연결 종료이며 파일·계정 완전 철거를 뜻하지 않는다.
- **rollback:** 호스트에서 NIC를 제거하여 guest physical NIC가 없는 상태에서만 허용한다.
  설치한 파일의 해시가 바뀌었으면 삭제하지 않는다. 세션/timer를 중지하고 이번에 생성한
  계정·그룹·파일·테이블만 제거한 뒤 두 운영 프로파일의 원래 autoconnect=yes를 복구한다.
  private receipt와 claim은 보존한다. 설치 중단/부분 파일·계정 생성의 불확실성이 있으면
  `*_DRIFT` 또는 `*_NEEDS_MANUAL_REVIEW`로 중단하며 강제로 덮어쓰거나 재설치하지 않는다.

코드는 설치/세션/원복을 자동 이어 실행하지 않는다. 첫 설치 성공 뒤에는 호스트에서
승인된 VMnet/MAC의 NIC만 추가하고, 연결 시작은 VM 콘솔에서 systemd unit으로 수행한다.
세션 함수를 콘솔 Python으로 직접 실행하지 않는다(ExecStopPost 보호를 받지 못함).
변경 중 다른 사람이 VM/NIC/NM/방화벽을 동시에 조작하지 않는 조건이다.

모든 설정 후보가 승인된 뒤 사용할 명령 형식(현재 실행 지시 아님):

```bash
# source/bundle은 /root 아래에 복사·해시검수하고 HGFS를 닫은 뒤 사용한다.
sudo python3 -I /root/<approved-source>/hbr-ssh-lifecycle.py install --bundle /root/<approved-bundle>
# host-gate.json을 실제 확인값으로 저장한 뒤, 승인된 NIC를 추가하고 콘솔에서 실행한다.
sudo systemctl start hbr-ssh-session.service
# 즉시 연결 종료
sudo systemctl stop hbr-ssh-session.service
# 호스트에서 NIC를 제거하고 source 원본이 보존된 콘솔에서 원복
sudo python3 -I /root/<approved-source>/hbr-ssh-lifecycle.py rollback
```

호스트 확인서 경로는 `/var/lib/hbr-ssh-control/host-gate.json`이다. root 소유/비쓰기 권한,
`vmnet="VMnet2"`, `host_only=true`, `dhcp/nat/bridge/other_guests/host_forwarding=false`,
`host="192.168.253.1"`, `guest="192.168.253.2"`, 실제 `mac/interface`, 현재 `checked_epoch`를
담는다. 이 파일은 **운영자 확인 기록**이며 guest가 Windows의 실제 설정을 독립 검증했다는
뜻이 아니다. 템플릿에 true를 채워 호스트 검증을 대신하지 않는다.

## 실제 연결까지 남은 필수 단계

1. VMnet2 실제 host-only 설정, DHCP/NAT/bridge 없음, 참여 VM, host adapter .1,
   host forwarding/ICS 부재, 고유 MAC과 guest interface를 확정한다.
   이번 host inventory 범위는 VMware 등록 목록과 두 프로젝트 디렉터리의 VMX이며
   등록되지 않은 모든 디스크/VM을 전수 검사했다는 뜻은 아니다.
2. console에서 NIC 분리 상태로 NM/SSH/firewall 원본과 소유권·모드·SELinux context를
   보존한다. 운영 프로파일 두 개의 autoconnect만 비활성화하고 재조회한다.
3. 구현한 installer/rollback의 exact SHA를 리뷰하고 격리 조건에서 검증한다.
   hbrctl은 wheel/docker/sudo 권한을 받지 않는다.
   계정 잠금/만료/PAM이 publickey 접속에 미치는 영향도 guest에서 확인해야 한다.
4. 기존 sshd Include 순서와 Match 우선순위, TrustedUserCAKeys 등 옵션 지원을
   실제 CentOS에서 `sshd -t` 및 모든 관련 user/local-address/source 조합의
   `sshd -T -C`로 확인한다. 관리IP에서 server08/root/암호/CA key가 거부되어야 한다.
   key 파일은 hbrctl이 읽을 수 있으나 수정할 수 없어야 한다. sshd 현재 전역 wildcard
   listen은 유지되므로 firewall 및 단일NIC 검증이 전제다.
5. 실제 CentOS nft/firewalld/NM 및 unit/timer 검증, 부팅 후 unmanaged/down 유지,
   설치 실패/서비스 중단/만료 시 연결 해제를 확인한다. 현재 세션은 firewalld/NM에
   BindsTo/After로 결속되고 기존 nft 표와 비교하지만, root가 nft 규칙을 임의로 지운
   순간부터 감지까지의 공백이 없다고 보장하지 않는다. 주기검사는 원자적 방화벽 보호가
   아니므로 이 세션 중 별도 규칙 변경·Docker 재기동·VM 재부팅은 허용 범위가 아니다.
6. NIC 없는 전달 단계를 끝내고 HGFS를 닫는다. 새 관리 환경 profile guard에서
   VM UUID·단일 관리NIC/MAC/IP·운영IP/기본경로 부재·방화벽을 검증한다.
   새 guard는 SSH 관리 세션 전용이며 기존 A3 무NIC guard를 완화하지 않는다.
7. exact SHA 검토 및 단계 범위 고정 후 연결. host key를 사전 지문과 대조하고
   strict host key checking으로 허용 조회·다른 사용자·암호·포워딩·다른 포트·IPv6·
   guest 신규 외부 연결·Docker forwarding 차단을 실제 검증한다.
8. timer는 link down과 전용 사용자 프로세스 종료를 수행하며 정확한 실시간 실행을
   보장하는 장치는 아니다(AccuracySec=1s 및 OS 스케줄링 지연). 만료·SIGTERM·실패·
   service stop의 실제 연결 해제/재연결 거부와 별도 rollback을 확인한다. 키/계정/규칙
   완전 철거와 IPv6 interface 상태 초기화는 NIC 제거 후 rollback 범위다.

## 중단과 복구

예상 밖 운영주소·라우트·NIC·규칙 또는 비허용 접속이 보이면 호스트에서 관리NIC를
먼저 분리한다. 콘솔로 이번 SSH/관리망 변경만 복구하고 원본 비교를 남긴다.
운영 프로파일 autoconnect 원복은 NIC 분리 확인 후에만 한다. Docker restart,
컨테이너 재생성, claim 삭제, snapshot restore는 이 복구 범위가 아니다.

## 검증 범위

Python 입력/명령 거부·만료·파일 무결성 및 설치/실패/원복 시뮬레이션은 STATIC/MOCK이다.
CI의 Ubuntu sshd/nft 실제 파서는 별도 단계이며 CentOS target 검증을 대신하지 않는다.
CentOS sshd/nft/firewalld/NM 파서, 실제 계정/키 인증, 패킷 차단, 권한·만료·복구는
미실행이다. `.candidate` 파일/plan.json은 배포 승인이 아니다.

공식 근거: [OpenSSH Match/ForceCommand](https://man.openbsd.org/sshd_config.5),
[systemd.link MACAddress·NamePolicy·Name](https://github.com/systemd/systemd/blob/v257/man/systemd.link.xml),
[NetworkManager profile](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-nmcli.html),
[no-auto-default](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/NetworkManager.conf.html),
[nftables chain verdict](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains).
