# Harbor 작업 복제본 — 주소 후보 소비·원복

baseline #13, 병합 #12/#13/#14, 증적 #159 후속. CODEX_ASSISTED.
이번 소스는 후보 적용을 위한 새 실행 코드다. 기존 부품 승인에 포함됐다고 표시하지 않는다.
실행 전 본 소스 SHA의 독립 리뷰를 받고 전달된 파일 SHA를 대조한다.

## 확인된 시작점

2026-10-08 14:21:56 KST 복제본 A1: 승인 검증기로 구성 차이 정확히 9개 PASS,
10개 컨테이너 running/healthy, logger IPv4 listener 확인. Compose 원본 SHA 유지.
관측 1회이며 자동기동·실제 로그 수신 PASS가 아니다.

대상: `D:\FDS-Isolated-Lab\harbor01-20261008\harbor01-test.vmx`.
UUID bios bytes `56 4d 9e 38 f0 24 ef e2-b6 8f 13 7a 50 47 78 8a`.
게스트 UUID의 SMBIOS byte-order 표기 두 형태만 허용한다. root, hostname harbor01,
물리 NIC 없음, 원 Compose 해시를 확인한다. 운영 Harbor와 수신 원본은 대상이 아니다.

## 실행·성공·실패

기존 server08 콘솔의 sudo를 사용한다. 암호 입력과 결과 기록을 분리한다.
검토된 `scripts/verify/clone-address-trial.py`는 전달·실행 이름도 `clone-address-trial.py`로 유지한다.
checker.py, override.json과 함께 root 전용 bundle에 전달한다. 승인 HEAD의 Git blob SHA256을
인계 기록에 명시하고 전달본 및 결과 `source_sha256`과 대조한다. 파일명 변경으로 혼동하지 않는다.
checker/override는 각각 병합 #12의 SHA로 실행 코드에 고정되어 있다.

```bash
sudo python3 /root/<verified-bundle>/clone-address-trial.py apply \
  --bundle /root/<verified-bundle> --work /root/hbr-address-trial-<RUN>
```

apply는 새 작업 폴더에 한 번만 허용한다. fresh render 비교, 컨테이너 집합,
10개 healthy, restart always, 기존 bind mount 및 아래 제한된 local volume,
로컬 태그 image ID와 현재 실행 image ID
일치를 확인한다. 이미지 드리프트가 있으면 작업을 진행하지 않는다.
정확히 앱 서비스 9개만 `up -d --no-deps --force-recreate --pull never`로 재생성한다.
log 컨테이너는 재생성하지 않고 기존 데이터 bind 경로와 volume을 재사용한다.
Docker daemon restart, reboot, prepare/down, 볼륨 삭제·외부 pull·보안 완화는 없다.

변경 명령은 최대 120초, 상태 회복은 추가 180초 관측 상한이다(개별 조회 최대35초).
기한 내 모두 healthy이며 앱 ID 변경·logger ID 보존, 이미지·mounts·ports·restart 및
주소 외 logging 옵션 보존이 맞아야 ADDRESS_APPLIED_HEALTHY다. compose/health 확인만으로
서비스 전체 기능·로그 수신·자동기동을 PASS로 올리지 않는다.

STOP_BEFORE_CHANGE이면 이 실행기의 변경 명령은 시작하지 않았다.
STOP_RECOVERY_REQUIRED이면 일부 변경 가능성이 있으므로 반복 apply하지 않는다.
해당 폴더의 명령별 rc·시각·정제 전후 inspect와 stdout/stderr를 먼저 보존한다.
timeout은 명령 완료 여부가 불확실하므로 진행 중인 compose가 없는지도 확인한다.
인증정보가 있을 수 있는 Compose 렌더링과 stderr는 root 전용 작업 폴더에만 보존한다.

후보를 되돌릴 때는 파일만 삭제하지 않고 원 Compose로 앱을 다시 생성한다.

```bash
sudo python3 /root/<verified-bundle>/clone-address-trial.py restore \
  --bundle /root/<verified-bundle> --work /root/hbr-address-trial-<RUN>
```

restore도 회차당 한 번이다. apply 상태가 ADDRESS_APPLIED_HEALTHY 또는
STOP_RECOVERY_REQUIRED일 때만 허용한다. STOP_BEFORE_CHANGE에는 restore하지 않는다.
최초 apply 직전 inspect를 기준으로 현재 10개 컨테이너와 mounts/image/ports/restart/logging을
대조한다. 일부 앱이 사라졌거나 volume이 달라졌으면 **변경 전에 중단한다**.
logger는 기존 ID의 healthy 상태여야 하며 원 이미지 태그가 달라졌어도 중단한다.
실행 전에 작업 사본 VMware 스냅샷의 생성 완료를 확인한다. restore가 막히거나 실패하면
실패 원본을 먼저 회수하고 해당 스냅샷 복구 경로를 사용한다. 운영 VM/수신 원본은 대상이 아니다.
스냅샷 시점 이후 전달 번들·결과는 사라질 수 있으므로 먼저 보존한다.
원 주소/이미지/데이터 경로·나머지 설정 및 건강 상태를 대조한
ORIGINAL_ADDRESS_RESTORED_HEALTHY까지만 보고한다. 업무 데이터 정합성은 별도 확인한다.

## 검증·다음 단계

STATIC/MOCK 24건: 정확한 주소 변화, 이미지 태그 드리프트, 비정상 health,
이미지/포트/restart/mount/logging 변화 거부, logger 재생성 거부, 앱 미재생성 거부,
다른 호스트/UUID 거부, 실행 흐름 한 번·실패 후 재시도 없음,
실제 회수 mount layout 9개, volume identity/options/경로 드리프트,
존재하지 않는 volume 또는 restore 대상 컨테이너에서 변경 전 중단,
STOP_BEFORE_CHANGE의 restore 금지, 재생성 timeout rc124에서 재시도 없음.
이 모의시험은 실제 Docker/복제본 조작을 하지 않는다.

후속 Docker restart 1회 및 VM reboot는 A2 결과를 받은 뒤 별도 단계로 기록한다.
주소 후보만으로 logger 준비 경쟁이 해소됐다고 가정하지 않는다. 기존 restart always와
systemd 관리자 등을 함께 바꾸지 않는다. 이번 PR에는 재시작 시험 실행기가 없다.

## A2 실제 중단을 반영한 volume 보존

2026-10-08 15:21:38 KST 최초 A2는 `UNEXPECTED_NON_BIND_DATA`로 변경 전에 중단했다.
당시 구성 차이 9개 PASS, 읽기 명령13개 rc0, 10개 healthy였다. 모든 mount가 bind라는
기존 실행기의 가정과 달리 다음 경로에서 local volume 9개가 회수됐다.

| 서비스 | 기존 volume 목적지 |
|---|---|
| portal / proxy (각3개) | /run, /var/cache/nginx, /var/log/nginx |
| registryctl | /var/lib/registry |
| log (재생성하지 않음) | /run, /etc/logrotate.d |

이 목록에 한해 기존 64자리 소문자 hex 이름, local driver, 정확한 Docker volume 경로,
RW/Mode/Propagation을 검사한다. 실제 volume inspect에서 이름·Mountpoint·scope local·
driver local·driver 옵션 없음까지 확인하고, 일부라도 다르면 변경 전에 중단한다.
DB /var/lib/postgresql/data 등 다른 목적지의 volume이나 tmpfs를 일반 허용하지 않는다.

[Docker Compose 공식 설명](https://docs.docker.com/reference/cli/docker/compose/up/)의
기존 컨테이너 volume 상속 동작을 사용하며 `--renew-anon-volumes`/`-V`를 넣지 않는다.
변경 후에는 volume Name/Source를 포함한 전체 mount 필드가 전과 같아야 한다.
이 문서와 모의시험은 복제본의 실제 새 Compose 실행을 증명하지 않는다.

최초 중단 회차는 원본으로 봉인한다. 수정 코드의 새 HEAD 독립 리뷰와 Lead 시험 판단 후에만
새 RUN으로 진행하며, 기존 apply.claim을 삭제하거나 같은 회차를 다시 실행하지 않는다.

## A2R1 STOP 후속: 이번 회차에 한정한 검사·복구

2026-10-08 16:20 A2R1은 앱9개를 재생성한 뒤 `PRESERVATION_MOUNTS`로 중단했다.
[evidence #166](https://github.com/321Team/fds-project-evidence/pull/166)의 독립 리뷰는
원본 STOP 및 관측된 local volume 7개 Mode `''→z` 해석을 수용했다.
이 해석은 과거 xattr 보존의 직접 증명, 자동기동 성공 또는 재시작 GO가 아니다.
봉인된 결과를 PASS로 고치지 않는다.

이번 opt-in `--a2r1-mode-profile`은 **기존 A2R1의 check-current/restore에만** 적용한다.
apply에서 사용하면 변경 전 거부한다. 기본 apply/restore의 엄격한 Mode 비교는 유지한다.

- 원본 작업 경로 `/root/hbr-address-trial-20261008-1607`과 `apply-result.json`
  SHA256 `b8e8c1966424f43f3a5daa36276a579f595f09f094b09c4d537252af5e74c988` 고정.
- 현재 10개 상태는 원본의 after와 완전히 같아야 한다(모두 running/healthy 포함).
  Mode 예외는 portal3/proxy3/registryctl1의 **기존 이름/경로가 보존된 7개**에만 적용.
  logger2개 volume, 모든 bind, Source/Name/Driver/RW/Propagation은 여전히 동일해야 한다.
- 새 조회로 Docker29.8.0/GitCommit3ce5872, Compose5.5.1, 원 DockerRootDir/driver/
  SecurityOptions, 호스트 Enforcing, 영향3개 컨테이너의 빈 MountLabel/ProcessLabel,
  SecurityOpt null/Privileged false를 확인한다.
- 9개 volume 디렉터리의 현재 xattr `system_u:object_r:container_file_t:s0`를 읽는다.
  복구 후에도 같은 조건을 다시 검사한다. 이것은 **이번 복구 전후의 현재값 대조**이며
  최초 A2R1 변경 전 xattr를 소급 증명하지 않는다. 보안 설정/라벨은 수정하지 않는다.
- 마지막 상태 재조회가 달라도 중단한다. 일부 기록/명령 실패를 PASS로 간주하지 않는다.

새 HEAD 독립 리뷰·번들 SHA 확인 후, 격리 VM의 server08 콘솔에서 우선 읽기 전용 확인:

```bash
sudo python3 /root/<reviewed-bundle>/clone-address-trial.py check-current \
  --bundle /root/<reviewed-bundle> \
  --work /root/hbr-address-trial-20261008-1607 --a2r1-mode-profile
```

`CANDIDATE_METADATA_VERIFIED`는 후보 메타데이터 조건 확인이다. 기존 apply 결과는 그대로이며
새 `/root/hbr-a2r1-check-*`에 정제 조회/rc/시각/소스 SHA를 보존한다. checker/override는
기존 작업 폴더의 승인 SHA를 검사한다. root 전용 stdout/stderr와 Compose 렌더링은
그대로 공개하지 말고 기존 증적 수집·비밀정보 검수 절차로 회수한다.

복구를 별도로 선택했을 때만 같은 명령의 mode를 `restore`로 바꾼다. 이 경로는 원 주소로
앱9개 재생성 1회이며, **현재 healthy 후보를 일부러 되돌리는 다음 기본 작업이 아니다.**
복구 직전 앱ID와 비교해 실제 재생성을 확인한다. timeout rc124/중단 rc130이면
`STOP_RECOVERY_REQUIRED`와 원본을 보존하고 반복하지 않는다.
복구가 시작되기 전에 STOP되어도 restore.claim을 지워 재사용하지 않는다.

## 다음 A3 Docker restart 시험의 인계 조건

이번 PR은 위 검사/복구 소스 검토다. Docker restart 실행기는 포함하지 않으며
소스 승인만으로 daemon restart나 VM reboot를 실행하지 않는다.
현재 healthy IPv4 후보를 유지한 채 다음 실행 묶음을 검토할 때 아래 항목을 모두 고정한다.

1. 대상 VM/UUID 일치, 물리 NIC 없음, 호스트 HGFS share 0/비활성 및 게스트 공유 mount 해제.
   `before-address-A2-20261008-1500` 스냅샷의 15:17:11 KST 완료 로그와 저장 위치 확인.
   스냅샷 복구는 아직 미시험이며 VMrun 종료코드0을 확인한 것으로 쓰지 않는다.
2. 위 check-current의 fresh 결과, 10개 healthy/IPv4 listener, boot ID,
   Docker unit 상태와 승인 observer SHA
   `ac9d42efbcd4f18effc2bcd7a819af29d7cc6aaa5cbd13c94fbd05e37f39e1e1`를 같은 RUN에 결속.
3. observer를 먼저 시작하고 첫 정상 표본을 확인한 뒤 T0와 재시작 명령의 시작/종료/rc를 기록.
   Docker restart는 정확히1회, VM reboot·수동 앱 start·Compose 재생성·자동 복구는 함께 하지 않는다.
   관측 상한/명령 timeout을 실행 코드에서 고정하고 관측 중 비정상 상태도 원본으로 보존한다.
4. 관측 종료 후 같은 boot ID, 컨테이너 ID/이미지/mount/logging/restart 보존,
   10개 running/healthy, logger IPv4 listener 및 T0 이후 Docker journal을 회수한다.
   observer의 running 표본이나 조회 rc만으로 autostart PASS를 결정하지 않는다.
   재시작 중 일시 조회 실패와 영구 기동 실패를 원본 시각으로 구분한다.
5. 실패 시 먼저 증적을 회수한다. unhealthy/변경된 후보는 이 profile restore의 조건에
   해당하지 않는다. 반복 재시작이나 강제 우회 대신 검토된 **스냅샷 복구 경로**를 사용한다.
   스냅샷 이후 번들·로그는 복구 시 사라지므로 host에 무결성 검수 후 보존한다.
6. AUTOSTART, SYSLOG_INGESTION, 업무 데이터 정합성, AC/Close는 각각 별도 판정한다.
   이 단계의 새 실행 코드·실행 창·관측/복구 절차는 독립 리뷰 후 인계한다.

검증: 기존24건 + 실제 봉인된 STOP fixture를 사용한 profile 모의시험12건(총36건).
정상7개 Mode 비교, 그 외 필드/Mode/보안/버전/xattr 변경 거부, prior 해시 변조 거부,
읽기 전용 경로의 변경 명령0회, 복구1회 및 timeout/interrupt 후 재시도0회를 포함한다.
Docker/게스트 Runtime은 이 모의시험에 포함되지 않는다.
