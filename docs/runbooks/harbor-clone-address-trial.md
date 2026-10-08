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
검토된 trial.py, checker.py, override.json을 root 전용 bundle에 전달하고 SHA를 확인한다.
checker/override는 각각 병합 #12의 SHA로 실행 코드에 고정되어 있다.

```bash
sudo python3 /root/<verified-bundle>/trial.py apply \
  --bundle /root/<verified-bundle> --work /root/hbr-address-trial-<RUN>
```

apply는 새 작업 폴더에 한 번만 허용한다. fresh render 비교, 컨테이너 집합,
10개 healthy, restart always, bind mount, 로컬 태그 image ID와 현재 실행 image ID
일치를 확인한다. 이미지 드리프트가 있으면 작업을 진행하지 않는다.
정확히 앱 서비스 9개만 `up -d --no-deps --force-recreate --pull never`로 재생성한다.
log 컨테이너는 재생성하지 않고 기존 데이터 bind 경로를 재사용한다.
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
sudo python3 /root/<verified-bundle>/trial.py restore \
  --bundle /root/<verified-bundle> --work /root/hbr-address-trial-<RUN>
```

restore도 회차당 한 번이다. 최초 apply 직전 snapshot을 사용하므로 일부 앱이 없어져도
복구할 수 있다. logger는 기존 ID의 healthy 상태여야 하며 그렇지 않으면 자동으로
확대 변경하지 않고 중단한다. 원 이미지 태그가 달라졌어도 중단한다.
원 주소/이미지/데이터 경로·나머지 설정 및 건강 상태를 대조한
ORIGINAL_ADDRESS_RESTORED_HEALTHY까지만 보고한다. 업무 데이터 정합성은 별도 확인한다.

## 검증·다음 단계

STATIC/MOCK 12건: 정확한 주소 변화, 이미지 태그 드리프트, 비정상 health,
이미지/포트/restart/mount/logging 변화 거부, logger 재생성 거부, 앱 미재생성 거부,
다른 호스트/UUID 거부, 실행 흐름 한 번·실패 후 재시도 없음,
일부 앱이 없는 상황에도 최초 snapshot으로 원복하는 경로.
이 모의시험은 실제 Docker/복제본 조작을 하지 않는다.

후속 Docker restart 1회 및 VM reboot는 A2 결과를 받은 뒤 별도 단계로 기록한다.
주소 후보만으로 logger 준비 경쟁이 해소됐다고 가정하지 않는다. 기존 restart always와
systemd 관리자 등을 함께 바꾸지 않는다. 이번 PR에는 재시작 시험 실행기가 없다.
