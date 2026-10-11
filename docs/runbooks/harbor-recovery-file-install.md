# Phase 1 검토 패키지의 새 파일 배치

CODEX_ASSISTED · 2026-10-11. [패키지 수신 검사](harbor-recovery-package-receipt.md) 후 파일 배치만 수행하는 적용기다. 기존 생성기·패키지 형식을 보존하며 `INSTALL_PLAN.apply=NOT_IMPLEMENTED_REQUIRES_TARGET_INPUT_REVIEW`는 그 문서가 생성된 당시의 상태다. 적용기가 생겼다는 사실이 해당 패키지의 설치 허용이나 현장 입력 검토를 대신하지 않는다.

## 실행 범위와 전제

`scripts/preparation/harbor_review_package_install.py`는 Linux3.10+의 신뢰된 Python/stdlib와 **별도로 검토·인증한 installer checkout 전체**에서 실행한다. installer·receipt validator·의존 recovery 모듈은 candidate package에서 읽거나 import하지 않는다. 이 파일 자체가 이미 실행 중인 자신/의존 모듈의 출처를 검증한다고 주장하지 않는다. PC의 읽기 전용 수신 검사 도구를 그대로 게스트에서 호출하는 절차가 아니다.

- 대상은 정확하게 승인된 **격리 Harbor 복제본**이다. 운영 Harbor를 자동 선택하지 않는다.
- 콘솔/sudo, fresh hostname/product UUID/boot ID, NIC/HGFS 없음, SELinux Enforcing, Docker/AC04 원 정본 및 비중첩을 확인한다. 기존 PC 전송 share는 실행 전에 닫고 게스트 HGFS도 해제한다.
- 승인 package16파일과 별도 외부 INSTALL_PLAN SHA256, **현재 부팅·시간·목적 디렉터리 metadata·receipt label을 담은 request 및 별도 외부 SHA256**을 받는다. 해시는 무결성 입력이며 승인 자체가 아니다.
- 목적 디렉터리와 private receipt 디렉터리는 정확 root:root/mode/SELinux·기본 ACL 없이 기존 정상 절차로 준비돼 있어야 한다. 이 적용기는 디렉터리 생성·소유/라벨 수선·SELinux 설정 변경을 하지 않는다. 디렉터리 준비 행위는 별도 실제 검토/허용 대상이다.
- 다른 root 작성자와 systemd/정책/컨테이너 작업을 배제한다. 인터프리터/도구 검증과 경로 기반 실행 사이의 악의적 root 교체를 완전 격리하는 도구가 아니다.

## 필수 request

schema는 `fds.harbor.file-install-request.v1`, operation은 `NEW_FILES_ONLY`다. 필드:

| 필드 | 실제 입력 |
|---|---|
| `plan_sha256` | 별도 보존한 정확 INSTALL_PLAN 해시 |
| `hostname`, `product_uuid`, `boot_id` | bundle 대상과 일치하는 fresh 게스트 식별. boot ID를 자동 학습하지 않음 |
| `not_before_epoch`, `expires_epoch` | 그 회차의 허용 시작·종료 UTC epoch. 종료까지 남은 예산이 충분한 경우만 실행 |
| `directories` | plan15개 payload의 직접 부모 전체와 receipt 부모의 정확 집합. 각 값 `{mode,gid:0,selinux}`. 모든 부모 체인은 root 소유·비쓰기·기본 ACL 없음 |
| `receipt_path` | 기존에 없는 `/var/lib/fds-harbor-recovery/install-receipts/<32자리 회차 ID>.jsonl`. 부모0700 |
| `receipt_context` | 해당 새 receipt 파일의 실제 예상 SELinux label. 디렉터리 label과 같다고 추정하지 않음 |

샘플 host/default label/default 예산이나 실제 값이 채워진 합성 request를 배포하지 않는다. 다른 회차의 request를 현재 부팅/승인 입력으로 재사용하지 않는다. request는 원본·외부 SHA·승인 범위/시점과 연결해 private 보관한다.

## 실행 순서와 판정

1. PC에서 exact package에 대한 기존 수신 검사, fresh 현장·폴더 준비·정확 source 및 입력 독립 검토와 이번 파일 배치 허용을 완료한다. 입력 미확정이면 여기서 보류한다.
2. 게스트에서 정확 checkout/Python 경로와 package/request 경로를 확인한다. 아래 자리표시는 실제 검토한 값으로 채운다.

```text
sudo <trusted-python> -I -S -B <trusted-checkout>/scripts/preparation/harbor_review_package_install.py
  --package <private-received-package>
  --plan-sha256 <external-approved-plan-hash>
  --request <private-reviewed-request.json>
  --request-sha256 <external-approved-request-hash>
  --timeout <reviewed-total-seconds>
  --execute
```

3. 읽기 전용 사전 검사: bundle/package15개 payload 결속, 외부 입력 파일/도구 pins, root·격리·부팅·Enforcing·nft·Docker 세대/profile·정상 Docker/guard, 기존 recovery manager 미존재/비활성·미진행 job을 확인한다. 목적 파일 또는 receipt가 하나라도 있으면 **아무 새 파일을 만들기 전에 STOP**한다.
4. 새 private receipt의 BEGIN을 먼저 동기화한다. 파일별 CREATE_INTENT → exclusive 생성 → **쓰기 전 실제 상속 label/owner/mode 확인** → bytes/fsync → 새 descriptor만 최종 mode 설정 → 해시/metadata/readback → FILE_VERIFIED 순서다. `launch.json` trust anchor는 마지막이다. 매 단계 현재 시간/현장과 디렉터리 경로 동일성을 다시 확인한다.
5. 최종 현장/모든 파일 bytes·metadata 재대조 후 `FILES_INSTALLED_ONLY`, rc0. 원본 stdout/rc/시각·private receipt와 source/입력/payload SHA를 연결한다. rc0은 파일 배치 완료만이며 Docker 정책·manager 실행·Store 초기화는 미수행이다.

적용기는 `systemctl show` 등 읽기만 호출한다. daemon-reload·enable/start/stop·Docker POST·VM reboot·원 Store 생성/변경은 호출하지 않는다. 다음 단계인 정확 unit reload/disabled readback·initialize·policy-install·arm·enable/start/H1~H8은 각각 기존 검토·실행 범위를 따르며 자동 연결하지 않는다.

## 실패·중단·복구

- 입력/경로/라벨/권한/시간/세대 drift·부족한 공간/쓰기/fsync/readback 오류면 즉시 다음 파일 중단, rc2. 전송/쓰기 실패 시 새 부분 파일과 receipt를 보존한다. 신호 중단은 rc130이다.
- receipt의 마지막 durable CREATE_INTENT는 시도 범위이며 FILE_VERIFIED와 다르다. STOP 기록 자체의 디스크/시간 오류도 가능하므로 STOP append 성공을 보장하지 않는다. 성공 최종 행이 없으면 설치 완료로 처리하지 않는다.
- **자동 전체 삭제·재시도·원복 없음.** receipt·현재 정확 파일 bytes/hash/metadata·대상 부팅/세대·source/요청 및 콘솔 인수자를 검토한 뒤 그 회차가 만든 파일의 처리만 결정한다. 기존 변경/다른 소유 파일이나 Store/claim/log를 삭제하지 않는다. 동일 이름 실행은 기존 목적 파일 때문에 중단한다.
- 일부 files가 존재하거나 manager/세대가 예상과 다르면 기존 원본을 보존하고 구체 복구 계획으로 인수한다. 새 namespace/receipt ID로 이전 실패를 우회하거나 런타임 H6 미확정 claim을 해소한 것으로 계산하지 않는다.

## 검증 경계

테스트의 package/request/host/filesystem은 SYNTHETIC이다. Linux CI의 임시 파일 시험도 실제 VM label·패키지 설치 성공을 입증하지 않는다. 실제 설치 입력·복구점·폴더/label 준비·H6 늦은 stop ACK·세대 변경/부분 정책 복구·AUTOSTART·SYSLOG_INGESTION·AC04~06 인수는 별도 잔여다. 부모 PR의 승인·sealed 원본을 수정하거나 취소하지 않는다.
