# Harbor 로깅 주소 일치 후보 — 미적용

관련: [baseline #13 분석](https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-6042409217),
[수정 준비](https://github.com/321Team/fds-project-baseline/issues/13#issuecomment-6042747313),
[증적 PR153](https://github.com/321Team/fds-project-evidence/pull/153).
CODEX_ASSISTED. HBR 책임 Lead 이하영의 검토 대상으로 준비한 혼합 코드/설정 PR이다.
기존 AC04 판정 및 가용성 위험 분리/수용 요청은 변경하지 않는다.

## 원본과 생성 경로

2026-10-08 KST 기존 harbor01/svc_ansible sudo 읽기 경로로 확인했다.

| 항목 | 확인값 |
|---|---|
| Compose | /home/server08/harbor/docker-compose.yml |
| Compose SHA256 | 0a84f57692268335eeedf45411e025d784e520bf749fa3501a3800cdfcb14ef0 |
| prepare SHA256 | 1d157d37aa2bb766d13cdb25c4e6b163202d641f729f1ea0188a59955c4f0a03 |
| prepare 이미지 참조 | goharbor/prepare:v2.13.1 |
| 현장 prepare 이미지 ID | sha256:4297b70787fde705bdf0bea6582398938b6f72de5b73a01eef3d9cfadb01a094 |

현장 prepare 해시는 공식 v2.13.1 make/prepare의 이미지 태그 dev를 v2.13.1로
바꾼 바이트의 해시와 일치한다. 원래 upstream 파일 자체와 동일하다는 뜻은 아니다.
이미지 ID만으로 upstream 소스 일치나 공급망 서명을 증명하지 않는다.

공식 버전의 [생성 함수](https://github.com/goharbor/harbor/blob/v2.13.1/make/photon/prepare/utils/docker_compose.py)는
Compose 경로에 템플릿을 렌더링하며, [템플릿](https://github.com/goharbor/harbor/blob/v2.13.1/make/photon/prepare/templates/docker_compose/docker-compose.yml.jinja)은
localhost 로깅 주소를 포함한다. 확인한 Git blob은 각각
c1c1111617496a7cf983c010ec63affef6067817,
0ccf1ace524f37aeabd35f48a8fee4090018487b이다.
생성 파일 직접 수정 대신 별도 override 후보를 준비했다.

## 변경 범위와 한계

[compose.logging-loopback.override.json](../../config/harbor/compose.logging-loopback.override.json)은
서비스 9개의 logging.options.syslog-address만 tcp://127.0.0.1:1514로 바꾼다.
JSON은 Compose가 읽을 수 있는 YAML 부분집합이며 명시적인 두 번째 -f 입력이다.
log 서비스 자체, logging driver/tag, 이미지, restart policy, 볼륨, 포트,
네트워크, TLS 및 보안 설정은 변경하지 않는다.

자동 탐색 이름이 아니므로 파일 존재만으로 적용되지 않는다. 향후 승인된 운영 명령이
원본과 override를 **명시적으로 함께** 소비해야 한다. prepare 재생성 후에도 override는
분리되어 있지만 설치/복구 명령이 원본만 읽으면 효과가 없다. 그 운영 경로는 미구현이다.

주소 일치는 당시 IPv6 연결 거부에 대한 후보 보완이다. logger 준비 전 앱 시작 경쟁,
Docker daemon restart 복구, AC04 인수는 증명하지 않는다. Compose depends_on 수정만으로
daemon 재시작 순서를 보장한다고 가정하지 않는다. 현재 restart: always와 별도의 host
시작 관리자를 무검토로 중첩하지 않는다.

## 읽기 전용 검증

위치: harbor01 승인된 기존 읽기 계정, /home/server08/harbor.
Docker Compose config JSON과 Python3 표준 라이브러리가 필요하다.
원본 해시와 검토한 override/검증기 SHA를 실행 직전에 확인한다.
설정 출력은 민감값을 포함할 수 있으므로 터미널·Git·증적에 그대로 게시하지 않는다.

아래는 config 렌더링만 수행하는 절차다. BASE/OVERRIDE/CHECKER는 검토한 절대 경로이다.
별도 셸에서 실행하며 어느 명령이든 실패하면 중단한다.

    set -eu
    umask 077
    HBR_CHECK_WORK=$(mktemp -d "$HOME/hbr-config-check.XXXXXXXX")
    cd /home/server08/harbor
    docker compose --project-directory "$PWD" -f "$BASE" \
      config --format json --no-env-resolution > "$HBR_CHECK_WORK/base.json" 2> "$HBR_CHECK_WORK/base.stderr"
    docker compose --project-directory "$PWD" -f "$BASE" -f "$OVERRIDE" \
      config --format json --no-env-resolution > "$HBR_CHECK_WORK/effective.json" 2> "$HBR_CHECK_WORK/effective.stderr"
    python3 "$CHECKER" --base-json "$HBR_CHECK_WORK/base.json" \
      --effective-json "$HBR_CHECK_WORK/effective.json" > "$HBR_CHECK_WORK/result.json"

검증기는 모든 정규화 필드를 비교하고 정확히 9개 주소 외 차이는 rc2로 중단한다.
서비스 추가/삭제, logging driver/restart/port 범위 변경, 부분 적용, 잘못된 JSON,
중복 키와 입력 크기 초과도 거부한다. 실패 결과에는 원본 값이나 traceback을 싣지 않는다.
정상은 CONFIG_DELTA=PASS, address_change_count=9, AUTOSTART=NOT_TESTED이다.
--no-env-resolution으로 env 파일 **내용**은 읽어 비교하지 않는다. 참조와 나머지 설정
필드를 비교하며 env 내용의 불변성이나 서비스 동작까지 PASS 범위를 넓히지 않는다.

원본 변경이 없어 서비스 원복은 없다. 원본 해시 변화 또는 rc2이면 소스 차이를 확인한다.
resolved JSON/stderr는 비공개로 유지하고 확인 후 해당 작업 폴더만 정리한다.
공개할 것은 정제된 결과뿐이다. up/start/restart/prepare 실행은 포함하지 않는다.

## 이번 확인 단계

- STATIC/MOCK: 합성 입력의 변경 범위·실패·민감값 비노출 시험 10건 PASS.
- 현장 읽기 전용 렌더링: 2026-10-08 02:52:15 KST, 기본/override config 두 명령 rc0.
  override는 stdin으로 전달했으며 현장 파일에 저장하지 않았다.
- CONFIG_DELTA=PASS, 정확히 9개 주소만 변경. Compose 전후 SHA256은 위 값과 동일.
- override SHA256: c67d8a652b94f9f142534d87adce70974f1f72bfe9863181a971b16f12b61d9b.
- RUNTIME_APPLY=NOT_PERFORMED, AUTOSTART=NOT_TESTED, AC04=NOT_EVALUATED.
  원본 env/Compose 전체 출력은 반출·공개하지 않았다.

## 운영 적용 전 잔여

1. HBR Lead가 주소 수정과 logger 준비/기동 경로를 포함한 방안을 선택하고 정확한
   SHA의 독립 검토를 확보한다. 현재 PR은 주소 후보와 검증기까지다.
2. 설치·복구 경로의 override 소비, 기존 image/volume/port/guard 보존,
   로그 설정 반영에 필요한 재생성 범위와 원복 설정을 확정한다.
3. 비중첩 작업창, logger TCP 수신 준비 판정, 앱 기동 주체, timeout,
   실패 통보와 수동 복구 B의 현재 유효성을 확정한다.
4. 별도 승인된 시험에서 T0 전후 logger/앱 9개의 시계열과 daemon journal을 수집한다.
   실패 시 임의 반복 시험/보안 완화 없이 중단하고 승인된 복구를 수행한다.
