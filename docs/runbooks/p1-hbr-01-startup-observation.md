# P1-HBR-01 logger·앱 기동 관측 후보

책임: [baseline #13](https://github.com/321Team/fds-project-baseline/issues/13), HBR Lead 이하영.
CODEX_ASSISTED / 2026-10-08 KST. 독립 리뷰 대기용 소스 준비이며 운영 적용·재시험 GO가 아니다.
이 변경은 관측 코드와 시험·CI만 추가한다. 주소 변경 후보 [PR12](https://github.com/321Team/infra-harbor-trivy/pull/12)와 독립적인 main 기반이다.

## 목적과 기존 기준

10/7 23:12:21 Docker 재시작 후 앱 9개가 exit128, logger만 healthy였고,
T+5 이후 수동 복구 B를 사용했다. 근거는 [evidence145](https://github.com/321Team/fds-project-evidence/pull/145),
daemon 오류는 [evidence153](https://github.com/321Team/fds-project-evidence/pull/153).
당시 자동기동 FAIL·수동 복구·verifier FAIL(order) 기록은 유지한다.

기존 자료에 부족한 logger listener·health와 앱 상태의 시계열을 다음 승인된 시험에서 보조 수집하기 위한 도구다.
이 수집기는 재시작/복구를 실행하지 않으며 T+5를 새 GO나 일반 timeout 기준으로 확정하지 않는다.
수집 간격과 횟수는 관측 범위이지 성공 기준이 아니다. 승인된 T0/복구 시점과 원래 시험 기준을 별도 연결해야 한다.

## 수집 범위

- 로컬 Docker socket을 명시하고 Docker 원격 접속 환경변수를 전달하지 않는다.
- 정해진 10개 컨테이너의 ID·이름·상태·시작 시각·exit code·health 상태만 Docker format으로 조회한다.
  환경변수, health 로그, State.Error, 자격증명, 전체 inspect는 출력하지 않는다.
- ss로 IPv4 127.0.0.1:1514의 LISTEN 존재만 확인한다. 연결·로그 전송·부하·패킷 수집은 없다.
  wildcard listener는 해당 주소의 정확한 바인딩으로 인정하지 않는다.
- 호스트명, 실행 uid, 도구 파일 SHA256, 실제 명령 배열, KST 시각과 각 조회 전후 monotonic ns를 기록한다.
- 정상 종료 footer를 포함하는 JSONL만 완전한 수집으로 요약한다. 조회 실패는 기록하고 다음 지정 표본까지 계속하며 최종 rc2다.
  원문 stderr와 잘못된 응답은 민감정보 방지를 위해 수집하지 않고 오류 유형·rc만 남긴다.
- 기본 1회, 최대 61회. 표본 사이 sleep은 5~10초, 각 두 명령 timeout은 4초다.
  61회/5초의 표본 간격은 명령 소요시간을 포함하므로 정확한 5초 주기나 300초 창이 아니다.
  최댓값 61회/10초의 예산은 명령 timeout까지 약 18분 8초이며 프로세스 스케줄 지연은 별도다.
  승인 창에 맞춰 운영자가 횟수를 정한다. 상주 서비스나 자동 스케줄 등록은 하지 않는다.

## 실행 전제와 전달

대상 harbor01 / 10.1.93.54, 기존 svc_ansible 접근 및 기존 sudo 읽기 권한.
Python3 표준 라이브러리, docker, ss가 필요하다. 새로운 권한·패키지는 설치하지 않는다.
정확한 검토 SHA의 스크립트를 기존 ansible01 전달 경로로 운영자 전용 작업 폴더에 전달하고,
로컬 Git blob 바이트와 현장 파일 SHA256 일치를 확인한다. CRLF 변환을 포함한 바이트 변경을 허용하지 않는다.
결과는 운영자 전용 0700 폴더에 0600 새 파일로만 생성한다. 이미 있는 파일은 덮어쓰지 않는다.
소스 전달·결과 폴더 생성은 작업 영역에 한정하며 Compose·서비스 입력으로 사용하지 않는다.

아래는 검토 후 사용할 실행 템플릿이다. 현재 실행됐다는 뜻이 아니다.
명령은 harbor01의 고정한 작업 폴더에서 기존 승인 계정으로 실행한다.

    umask 077
    sudo -n python3 ./observe-harbor-startup.py collect --expected-host harbor01 --samples 1 --interval 5 --output ./snapshot.jsonl
    # 직전 rc를 별도 실행 기록에 보존한다. rc2이면 먼저 원인을 분류한다.
    sudo -n python3 ./observe-harbor-startup.py summarize ./snapshot.jsonl
    sudo -n sha256sum ./observe-harbor-startup.py ./snapshot.jsonl

sudo로 생성하면 결과 파일은 root 소유다. 기존 승인된 sudo 읽기 경로로만 가져오며 공개 권한으로 완화하지 않는다.
다음 시험의 연속 관측은 승인된 횟수를 --samples에 지정하고 고유한 새 출력 파일명을 쓴다.
수집 시작을 Docker 재시작 명령과 결합하지 않는다. 비중첩 창·실행 주체·T0·중단·수동 복구는 기존 별도 실행안이 담당한다.

## 판정·중단·복구

rc0 = 지정된 수집이 끝나고 조회/선택 필드 해석 오류가 없음. 서비스 정상·자동기동 성공을 뜻하지 않는다.
rc2 = 파일/입력 오류 또는 조회 실패. daemon 재시작 중의 조회 실패도 숨기지 않는다.
Ctrl+C는 rc130, 종료 footer 없는 부분 파일은 요약 불가다. 부분 원본은 보존하고 같은 파일에 재실행하지 않는다.
SIGTERM/SSH 종료도 부분 파일일 수 있으므로 footer·rc를 확인한다.
예상과 다른 대상/파일/도구 오류는 자동 수정·sudo 대체·설정 완화 없이 중단한다.
도구는 설정을 변경하지 않아 서비스 원복 작업이 없다. 시험 자체 실패 시에는 기존 승인된 복구안만 적용한다.

요약은 완전성·조회 오류·관측된 ID 변경과 해당 표본 인덱스를 보고한다.
identity_change_observed=false는 관측 표본 사이 ID 변경을 찾지 못했다는 뜻이며,
identity_comparable_samples가 0~1이면 비교 근거가 부족하다. 관측 밖 재생성·재시작은 배제하지 못한다.
앱 running은 healthy와 다르다. logger healthy + LISTEN도 로그 수신·저장 성공의 증거가 아니다.
Docker와 ss는 순차 호출이므로 한 표본도 원자적인 상태가 아니다. StartedAt은 마지막 시작 시각이며 준비 완료 시각이 아니다.
AUTOSTART/AC04는 항상 NOT_EVALUATED, SYSLOG_INGESTION은 NOT_TESTED다.

후속 판정에는 승인된 시험 원본 T0/종료/수동 개입 시각, daemon journal 및 당시 ID 집합,
주소/Compose 적용 SHA, 실제 로그 수신 검증, Runner TLS/guard 등 기존 시험 원본이 필요하다.
현재 정상 스냅샷을 과거 실패 당시 순서의 증거로 대체하지 않는다.

## 검증과 잔여

합성 시험은 정상/exit128/health starting/listener 없음/객체 교체/daemon 불가/timeout/중단/덮어쓰기 거부/
호스트 불일치/민감 응답 비출력/불완전·변조된 입력 거부를 포함한다.
CI는 Docker 없는 GitHub hosted runner에서 같은 시험을 실행한다. 합성 결과를 현장 증적으로 편입하지 않는다.
이 PR만으로 logger 준비 후 앱 시작을 보장하는 운영 기동 주체가 구현되는 것은 아니다.
기존 restart:always와 중첩하지 않는 기동 주체·실패 처리·복구 설계는 HBR Lead와 별도 확정한다.
독립 리뷰·병합·현장 실행·증적 편입·AC 인수는 각각 별도 단계다.
