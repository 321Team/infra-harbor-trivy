# Harbor logger 주소·준비 순서 분리 검증

P1-HBR-01 [baseline #13](https://github.com/321Team/fds-project-baseline/issues/13) 후속.
GWONUK / CODEX_ASSISTED. 혼합 코드·CI PR, 독립 리뷰 및 Lead 병합 판단 대상.

운영 Harbor는 앱9개가 `tcp://localhost:1514`, logger는 IPv4 loopback만 수신하며,
10/7 daemon 원본에 `[::1]:1514 connection refused`가 남았다. PR12의 명시적 IPv4 주소
후보와 PR13의 상태 관측기는 현재 독립 리뷰 대기다. localhost 주소 수정만으로 logger
준비 순서도 보장되는지 확인할 입력이 부족하므로, 실제 Docker logging driver에 두 원인을
각각 제시하는 격리 실험을 추가한다. 운영 설정·restart 정책·기동 주체는 바꾸지 않는다.

## 실행 환경과 격리

- 이 저장소의 GitHub-hosted Ubuntu 24.04 일회성 runner만 허용한다. 환경 guard는 운영자
  실수 방지 장치이며 악의적 환경 변수 위조에 대한 보안 경계는 아니다. 로컬/SSH/자체 Runner 실행 금지.
- 로컬 Unix Docker socket 고정, 기존 컨테이너가 있으면 중단. daemon 재시작·systemd·방화벽·TLS
  변경·Harbor 접속·credential·volume·외부 포트 공개 없음.
- runner의 C compiler로 단순 표식 출력기를 정적 빌드한다. FROM scratch에 그 파일만 넣어
  외부 이미지 pull 없이 시험 이미지를 생성한다. image ID·binary hash·Docker version·명령/rc를 보존한다.
- 시험 컨테이너는 network none/nonroot/read-only/drop ALL/no-new-privileges/restart=no,
  CPU·메모리·PID 제한. 로그 연결은 컨테이너 네트워크가 아닌 Docker daemon의 loopback 경로다.
- 출력 폴더는 신규 생성, 모든 객체는 회차 UUID label·전체 ID로 묶는다. 정리는 소유 label을
  재확인한 ID만 대상으로 하고, 남은 객체/조회 실패는 실패 처리한다. 이름만으로 강제 삭제하지 않는다.
- 시험 도중 종료 신호·조회 실패도 finally에서 정리한다. SIGKILL/runner 유실은 정리를 보증하지
  못하며 GitHub의 일회성 VM 폐기에 의존한다. 운영 환경으로 이 복구 가정을 가져가지 않는다.

## 실제 실험과 판정

| 경우 | 기대·판정 |
|---|---|
| IPv4 logger 준비 후 명시적 IPv4 | 컨테이너 시작/exit0 및 고유 표식의 실제 TCP 수신 모두 필수 |
| IPv4만 수신할 때 명시적 IPv6 | logging driver connection refused로 시작 실패; 다른 API 오류는 실패 원인 불일치 |
| localhost | 현재 runner의 주소 선택 결과 그대로 기록. 성공해도 harbor01의 과거 실패를 반박하지 않음 |
| IPv4 주소는 맞지만 logger 미준비 | 시작 실패를 확인하고, logger 준비 후 **같은 객체를 명시적으로 다시 시작**해 실제 표식 수신 |

마지막 경우는 준비된 수신기의 필요성을 검증하며 자동 재시작·자동 회복 성공은 아니다.
`restart=always`의 daemon 재기동, Harbor 서비스 의존성·DB 데이터·로그 저장/보존,
실제 rsyslog, Harbor T+5/AC04, 운영 수정·원복은 **NOT_TESTED/NOT_EVALUATED**다.
이 코드는 Harbor 전체 복제 VM 시험을 대체하지 않는다. 원인별 기전 검증 후 HBR Lead가
기존 Docker restart 정책 유지 가능 여부 또는 단일 기동 책임 이관을 결정한다.

## 실행·증적·후속

PR CI가 guard 단위시험 다음에 `python3 scripts/verify/syslog-startup-lab.py --output <새 폴더>`를
실행한다. 준비 도구가 없으면 설치로 우회하지 않고 CI 실패를 남긴다. job 상한8분,
개별 명령20초(컴파일30초/빌드60초), 수신 확인5초. 출력에는 commands.jsonl, 실제 수신 표식,
result.json, SHA256SUMS가 있으며 실패에도 artifact 업로드한다. 결과의 source_commit은
GitHub PR 합성 merge SHA일 수 있으므로 PR HEAD·Run head SHA와 함께 추적한다.

CI PASS는 격리 Docker 실험의 판정이다. 운영 자동기동/AC04 PASS·독립 승인·병합과 구분한다.
후속: 운영과 분리된 Harbor 복제 환경 확보 → 실제 생성/override 소비 경로·기동 방식·로그 수신 기준
확정 → source 독립 리뷰 → 재생성/daemon 재시작·복구 시험 창. 운영 볼륨 삭제/자동 pull/보안 완화는 금지한다.

근거: [Docker syslog driver](https://docs.docker.com/engine/logging/drivers/syslog/),
[Docker restart 정책](https://docs.docker.com/engine/containers/start-containers-automatically/).
