# PR32~39 독립 리뷰 후 보완과 Runtime 잔여

2026-10-09. [PR37 리뷰](https://github.com/321Team/infra-harbor-trivy/pull/37#pullrequestreview-5469792660)와 [PR38 리뷰](https://github.com/321Team/infra-harbor-trivy/pull/38#pullrequestreview-5469794847)는 기존 정확 HEAD의 코드·모의검증 승인이다. 이 후속 코드에는 새 독립 리뷰가 필요하다.

## 반영한 항목

- 설치 journal이 아직 없는 최초 HOLD는 `NOT_ARMED`를 유지한다. 중복 `hold`도 기존 장애 사유를 덮지 않는다. RUN 전환·실제 동작 시 installation gate는 계속 필수이며 실패한 gate로 logger reconciliation을 허용하지 않는다.
- 다른 프로젝트의 `Labels=null` 컨테이너를 inventory에서 제외한다. 정확한 Harbor 대상 집합은 계속 비교하므로 대상 label 누락은 실패한다.
- socket xattr 조회도 symlink를 따라가지 않는다. NFSv4 ACL과 고정 대상의 capability/미등록 xattr을 거부한다. 실제 SELinux 값은 현장 입력과 별도로 검증해야 한다.
- signal handler의 threading.Event/Condition 잠금을 제거했다. main-thread bool flag만 설정하고 대기는0.1초 이하 구간으로 나눈다. 신호 처리 중 잠금 획득이 없으며 진행 중 Docker 요청을 취소했다고 표시하지 않는다.
- 마지막 fresh 관측 뒤 종료가 확인되면 `stopped` 결과와 `MANAGER_STOP_BEFORE_POST` HOLD를 기록한다. 실제 POST0건인 종료 경로를 전송 실패/미확정과 구분한다. intent/claim 보존은 동일하다.
- tick 예외 발생 시 별도 잠금으로 `MANAGER_TICK_FAILED` HOLD 저장을 시도하고, 실패하면 `hold_persisted=false`를 보고하며 rc2로 종료한다. 디스크/파일 오류 시 HOLD를 저장했다고 거짓 보고하지 않는다.
- reconcile/stop 진입 시 기존 start intent와 stop claim 파일의 최대 token보다 현재 next_token이 큰지 확인한다. 뒤로 되돌린 상태는 전체 healthy여도 재판정하지 않는다. 기존 기록을 삭제하거나 token을 자동 증가시켜 통과시키지 않는다.
- stop 예산은 library에서도 유한값을 검사한다. 전체 CLI는 실패 저장 예외를 기존 STOP/rc2로 처리한다. 라이브러리 직접 호출자는 예외를 처리해야 하며 성공값으로 바꾸지 않는다.
- package 생성기의 최소 shutdown 예산 검사는 PR39에 이미 포함됐다. unit_text는 일반 순수 렌더러이므로 실제 설치 입력은 package 검사 및 현장 실측을 모두 거쳐야 한다.
- PR39 후속으로 package CLI는 검증 전후 같은 HEAD와 깨끗한 checkout을 요구한다. staged/unstaged/untracked 변경이 있으면 출력 전에 중단하며 자동 정리하지 않는다. 입력/출력은 checkout 밖 승인 비공개 경로에 둔다. 별도 수정자가 없는 신뢰된 checkout에서 실행해야 하며, 이 검사는 이미 로드된 Python/모듈의 악의적 교체를 격리하는 보안 경계가 아니다. library `prepare`는 시험용 순수 함수이며 CLI의 출처 확인을 대신하지 않는다.

## 남은 실패 의미

HOLD 저장 실패 때 디스크에는 과거 RUN이 남아 있을 수 있다. rc2는 현재 unit 자동 재시작을 막지만 다음 부팅의 enable 상태를 영구 해제하지 않는다. 이후 boot/start가 resume와 fresh host 검사를 통과하면 저장된 의도대로 이어갈 수 있다. 이 상태에서는 콘솔에서 장애 원본을 보존하고 실제 저장 상태·manager 활성화 정책을 확인하기 전 계획된 reboot/start를 수행하지 않는다. 오류 때문에 기존 파일을 직접 고치거나 초기화하지 않는다.

## graceful stop Runtime 전 반드시 닫을 잔여

1. 정확한 Harbor2.13.1 이미지/컨테이너의 StopSignal과 현재 클라이언트 연결을 확인한다. 현재 경로는 신호를 덮어쓰지 않는 `POST /stop?t=-1`이며 proxy·portal은 SIGQUIT/3, 나머지 앱은 SIGTERM/15 적합성을 첫 HOLD/claim 전과 각 전송 전에 확인한다. 미설정은 Docker 기본 SIGTERM이다. H6 회차 전에 Push/Pull·배포의 새 요청을 멈추고 기존 요청·연결이 정리됐다는 실제 근거를 확인한다. 사용자 비중첩 회신만으로 연결 유휴를 입증했다고 표시하지 않는다. nginx QUIT은 진행 중 요청, DB smart shutdown은 연결 잔존 때문에 대기가 길어질 수 있다. 현장 확인 없이 SIGINT/SIGKILL로 자동 변경하지 않는다.
2. `--stop-seconds`는 관측·claim 저장·요청·readback 전체 클라이언트 예산이며 컨테이너 종료 완료시간의 상한을 보장하지 않는다. `t=-1`은 daemon의 강제 종료 타이머를 사용하지 않으므로 긴 요청이 남으면 proxy의 첫 종료 요청부터 예산을 초과할 수 있다. 시간 초과는 요청 취소나 종료 성공이 아니다. HOLD와 원 claim을 보존하고 다음 앱 전송을 중단하며, ACK 없는 회차는 `settle-stop-readback`으로 해소하지 않는다. 아래3·4항의 원본 수집·별도 복구 경로를 따른다. 실제 H6 예산은 대상별 실측으로 정하며 관리자 기동/복구 예산을 전용하지 않는다.
3. 늦게 종료된 앱의 미완료 stop claim에는 자동 해소 기능이 없다. [ACK 영속 기록·명시적 관측 정리](harbor-recovery-stop-readback.md)는 실제 HTTP204가 이미 기록된 동일 세대 tail만 다루고 HOLD를 유지한다. ACK 없는 timeout/legacy claim·부분 policy·세대 변경은 해결하지 않는다. 단순 exited 관측을 미확정 요청의 완료 ACK로 바꿔 새 기동을 허용하지 않는다. 임의 Store 편집·새 namespace 우회는 복구 절차가 아니다.
4. 회차 전 검토할 복구 입력은 exact claim/state/package hash, 마지막 daemon/boot, 명령 프로세스 종료와 후속 요청0건, 대상 ID별 현재 상태 및 logger/데이터 상태, request 완료를 판단할 원본, 보존 사본과 복구 인수자다. 원본만으로 완료를 확정할 수 없으면 별도 승인된 daemon 경계/복구 계획과 그에 맞는 코드가 먼저 필요하다. 기존 A3 restart claim을 재사용하지 않는다.

따라서 이 후속을 반영해도 실제 graceful-stop 회차를 지금 승인/실행하지 않는다. 입력과 미확정 요청 해소 경로가 검토되기 전에는 H6=NOT_READY다. 상태·증적·logger 보존을 우선하고 AC나 자동복구 전체 완료로 표시하지 않는다.

## 앞선 리뷰에서 유지한 현장·설치 검토 항목

- PR32: 실제 Engine의 created/Health 필드와 버전 변경에 따른 inspect fingerprint는 현장에서 확인한다. 최초 설치는 전체 healthy를 요구하며 새 컨테이너 생성이나 임의 Engine 업그레이드는 범위에 포함하지 않는다.
- PR33: 다른 root 작성자 배제는 전제다. 파일 검증 후 경로 기반 실행 사이의 교체, O_PATH 우선 열기, 정상 종료한 도구의 자손 프로세스 정리까지 완전하게 보장한다고 주장하지 않는다. private HOME/DOCKER_CONFIG/cwd의 config.json·cli-plugins 등 추가 파일 목록을 입력 검토에 포함하고, max_age와 종료 예산은 실제 도구 실행 시간으로 검증해야 한다. 자동 학습이나 budget 완화로 통과시키지 않는다.
- PR34: claim 이후 전송 전 오류도 현재는 보수적으로 미확정 상태를 보존한다. daemon/boot 세대가 바뀌거나 일부 policy만 변경된 상태의 복구는 현재 same-generation/all-healthy rollback으로 처리할 수 없다. 해당 실패 회차 전에는 원본 claim/journal·현재 정책·세대·콘솔 인수에 결속한 별도 복구 계획과 필요한 코드 검토가 먼저다. 이전 INSTALLED_HOLD 단계가 HOLD로 변경되어도 변경 목록·원본 journal을 보존한다.
- PR35·36: 실제 enforcing SELinux/Python 호환성과 상태 파일 생성 후 label 검사는 미실행이다. 실패한 initialize/hold가 lock 또는 일부 파일을 남길 수 있다. 자동 삭제·초기화·relabel하지 않고, 원본을 보존한 채 승인된 설치 절차로 원인을 해소한다. Python 시작 전 신뢰 경계는 bootstrap 문서의 제한을 따른다.

위 항목은 부모 PR의 독립 코드 승인을 취소하거나 새로운 팀 정책을 만드는 내용이 아니다. 현재 보장 범위와 후속 회차의 준비 조건을 기록하며, 미완료 Runtime을 완료로 확대하지 않는다.
