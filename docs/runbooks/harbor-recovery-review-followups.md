# PR37·38 독립 리뷰 후 보완과 Runtime 잔여

2026-10-09. [PR37 리뷰](https://github.com/321Team/infra-harbor-trivy/pull/37#pullrequestreview-5469792660)와 [PR38 리뷰](https://github.com/321Team/infra-harbor-trivy/pull/38#pullrequestreview-5469794847)는 기존 정확 HEAD의 코드·모의검증 승인이다. 이 후속 코드에는 새 독립 리뷰가 필요하다.

## 반영한 항목

- signal handler의 threading.Event/Condition 잠금을 제거했다. main-thread bool flag만 설정하고 대기는0.1초 이하 구간으로 나눈다. 신호 처리 중 잠금 획득이 없으며 진행 중 Docker 요청을 취소했다고 표시하지 않는다.
- 마지막 fresh 관측 뒤 종료가 확인되면 `stopped` 결과와 `MANAGER_STOP_BEFORE_POST` HOLD를 기록한다. 실제 POST0건인 종료 경로를 전송 실패/미확정과 구분한다. intent/claim 보존은 동일하다.
- tick 예외 발생 시 별도 잠금으로 `MANAGER_TICK_FAILED` HOLD 저장을 시도하고, 실패하면 `hold_persisted=false`를 보고하며 rc2로 종료한다. 디스크/파일 오류 시 HOLD를 저장했다고 거짓 보고하지 않는다.
- reconcile/stop 진입 시 기존 start intent와 stop claim 파일의 최대 token보다 현재 next_token이 큰지 확인한다. 뒤로 되돌린 상태는 전체 healthy여도 재판정하지 않는다. 기존 기록을 삭제하거나 token을 자동 증가시켜 통과시키지 않는다.
- stop 예산은 library에서도 유한값을 검사한다. 전체 CLI는 실패 저장 예외를 기존 STOP/rc2로 처리한다. 라이브러리 직접 호출자는 예외를 처리해야 하며 성공값으로 바꾸지 않는다.
- package 생성기의 최소 shutdown 예산 검사는 PR39에 이미 포함됐다. unit_text는 일반 순수 렌더러이므로 실제 설치 입력은 package 검사 및 현장 실측을 모두 거쳐야 한다.

## 남은 실패 의미

HOLD 저장 실패 때 디스크에는 과거 RUN이 남아 있을 수 있다. rc2는 현재 unit 자동 재시작을 막지만 다음 부팅의 enable 상태를 영구 해제하지 않는다. 이후 boot/start가 resume와 fresh host 검사를 통과하면 저장된 의도대로 이어갈 수 있다. 이 상태에서는 콘솔에서 장애 원본을 보존하고 실제 저장 상태·manager 활성화 정책을 확인하기 전 계획된 reboot/start를 수행하지 않는다. 오류 때문에 기존 파일을 직접 고치거나 초기화하지 않는다.

## graceful stop Runtime 전 반드시 닫을 잔여

1. 정확한 Harbor2.13.1 이미지/컨테이너의 StopSignal과 현재 클라이언트 연결을 확인한다. 현재 경로는 SIGTERM을 명시하므로 이미지 STOPSIGNAL을 대체한다. 특히 DB smart shutdown은 연결 잔존 시 끝나지 않을 수 있다. 현장 확인 없이 SIGINT/SIGKILL로 자동 변경하지 않는다.
2. `--stop-seconds`는 관측·claim 저장·요청·readback 전체 예산이며 순수 SIGTERM 대기 시간과 다르다. 대상별 실측을 기준으로 정한다.
3. 늦게 종료된 앱의 미완료 stop claim에는 아직 자동 해소 기능이 없다. 단순 exited 관측을 미확정 요청의 완료 ACK로 바꿔 새 기동을 허용하지 않는다. 임의 Store 편집·새 namespace 우회는 복구 절차가 아니다.
4. 회차 전 검토할 복구 입력은 exact claim/state/package hash, 마지막 daemon/boot, 명령 프로세스 종료와 후속 요청0건, 대상 ID별 현재 상태 및 logger/데이터 상태, request 완료를 판단할 원본, 보존 사본과 복구 인수자다. 원본만으로 완료를 확정할 수 없으면 별도 승인된 daemon 경계/복구 계획과 그에 맞는 코드가 먼저 필요하다. 기존 A3 restart claim을 재사용하지 않는다.

따라서 이 후속을 반영해도 실제 graceful-stop 회차를 지금 승인/실행하지 않는다. 입력과 미확정 요청 해소 경로가 검토되기 전에는 H6=NOT_READY다. 상태·증적·logger 보존을 우선하고 AC나 자동복구 전체 완료로 표시하지 않는다.
