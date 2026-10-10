# Phase 1 Harbor 검토 패키지 수신 검사

CODEX_ASSISTED · 2026-10-10. [기존 package 생성](harbor-recovery-review-package.md)의 읽기 전용 소비 검증이다. 생성자의 검토 입력·INSTALL_PLAN을 재사용하며 새 팀 승인 단계나 Phase 2 사전작업을 추가하지 않는다.

## 목적과 실행 위치

패키지를 생성한 뒤 보관·전송 중 파일이 누락되거나 바뀌지 않았는지, source와 unit/launch/bundle의 연결이 일치하는지 자동 대조한다. 실행 위치는 **신뢰된 검토 checkout과 비공개 패키지 경로가 있는 작업 PC**다. 게스트 설치기나 bootstrap을 대신하지 않는다. Python·검증기와 그 checkout 모듈은 먼저 신뢰되어야 하며, 후보 파일 자체의 hash로 이미 실행된 검증기 코드를 인증하지 않는다.

필요 입력은 package 절대 경로, 기존 생성·검토 기록에 별도로 보존한 정확한 `INSTALL_PLAN.json` SHA256, 명시적 유한 시간 예산이다. 검증 시 현재 패키지에서 hash를 계산해 새 기준으로 채택하지 않는다. 입력 package는 checkout 밖 승인된 비공개 경로에 두고 다른 작성자와 중첩하지 않는다. 검사 동안 읽은 bytes를 확인하는 것이며 검사 이후 변경이나 악의적 동시 작성자 배제를 보장하지 않는다.

```text
python -B scripts/preparation/harbor_review_package_check.py
  --package <수신한 비공개 package 절대 경로>
  --plan-sha256 <기존 생성·검토 기록의 INSTALL_PLAN SHA256>
  --timeout <해당 검사에 정한 초, 0초 초과600초 이하>
```

실제 package가 없는 상태에서 샘플 입력을 현장 입력으로 채워 실행하지 않는다. 시험 fixture의 SYNTHETIC package는 현장 증적으로 사용하지 않는다.

## 검사와 판정

- 정확한 source11개, bootstrap, manager.service, bundle.json, launch.json, INSTALL_PLAN.json 총16파일만 수용한다. 추가/누락/빈 파일·크기 초과, symlink/reparse point·hardlink·특수 파일·읽는 중 교체/변경을 거부한다. 디렉터리 부모의 symlink도 거부한다.
- 외부 INSTALL_PLAN hash를 먼저 대조하고 각 payload의 길이·hash·명시적 UID/GID/mode/context·대상 경로 선언을 검증한다. 여기서 metadata는 **설치 계획의 선언값**이며 현장 파일의 root/SELinux/ACL 확인이 아니다. 작업 PC의 Windows ACL과 게스트 Linux 보안 상태를 이 검사로 증명하지 않는다.
- source의 revision/대상/pin, manager unit pin, bundle execution binding·Store, launch의 bundle hash/path/context와 고정 anchor 경로를 대조한다. unit은 기존 renderer의 정확한 bytes여야 하며 bootstrap hash 경로·launch context·명시 예산이 연결돼야 한다. 기존 최소 shutdown 예산을 유지한다.
- 원 bundle에 필요한 외부 파일 목록이 INSTALL_PLAN에서 빠지지 않았는지 확인한다. 그 파일 본체와 현장 일치 여부는 이 package에 포함되지 않아 `NOT_VERIFIED`다. 원 입력 JSON 본체도 포함되지 않아 원 입력 bytes의 재검증은 별도로 남는다.
- 후보 Python은 hash/pin 대조 뒤 구문 컴파일만 한다. 후보 코드 import/실행·bytecode 쓰기·Docker/SSH/서비스 명령·설치·권한 변경·삭제·수정은 없다.

정상 종료는 rc0, `status=PACKAGE_BYTES_VERIFIED`다. 출력은 plan/input hash, source revision, 파일 수와 다음 경계를 포함한다.

| 단계 | 이 검사의 판정 |
| --- | --- |
| 수신16파일·내부 결속 | 검사 시 읽은 bytes 일치 |
| 독립 리뷰·사람의 승인 | NOT_VERIFIED |
| 원 입력 JSON 본체 | NOT_INCLUDED_NOT_VERIFIED |
| 현장 metadata·SELinux·외부 파일 | NOT_VERIFIED |
| 실제 설치·Runtime | NOT_RUN |

이 판정은 H0/H1 완료나 HBR AC 충족이 아니다. 기존 source 리뷰와 input review를 취소·대체하거나 이미 확정된 실행 책임에 추가 Lead GO를 요구하지 않는다.

## 실패와 다음 순서

실패하면 rc2/STOP이며 예외 원문·package 내용·민감정보를 출력하지 않는다. 입력과 부분 전송본을 보존하고 생성자 원본/hash와 비교하여 누락·변경 원인을 확인한다. 승인 hash를 현재값으로 교체하거나 파일·경로를 자동 고치지 않는다. 재전송은 원본을 보존한 새 경로로 하고 다시 대조한다.

수신 검사가 통과하면 기존 설치 검토 순서로 이어간다. 현장 identity/격리·원복점·Python 공급 경로·SELinux/context 생성·외부 파일·실측 예산이 필요하며, 정확한 package/행위 범위에 결속한 회차에서만 새 파일 배치와 disabled unit 준비를 수행한다. 설치 적용기와 실제 서버 시험은 이 도구에 포함되지 않는다. 미확정 stop claim과 H6 잔여는 [기존 실패 의미](harbor-recovery-review-followups.md)를 유지한다.

## 검증

`python3 -B -m unittest discover -s tests/recovery-core -v`

추가 시험은 정상 생성기→수신 검사, payload·manifest·연결 변조, 원 bundle에 없는 재pin, 잘못된 target/metadata, hardlink·읽는 중 변경·deadline, 무수정/후보 미실행, 비밀 출력 차단을 다룬다. Linux CI의 symlink/FIFO 시험은 파일 소비 검사이며 실제 Harbor·systemd·SELinux Runtime 시험이 아니다.
