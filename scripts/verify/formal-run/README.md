# IF-09 Runner 정식 시험 wrapper (AC-02)

병합된 `scripts/verify/runner-push-test.sh`(본체)를 Runner(`cicd-runner01`)에서 **한 번의 Review Run**으로 실행하고, AC-03(Worker 3대)로 넘길 `review-run.env`를 만든다. 본체의 판정 로직은 바꾸지 않는다.

| 파일 | 설명 |
|---|---|
| `hbr-formal-run.sh` | wrapper 본체(본체 `runner-push-test.sh`를 내장). 전체 sha256은 아래 |
| `runner-formal-run-oneshot.txt` | Runner 터미널에 붙여넣는 한 덩어리(wrapper를 파일로 쓴 뒤 **외부 `sha256sum -c`가 통과할 때만** 실행) |
| `../../../tests/review/test_hbr_formal_run_wrapper.sh` | 격리(모의) 시험 23개 |

**wrapper 전체 sha256**: `9ffc541874455fe981a762729000de94d575b01cc4b9091eb08c59fd9db7c88a`
**내장 본체 sha256**: `1305e9affe70132bcc570a646369834dd1ce237570a4c7537bbead6da6b6fe1e` (= `scripts/verify/runner-push-test.sh`, 시험 11이 드리프트를 검사)

## 종료 코드
`0` PASS / `1` 본체 FAIL / `2` ERROR(본체 ERROR, 또는 wrapper·증적 처리 실패). PASS는 본체 rc=0, TEST_TAG·MANIFEST_DIGEST 유효, handoff 생성, `SHA256SUMS` seal·재검증이 모두 참일 때만 출력한다.

## 실행 전제와 방식

IF-09 공통 Test Artifact execution input은 2026-10-02 baseline #13 결정으로
`docker.io/library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e`
로 고정한다. 기존 `c053b592...`는 Runner/Docker Hub에서 `manifest unknown`으로 재현되어 superseded 처리됐다.
새 값은 cicd-runner01에서 exact digest pull rc0로 재검증했으며 원본 로그 SHA256은
`695269d178b2c160f65af3b06981c56d9f78bbdbff4866bb4aa217298a835633`이다.
승인 근거: baseline #13 comment `5946864064`.
pull 실패 시 다른 tag/digest로 임의 대체하지 않고 HOLD한다. 시험 14가 이 input identity drift를 회귀검사한다.

승인된 IF-09 공통 Test Artifact는 `docker.io/library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e`이다. pull 실패 시 다른 tag/digest로 임의 대체하지 않고 HOLD한다. 시험 14가 이 입력 identity drift를 회귀검사한다.
1. Runner에 승인 Root CA가 Podman trust로 배치돼 있어야 한다(`~/.config/containers/certs.d/10.1.93.54/ca.crt`, sha256 `20ddfa5e…`).
2. `runner-formal-run-oneshot.txt`를 붙여넣으면 wrapper를 `~/hbr-formal-run.sh`로 쓰고 sha256을 확인한 뒤에만 실행한다.
3. `robot$push` 비밀번호는 터미널 입력으로만 받는다. 환경에 `RUNNER_ROBOT_SECRET`가 이미 있으면 STOP한다.
4. 매 실행은 새 `~/hbr-review-run-hbr-<시각>-<nonce>/`에 `run.log`, 본체 사본, (PASS 시) `review-run.env(+.sha256)`·`summary.txt`, `SHA256SUMS`를 남긴다. 디렉터리 재사용은 금지한다.

## 시험
```bash
bash tests/review/test_hbr_formal_run_wrapper.sh
```
podman·tee·sha256sum·date는 모의/shim이며 Harbor나 네트워크에 접속하지 않는다. 시험 10은 생성된 `review-run.env`를 실제 `scripts/verify/lib/load-review-run-env.sh`로 읽어 AC-03 인계 계약을 확인한다.

## 알려진 한계
- 이전 HEAD `6d1da03e86f9a90115f63b03d55ca51be3094607`은 2026-10-02 ansible01 Linux에서 22/22 PASS(raw log SHA256 `c42e104704feb2882a6cc1a96f7e26c9b040c04e1b5449452ded441f409448fd`)였다. 이후 승인 base digest 복원과 시험 14 추가로 HEAD/bytes가 변경되었으므로 현재 exact HEAD에서 Linux Gate를 다시 수행해야 한다.
- 이 PR/wrapper의 승인은 실행 도구 승인이며 AC-02 Runtime PASS가 아니다.
