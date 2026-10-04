# IF-09 Runner 정식 시험 wrapper (AC-02)

병합된 `scripts/verify/runner-push-test.sh`(본체)를 Runner(`cicd-runner01`)에서 **한 번의 Review Run**으로 실행하고, AC-03(Worker 3대)로 넘길 `review-run.env`를 만든다. 본체의 판정 로직은 바꾸지 않는다.

| 파일 | 설명 |
|---|---|
| `hbr-formal-run.sh` | wrapper 본체(본체 `runner-push-test.sh`를 내장). 전체 sha256은 아래 |
| `runner-formal-run-oneshot.txt` | Runner 터미널에 붙여넣는 한 덩어리(wrapper를 파일로 쓴 뒤 **외부 `sha256sum -c`가 통과할 때만** 실행) |
| `../../../tests/review/test_hbr_formal_run_wrapper.sh` | 격리(모의) 시험 23개 |

**wrapper 전체 sha256**: `f33c937fe9212a46f21b3dcd25ccd5f8f21ab441c602c6a00eeacf806c2a8d2a`
**내장 본체 sha256**: `b4c8bf988608e3f067476dafaf4dc2438ee150d2a891a938936a19195053ac99` (= `scripts/verify/runner-push-test.sh`, 시험 11이 드리프트를 검사)

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
- 과거 HEAD `6d1da03e86f9a90115f63b03d55ca51be3094607`의 c64c wrapper는 2026-10-02 ansible01 Linux에서 22/22 PASS(raw log SHA256 `c42e104704feb2882a6cc1a96f7e26c9b040c04e1b5449452ded441f409448fd`)였다. 현재 authfile 격리 변경은 wrapper bytes가 달라졌으므로 현재 exact HEAD에서 Linux Gate를 다시 수행해야 한다.
- 이 PR/wrapper의 승인은 실행 도구 승인이며 AC-02 Runtime PASS가 아니다.

## 2026-10-04 authfile 격리 후보

정상/음성 시험은 각각 새 `positive-auth.json`/`negative-auth.json`을 사용한다. 모든 login/pull/push는 `--authfile`을 명시하며, 상속된 `REGISTRY_AUTH_FILE`은 자식 프로세스 안에서 교체한다. 기본 auth store에 대한 logout은 제거했다. 임시 디렉터리 0700 및 파일 0600을 사용하고 EXIT/INT/TERM/HUP에서 정리한다. SIGKILL/전원 중단은 trap으로 정리할 수 없다.

`bash tests/review/test_runner_auth_isolation.sh`는 정상·실패·signal 경로의 격리 계약을 mock으로 검사한다. 실제 Podman/Linux 실행, 독립 exact-head 검토와 Lead 판단은 별도이며 아직 수행하지 않았다. 기존 IF-09 보고 이력을 소급 변경하지 않는다. 부모 터미널에서는 source하지 말고 `if bash ./hbr-formal-run.sh; then printf 'RC=0\n'; else rc=$?; printf 'RC=%s\n' "$rc"; fi` 형태로 실행한다.
