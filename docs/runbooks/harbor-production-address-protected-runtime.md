# 운영 Harbor 주소 변경 — 보호 입력·실행 증적·현행 조회 연결

CODEX_ASSISTED · 2026-10-12 · baseline#13 · PR48 후속.
주소 변경 라이브러리를 연결하는 코드다. 후속 [일회성 진입점/감독 계약](harbor-production-address-entrypoint.md)이
추가됐으며 **실제 운영 입력·신뢰된 배치·감독 서비스 설치/기동은 아직 미완료**다.
실제 package·profile·policy·회차는 생성하지 않았다. 아래 계약을 실제값으로 충족하고
신뢰된 설치/진입 경로와 독립 리뷰를 마친 뒤 기존 허용 범위의 운영 실행으로 이어간다.
작성·모의/CI·현장 읽기·실제 변경·AC를 구분한다.

## 연결한 경로

| 모듈 | 역할 |
|---|---|
| harbor_address_package.py | 외부에서 검토한 7개 JSON의 정확 bytes/hash 공급과 재읽기 |
| harbor_address_host.py | 운영 세대·도구·보호 설정·이미지·resource·원본 경로의 읽기 대조 |
| harbor_address_evidence.py | Compose 호출/프로세스 intent·결과의 영속 보존, 부분 상태 읽기와 증적 판독 |
| harbor_address_session.py | package/model/보존/host 결속, 기존 Sequence·Journal·Backend·PinnedCompose 연결 |

이 변경은 기존 clone guard를 느슨하게 하지 않는다. ProductionHost는 명시적으로 다른
운영 정책 schema를 소비한다. Docker 읽기 연결은 고정 local root Unix peer/API1.56이며
GET allowlist 외 start/DELETE 등은 전송 전에 거부한다. 유일한 앱 변경 경로는 기존
단일 서비스 ComposeTransport다. logger 재생성·원 Compose 덮어쓰기·manager 설치는 없다.

## 실제 입력 계약

7파일은 plan.json, base.json, candidate.json, model.json, preservation.json,
profile.json, host-policy.json이다. 각각 원본 private bytes의 외부 검토 hash를 공급하며
공급기가 supply.claim을 먼저, manifest.json을 마지막에 쓴다. 빈 root0700 보호 경로에
root0600·단일 link·정확 SELinux context로 작성한 뒤 모든 파일을 다시 읽는다.
기존/부분 디렉터리·추가 파일·ACL·symlink·hardlink·hash/label 차이는 거부한다.
공급 중 실패한 claim/부분 파일은 보존하고 다시 채우거나 지우지 않는다.

- plan: 기존 healthy10 유지보수 schema, 실제 binding/input 식별값, 관측 신선도와 앱별
  health/IO/poll 예산. 현재 예산값을 만들거나 이전 clone 회차를 재사용하지 않는다.
- base/candidate/model: 검토된 resolved Compose와 주소9곳 변경, 동일 기존 external
  resource 참조. assemble이 다시 계산해 전체 모델·image ref/ID·baseline 투영을 대조한다.
- preservation: 10개 full inspect baseline, 검토한 생성 label/기존 volume Mounts 기대값,
  명시적 hostname/address 변환 목록. 임의 필드를 무시하거나 현재값을 자동 학습하지 않는다.
- profile: 실제 운영7개 volume metadata/inventory, Engine/Compose/security, 허용 근거 hash와
  host binding. 이전 clone 예외나 예상 Mode=z를 실제 실행 성공으로 취급하지 않는다.
- host-policy: hostname/UUID/boot, 물리 NIC+lo 주소/route hash, 도구 경로·mode·label·hash,
  root pinned source/interpreter/unit/drop-in, 원본 Compose/env 파일 hash와 metadata,
  socket metadata, Engine profile, Docker/AC04 Invocation·Requires·After·unit 상태,
  manager 미설치 상태, nft 구조 hash, 이미지 ref→ID, 기존 network/volume 구성 hash.

host policy의 inputs_sha256은 검토한 입력 식별 근거다. package manifest 자체를 재귀적으로
해시하는 필드가 아니다. host policy fingerprint→plan binding/profile host binding,
preservation fingerprint→FullPreservation binding, model fingerprint를 각각 대조한다.
수치·실제 label·대상/참여자·승인 근거를 기본값으로 합성하지 않는다.

ProductionHost는 전후 두 번 host/resource/원본을 읽고 package를 다시 대조한다.
nft의 counter/handle과 network endpoint membership/Peers만 동적인 조회 필드로 제외한다.
network의 identity/IPAM/config, volume 전체 resource 구성과 앱7개 source metadata는 유지한다.
원본이 user 소유 부모 밑에 있더라도 최종 파일 root metadata와 fd/hash/path를 읽기 대조할 수 있다.
이를 실행 파일이나 Compose 입력으로 사용하지 않으며 부모 권한 변경도 하지 않는다.
주소/route의 아직 검토되지 않은 동적 필드는 자동 정규화하지 않아 차이 발생 시 중단한다.

## 실행 증적과 판독

AuditedCompose는 CALL_INTENT를 먼저 기록한다. PinnedCompose가 경로·ELF·private 환경을
검증한 뒤 프로세스 실행 직전에 PROCESS_INTENT를 fsync한다. 기록 또는 기한 검사가
실패하면 프로세스를 실행하지 않는다. 반환 뒤 PROCESS_RESULT와 CALL_END를 기록한다.
stdout/stderr/inspect/Sequence 결과는 private0600 payload 파일에만 저장하고
공개 가능한 진단에는 rc·고정 원인·크기·hash·ID만 남긴다. 예외 원문은 반환하지 않는다.

각 레코드는 순번·plan hash·이전 hash·payload hash에 결속된다. O_EXCL claim·단일 writer·
fork/동시 호출 제한, 파일/디렉터리 교체·권한 변화·예상 밖 파일 검사로 재사용을 거부한다.
정상적으로 끝난 경우에만 evidence.closed를 쓴다. 증적은 재실행 허용증이 아니다.

inspect_evidence는 모든 private payload를 스트림 해시로 검증하고 내용은 반환하지 않는다.

| 증적 | 판독 |
|---|---|
| 완결된 증적, recreate PROCESS_INTENT 없음 | 이 audited client의 up NOT_INVOKED |
| recreate PROCESS_INTENT 있음 | MAY_HAVE_RUN; Docker 수락/성공을 뜻하지 않음 |
| close 없음/손상/고아 파일/경로 변화/읽기 실패/호출 미종료 seal | UNKNOWN 또는 불완전; 자동 resume 불가 |

기존 Sequence의 UNKNOWN을 소급 덮어쓰지 않는다. 위 판독은 별도 하위 호출 증거이며 다른
행위자의 실행이나 실제 서비스 상태를 증명하지 않는다. 쓰기 intent 이후 전원 장애·강제
종료로 결과를 보존하지 못하면 보수적 미확인 상태가 유지된다.

## 기한·중단·인수

ProtectedSession은 mutation_deadline과 그보다 뒤의 collection_deadline을 별도로 요구한다.
수집 예산은 변경 기한을 연장하지 않는다. 앱 오류·지연·drift·디스크 오류 시 다음 재생성은
없으며, 새 세션/기존 claim 재사용·자동 retry·정지·snapshot 복원·volume 삭제를 수행하지 않는다.
현재 Harbor inventory(최대32개)와 기존10ID를 읽기만 하여 부분 상태를 private로 보존한다.
이미 교체돼 없어진 old ID는 조회 실패로 남긴다. collection.complete=false가 새 앱 실패를
의미하지 않으며, Sequence 상태·각 읽기 실패와 따로 판단한다. 수집 저장이 실패해도 이미
반환된 Sequence 결과를 유지하고 evidence_sealed=false와 고정 원인을 반환한다.

프로세스/파이프는 기존 절대 기한과 출력 한도를 따른다. 파일 fsync나 커널 I/O 자체는
협조적 기한 확인만으로 강제 제한할 수 없다. 후속 일회성 unit 생성/검사 코드를 실제
운영 입력에 결속해 배치하고 OS 감독 동작을 확인해야 한다.
Compose client를 종료해도 Docker가 수락한 작업이 계속될 수 있다. 이 변경을 hard realtime
중단이나 Docker rollback 보장으로 표시하지 않는다.

## 배치 전 남은 사항

1. 실제 운영 source·보호 경로·SELinux·현재 세대와 단일 회차 입력을 신뢰된 접근으로 수집하고
   패키지 기대값을 검토한다. 기존 원본/수신 승인과 일치하는 범위를 재사용한다.
2. 후속 bootstrap/CLI와 일회성 unit 계약을 검토하고 신뢰된 interpreter/source를 먼저
   배치·검증한다. 이미 임의로 import한 Python을 나중에 hash 검사해 신뢰할 수는 없다.
3. source 배치와 private root 경로의 실제 fd 실행·Compose config roundtrip을 읽기로 확인한다.
   기존15:07 운영 standalone5.6.0의 동일 global 옵션 config rc0는 옵션 지원 근거이고,
   16:12에는 HOME 없는 /proc/self/fd version rc0도 확인했다. 두 결과는 아직 미검증인
   private HOME config roundtrip/up 실행을 대신하지 않는다.
4. 검토한 source/input 일치·fresh10healthy·보호/보존·IPv4 logger·남은 예산을 확인한 후
   기존 운영 변경 허용으로 앱9개를 각 최대1회 순서대로 수행한다. 오류면 증적과 부분 상태를
   보존해 담당자에게 인수한다. 후속 manager/H6·worker 확인·최종 AC는 별도 미완료다.

이 목록을 새 전체 담당자 회신 Gate나 신규 업무 정책으로 확대하지 않는다.
스냅샷은 기존 수신 자료이며 자동 복원하지 않는다. 테스트 clone은 종료 상태를 유지한다.

## 검증 경계

systemd `Requires`/`After`는 의존 항목의 집합으로 비교한다. 설정 재로드 뒤
출력 순서만 바뀌어도 기존 검토 입력을 다시 만들지 않는다. 항목 추가·삭제·중복,
InvocationID/상태/원본·drop-in 경로/reload 변화는 계속 중단한다. 원본 JSON과
패키지 hash는 보존하며, 이 비교는 정책 재학습이나 실제 drift 허용이 아니다.
근거: [systemd v257 의존 속성 구현](https://github.com/systemd/systemd/blob/v257/src/core/dbus-unit.c#L150-L184).
정적 문자열 회귀 외에 CI 임시 unit에서 실제 재로드 전후 비교와 미기동 검증을 수행한다.
CI에는 Docker/운영 데이터가 없으므로 실제 재생성·보존·인수를 대신하지 않는다.

test_protected_runtime.py는 합성 Engine/host와 Linux root 임시 디스크를 사용한다.
Linux에서는 O_EXCL/fsync/파일 보호·private payload/hashchain/손상·부분 공급·호출 전 저장
실패·늦은 반환·Sequence/Journal/AuditedCompose 연결을 검증한다. Compose/Docker 서비스에
실제 접속하지 않는다. Ubuntu CI의 SELinux 부재 시험 또는 context mock은 운영 Enforcing
검증이 아니며 ProductionSession은 None context를 허용하지 않는다.
