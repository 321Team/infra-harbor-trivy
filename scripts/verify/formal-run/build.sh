#!/usr/bin/env bash
# hbr-formal-run.template.sh + runner-push-test.sh -> hbr-formal-run.sh, runner-formal-run-oneshot.txt
set -euo pipefail
cd "$(dirname "$0")"
while IFS= read -r line || [ -n "$line" ]; do
  if [ "$line" = "@@BODY@@" ]; then cat ../runner-push-test.sh; else printf '%s\n' "$line"; fi
done < hbr-formal-run.template.sh > hbr-formal-run.sh
W="$(sha256sum hbr-formal-run.sh | cut -d' ' -f1)"
{
  echo "cat > ~/hbr-formal-run.sh <<'WRAP_EOF'"
  cat hbr-formal-run.sh
  echo "WRAP_EOF"
  echo "# 실행 전 외부 검증: 아래 해시가 검토된 값과 같을 때만 실행"
  echo "sha256sum ~/hbr-formal-run.sh   # 기대: $W"
  echo "bash ~/hbr-formal-run.sh $W"
} > runner-formal-run-oneshot.txt
echo "WRAPPER_SHA256=$W"; wc -l hbr-formal-run.sh
