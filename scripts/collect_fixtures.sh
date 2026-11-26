#!/bin/bash
# Run ON THE UNRAID HOST (not in the container). Copies only the files server.py parses
# into ./fixtures/, with serial numbers masked, so the parsers can be tested against
# your real hardware (run from the repo root):   bash scripts/collect_fixtures.sh && pytest -q tests/test_real_fixtures.py
set -eu
out=fixtures/emhttp
mkdir -p "$out/smart"
src=/var/local/emhttp

# disks.ini: keep everything, mask the drive id (model_serial) down to its last 4 characters
sed -E 's/^(id|idSb)="[^"]*(.{4})"/\1="MASKED\2"/' "$src/disks.ini" > "$out/disks.ini"

# var.ini: only the keys server.py reads (the full file contains licence and flash GUIDs)
grep -E '^(mdState|mdResync|mdResyncPos|mdResyncSize|mdResyncAction|mdNumDisks|mdNumDisabled|mdNumInvalid|mdNumMissing|mdResyncCorr|mdResyncErr|mdResyncDt|mdResyncDb|sbSyncErrs|sbSyncExit)=' \
  "$src/var.ini" > "$out/var.ini"

# cached SMART attribute reports, serial lines masked if any
for f in "$src"/smart/*; do
  [ -f "$f" ] || continue
  sed -E 's/^(Serial [Nn]umber:[[:space:]]+).*/\1MASKED/' "$f" > "$out/smart/$(basename "$f")"
done

# real filesystem sizes (1K blocks) to prove the disks.ini unit assumption
df -k --output=target,size /mnt/disk* /mnt/cache* /mnt/*/ 2>/dev/null | sort -u > fixtures/df.txt || true

echo "Wrote fixtures/ ($(ls "$out/smart" | wc -l) SMART reports). Review the files before sharing them."
