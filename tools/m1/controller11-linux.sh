#!/usr/bin/env bash
set -euo pipefail
umask 077
WORK="$(dirname -- "$(realpath -- "$0")")"
OUT="$(dirname -- "$(dirname -- "$WORK")")/outputs/m1"
[[ $# == 3 && "${WSL_DISTRO_NAME:-}" == Ubuntu-24.04 && "$(id -u)" == 1000 ]] || exit 23
attachment="$(realpath -- "$1")"; attachment_sha="$2"; deadline="$3"
[[ "$attachment" == "$OUT/linux-bootstrap.json" && "$attachment_sha" =~ ^[0-9a-f]{64}$ && "$deadline" =~ ^[0-9]{10}([.][0-9]{1,9})?$ ]] || exit 23
read -r actual _ < <(sha256sum -- "$attachment")
[[ "$actual" == "$attachment_sha" ]] || exit 23
deadline_whole="${deadline%%.*}"
now="$(date +%s)";remaining="$((deadline_whole-now-1))"
[[ "$remaining" -ge 1 && "$remaining" -le 299 ]] || exit 124
read -r nonce < /proc/sys/kernel/random/uuid
unit="tail11agg-$nonce.service"
mkdir -p -- "$OUT/linux-x64" "$OUT/tmp"
set +e
systemd-run --user --quiet --wait --pipe --unit="$unit" \
 --property=Type=exec --property=CPUQuota=200% --property=MemoryMax=536870912 \
 --property=MemorySwapMax=0 --property=TasksMax=64 --property="RuntimeMaxSec=$remaining" \
 --property=TimeoutStopSec=1 --property=KillMode=control-group \
 --working-directory="$WORK" --setenv="TAIL11_ROOT_NONCE=$nonce" \
 --setenv="TAIL11_ROOT_UNIT=$unit" --setenv=WSL_DISTRO_NAME=Ubuntu-24.04 \
 --setenv="TAIL11_EXECUTION=${TAIL11_EXECUTION:-CI_HANDOFF}" --setenv=PYTHONDONTWRITEBYTECODE=1 --setenv="TMPDIR=$OUT/tmp" \
 --setenv="TEMP=$OUT/tmp" --setenv="TMP=$OUT/tmp" \
 /usr/bin/python3 -I -S -B "$WORK/aggregate_worker.py" --attachment "$attachment" \
 --attachment-sha "$attachment_sha" --role linux-root --rid linux-x64
exitcode=$?
set -e
profile="$OUT/linux-x64/aggregate-root-actual-profile.json"
[[ -f "$profile" ]] || exit 25
# JSON is the source-bound, kernel-observed profile. Extract exactly the fixed cgroup field.
cgroup="$(/usr/bin/python3 -I -S -B -c 'import json,sys; print(json.load(open(sys.argv[1]))["cgroup"])' "$profile")"
[[ "$cgroup" == */"$unit" ]] || exit 25
[[ ! -e "/sys/fs/cgroup$cgroup/cgroup.procs" || -z "$(cat -- "/sys/fs/cgroup$cgroup/cgroup.procs")" ]] || exit 25
set +e
terminal="$(systemctl --user show "$unit" --property=MainPID,ControlPID,ActiveState --no-pager)";querycode=$?
set -e
if [[ "$querycode" == 0 ]]; then
 main="$(sed -n 's/^MainPID=//p' <<< "$terminal")";control="$(sed -n 's/^ControlPID=//p' <<< "$terminal")";state="$(sed -n 's/^ActiveState=//p' <<< "$terminal")"
 [[ "$main" == 0 && "$control" == 0 && ( "$state" == inactive || "$state" == failed ) ]] || exit 25
 proof='ORIGINAL_SYSTEMD_WAIT_AND_EMPTY_OR_REMOVED_CGROUP'
else
 [[ ! -e "/sys/fs/cgroup$cgroup" ]] || exit 25
 proof='ORIGINAL_SYSTEMD_WAIT_UNIT_COLLECTED_CGROUP_REMOVED'
fi
receipt="$OUT/linux-x64/aggregate-supervisor-terminal.json"
( set -o noclobber; printf '{"exitCode":%s,"mainPid":0,"controlPid":0,"emptyOrRemovedCgroup":true,"originalUnit":"%s","rootAttachmentSha256":"%s","deadline":%s,"proof":"%s","forcedSuccessClaim":false}\n' \
 "$exitcode" "$unit" "$attachment_sha" "$deadline" "$proof" > "$receipt" )
exit "$exitcode"
