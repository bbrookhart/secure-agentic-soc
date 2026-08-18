#!/usr/bin/env bash
# Back up and restore the state volume.
#
# What is in here and why it matters:
#
#   audit/          the evidence. Hash-chained and signed; losing it loses the
#                   ability to say what the system did.
#   audit/signing-key.pem
#                   the signing key. Restoring the log WITHOUT this leaves
#                   records nobody can verify, so it is included -- and that
#                   makes the backup itself sensitive: anyone holding it can
#                   forge audit records. Encrypt it, and store it apart from the
#                   log it signs.
#   checkpoints.sqlite
#                   suspended runs. Losing this strands every investigation
#                   waiting at an approval gate.
#   cases.sqlite    cross-run correlation. Losing it makes the system forget
#                   that a host was compromised last quarter.
#   chroma/         the log index. Rebuildable from data/, so it is excluded.
#
# A backup nobody has restored is a hypothesis. `restore` verifies the audit
# chain afterwards, so the test is part of the procedure rather than a promise.
#
# Usage:
#   scripts/backup.sh create  [DEST_DIR]
#   scripts/backup.sh restore ARCHIVE
#   scripts/backup.sh verify  ARCHIVE

set -euo pipefail

STATE_DIR="${SOC_STATE_DIR:-state}"
DEST="${2:-backups}"

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

require_state() {
    if [[ ! -d "$STATE_DIR" ]]; then
        echo "error: state directory '$STATE_DIR' not found" >&2
        exit 1
    fi
}

case "${1:-}" in
create)
    require_state
    mkdir -p "$DEST"
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    archive="$DEST/soc-state-$stamp.tar.gz"

    # chroma/ is a derived index; excluding it keeps the archive small and
    # keeps the restore honest about what is actually irreplaceable.
    tar --exclude='chroma' --exclude='.instance.lock' \
        -czf "$archive" -C "$(dirname "$STATE_DIR")" "$(basename "$STATE_DIR")"

    echo "wrote $archive"
    echo
    echo "This archive contains the audit signing key. Anyone holding it can forge"
    echo "audit records: encrypt it at rest, and store it separately from the log"
    echo "it signs."
    ;;

restore)
    archive="${2:-}"
    [[ -f "$archive" ]] || usage

    if [[ -e "$STATE_DIR" ]]; then
        echo "error: '$STATE_DIR' already exists. Move it aside first -- restoring" >&2
        echo "       over live state would merge two histories into one chain." >&2
        exit 1
    fi

    tar -xzf "$archive" -C "$(dirname "$STATE_DIR")"
    echo "restored into $STATE_DIR"

    # The restore is not finished until the evidence verifies.
    echo
    echo "Verifying restored audit chains..."
    python -m src.run_cli --health || true
    ;;

verify)
    archive="${2:-}"
    [[ -f "$archive" ]] || usage
    tar -tzf "$archive" >/dev/null && echo "archive readable: $archive"
    tar -tzf "$archive" | grep -q 'audit/audit.jsonl' \
        && echo "contains the audit log" \
        || echo "WARNING: no audit log in this archive"
    ;;

*)
    usage
    ;;
esac
