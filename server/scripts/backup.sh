#!/usr/bin/env bash
# Nightly SQLite backup. Crontab: 0 2 * * * /home/mjnetwork/lamp/beest-license/server/scripts/backup.sh
set -euo pipefail
SRC="${BEEST_DB_PATH:-/home/mjnetwork/lamp/beest-license/beest-data/beest.db}"
DST_DIR="${BEEST_BACKUP_DIR:-/home/mjnetwork/lamp/nextcloud-data/beest-backup}"
mkdir -p "$DST_DIR"
TS="$(date +%F_%H%M)"
if [ -f "$SRC" ]; then
  sqlite3 "$SRC" ".backup '$DST_DIR/beest-$TS.db'"
  ls -t "$DST_DIR"/beest-*.db | tail -n +15 | xargs -r rm --
  echo "backup -> $DST_DIR/beest-$TS.db"
else
  echo "no db yet at $SRC (container not started?)" >&2
fi
