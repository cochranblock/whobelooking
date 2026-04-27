#!/usr/bin/env bash
# whobelooking watchdog — run from cron every minute.
# Starts the server if it isn't running. No-op if it is.

BINARY=/home/mcochran/whobelooking/target/diamond/whobelooking
LOG=/home/mcochran/.local/share/whobelooking/logs/watchdog.log

if ! pgrep -x whobelooking > /dev/null 2>&1; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) whobelooking down — restarting" >> "$LOG"
    nohup "$BINARY" serve >> "$LOG" 2>&1 &
fi
