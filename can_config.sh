#!/usr/bin/env bash
set -euo pipefail

CHANNEL="${1:-can0}"
BITRATE="${2:-500000}"
TXQUEUELEN="${3:-10000}"

printf "[default]\ninterface = socketcan\nchannel = %s\n" "$CHANNEL" > "$HOME/.canrc"

sudo ip link set "$CHANNEL" down 2>/dev/null || true
sudo ip link set "$CHANNEL" type can bitrate "$BITRATE" restart-ms 100
sudo ip link set "$CHANNEL" txqueuelen "$TXQUEUELEN"
sudo ip link set "$CHANNEL" up

ip -details link show "$CHANNEL"
