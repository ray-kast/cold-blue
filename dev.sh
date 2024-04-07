#!/bin/sh

set -xe
port="$1"
if ! shift 1; then
  echo "usage: ./dev.sh <port> [args...]"
  exit 1
fi
systemfd --no-pid -s http::"$port" -- cargo watch -x "run serve $@"
