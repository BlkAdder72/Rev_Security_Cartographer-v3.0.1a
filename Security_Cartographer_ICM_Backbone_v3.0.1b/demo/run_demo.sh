#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
python3 run_demo.py
printf '\nDemonstration complete. Open demo_output/02-blocked-change/map.html\n'

