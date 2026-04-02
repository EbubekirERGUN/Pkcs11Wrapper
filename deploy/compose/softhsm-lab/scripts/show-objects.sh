#!/usr/bin/env bash

set -euo pipefail

exec /opt/pkcs11-lab/scripts/seed-token.sh --list-only
