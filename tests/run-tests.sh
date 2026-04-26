#!/usr/bin/env bash
#
# LMD Test Runner — batsman integration wrapper
# Usage: ./tests/run-tests.sh [--os OS] [--parallel [N]] [bats args...]
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BATSMAN_PROJECT="lmd"
BATSMAN_PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BATSMAN_TESTS_DIR="$SCRIPT_DIR"
BATSMAN_INFRA_DIR="$SCRIPT_DIR/infra"
BATSMAN_DOCKER_FLAGS=""
BATSMAN_DEFAULT_OS="debian12"
BATSMAN_CONTAINER_TEST_PATH="/opt/tests"
BATSMAN_SUPPORTED_OS="debian12 centos6 centos7 rocky8 rocky9 rocky10 ubuntu2004 ubuntu2404 yara-x"

# yara-x variant: uses debian12 base image (no separate batsman base for variants)
BATSMAN_BASE_OS_MAP="yara-x=debian12"

source "$BATSMAN_INFRA_DIR/lib/run-tests-core.sh"
batsman_run "$@"
