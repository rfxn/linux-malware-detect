BATSMAN_OS_MODERN := debian12 rocky9 ubuntu2404
BATSMAN_OS_LEGACY := centos7 rocky8 ubuntu2004
BATSMAN_OS_DEEP   := centos6
BATSMAN_OS_EXTRA  := rocky10 yara-x
BATSMAN_OS_ALL    := $(BATSMAN_OS_MODERN) $(BATSMAN_OS_LEGACY) $(BATSMAN_OS_DEEP) $(BATSMAN_OS_EXTRA)
BATSMAN_RUN_TESTS := ./run-tests.sh
BATSMAN_PROJECT   := lmd

# Per-test timeout (seconds): prevents hung scans from blocking the entire suite.
# 180s accommodates heavy scan tests; genuine hangs run 45+ minutes.
# Override at invocation: make test BATSMAN_TEST_TIMEOUT=60
export BATSMAN_TEST_TIMEOUT ?= 180

include infra/include/Makefile.tests

# UAT override: --init reaps orphaned background processes (monitor mode tests),
# --stop-timeout 3 ensures fast container shutdown when background maldet processes
# linger after bats exits.
uat:
	BATSMAN_DOCKER_FLAGS="--init --stop-timeout 3" $(BATSMAN_RUN_TESTS) -- $(BATSMAN_UAT_PATH)
