PYTHON ?= python3
KP_DIR ?= $(CURDIR)/KernelPatch

BENCH_PACKAGE ?= io.z9null.tracefixture
BENCH_DEVICE ?=

ifneq ($(strip $(BENCH_DEVICE)),)
BENCH_DEVICE_FLAG := --device $(BENCH_DEVICE)
endif

.PHONY: check kpm bench clean

check:
	PYTHONPATH=src $(PYTHON) -m compileall -q src

kpm:
	$(MAKE) -C kpm KP_DIR="$(KP_DIR)"

bench:
	PYTHONPATH=src $(PYTHON) -m z9mon bench run \
	  --package $(BENCH_PACKAGE) \
	  --kpm $(CURDIR)/kpm/z9null_monitor.kpm \
	  $(BENCH_DEVICE_FLAG) \
	  --json

clean:
	$(MAKE) -C kpm clean
