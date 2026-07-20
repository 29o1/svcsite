PYTHON ?= python3
KP_DIR ?= $(CURDIR)/KernelPatch

.PHONY: check kpm clean

check:
	PYTHONPATH=src $(PYTHON) -m compileall -q src

kpm:
	$(MAKE) -C kpm KP_DIR="$(KP_DIR)"

clean:
	$(MAKE) -C kpm clean
