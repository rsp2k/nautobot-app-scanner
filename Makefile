# Root Makefile — proxy to development/Makefile so `make <target>` works
# from either the repo root or the development/ subdir.
.DEFAULT_GOAL := help
.PHONY: %

%:
	@$(MAKE) -C development $@
