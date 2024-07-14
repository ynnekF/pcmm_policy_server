CWD 			:= $(shell pwd)
PYTHON3 		?= $(shell which python3.11)
PYTEST			:= $(shell which py.test)
.PHONY: help

VDIR 		= $(CWD)/venv

see-dir:
	@echo $(CWD)

install: clean ## Setup virtualenv & install dependencies
	virtualenv --python=$(PYTHON3) $(VDIR)
	. $(VDIR)/bin/activate

	$(VDIR)/bin/python3 -m pip install --upgrade pip setuptools
	$(VDIR)/bin/pip install $(CWD) .
	@rm -rf *.egg-info

clean: ## Clean build artifacts
	-@find ./ -type d -name "__pycache__" | xargs rm -rf
	rm -rf $(CWD)/dist
	rm -rf $(CWD)/build
	rm -rf *.egg-info
	-@$(RM) -rf $(VDIR)

black:
	black . --line-length 120

PYTEST_ARGS=-v --tb=short
