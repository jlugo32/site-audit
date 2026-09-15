.PHONY: help lint test test-live examples

help:
	@echo "make lint       - run shellcheck on the script and the test suite"
	@echo "make test       - run the offline test suite"
	@echo "make test-live  - run the test suite plus a live smoke test against example.com"
	@echo "make examples   - regenerate examples/ from a live run against example.com"

lint:
	shellcheck -x site-audit tests/run.sh

test:
	bash tests/run.sh

test-live:
	LIVE=1 bash tests/run.sh

examples:
	./site-audit example.com --no-color --md examples/example.com.md > examples/example.com.txt
	./site-audit example.com --json > examples/example.com.json
