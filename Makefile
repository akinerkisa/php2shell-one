.PHONY: install test smoke
install:
	python -m pip install -e .
test:
	python -m unittest discover -s tests -v
smoke:
	php2shell status
	php2shell hunt --access-log examples/access.log --error-log examples/error.log
	php2shell repo-audit lab
