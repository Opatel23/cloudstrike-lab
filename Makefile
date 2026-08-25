.PHONY: demo test lint

demo:
	python -m cloudstrike demo --output outputs/demo-report.json

test:
	python -m unittest discover -s tests -v

lint:
	python -m ruff check .
