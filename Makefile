test:
	python3 -m pytest
	python3 -m pytest --flake8 pantalaimon
	python3 -m pytest --isort

coverage:
	python3 -m pytest --cov=pantalaimon --cov-report term-missing

typecheck:
	mypy --ignore-missing-imports pantalaimon

run-local:
	python -m pantalaimon.main --log-level debug --config ./contrib/pantalaimon.conf

isort:
	isort -y -p pantalaimon
