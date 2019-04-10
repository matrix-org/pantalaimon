test:
	python3 -m pytest
	python3 -m pytest --flake8 pantalaimon
	python3 -m pytest --isort
