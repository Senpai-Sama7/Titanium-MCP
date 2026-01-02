.PHONY: run test eval

run:
	uv run server.py

test:
		uv run --with pytest --with pytest-asyncio --with pytest-cov pytest -q --cov=. --cov-report=term-missing --cov-fail-under=65

eval:
		uv run evals/run_eval.py
