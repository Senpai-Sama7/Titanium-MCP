.PHONY: run test eval

run:
	uv run server.py

test:
	uv run --with pytest --with pytest-asyncio pytest -q

eval:
	uv run evals/smoke_eval.py
