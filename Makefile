.PHONY: test run

test:
	PYTHONPATH=services/api-gateway python -m pytest

run:
	PYTHONPATH=services/api-gateway uvicorn faro_api.main:app --host 127.0.0.1 --port 8000
