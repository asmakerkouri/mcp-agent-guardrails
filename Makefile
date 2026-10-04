install:
	pip install -r requirements-dev.txt

test:
	ruff check . && pytest -q

demo:            ## red-team scenario with a scripted (hijacked) model, no API key needed
	PYTHONPATH=src python scripts/demo.py

eval:            ## red-team benchmark + figures
	PYTHONPATH=src python eval/redteam.py
	PYTHONPATH=src python scripts/demo.py > /dev/null
	python scripts/make_figures.py

run:             ## real LLM through Ollama, e.g. make run TASK="Summarise the notes into report.md"
	PYTHONPATH=src python -m mcpguard.cli "$(TASK)" --workspace demo_workspace

.PHONY: install test demo eval run
