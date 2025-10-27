# Project Structure

- `inventory_raw.csv`: Input dataset (synthetic, intentionally messy)
- `run.py`: Orchestrator entrypoint to produce outputs
- `src/pipeline.py`: Validation, normalization, enrichment logic
- `documentations/approach.md`: Pipeline explanation and how to run
- `documentations/prompts.md`: Log for any LLM prompts used
- `documentations/cons.md`: Known limitations and tradeoffs
- `config/openai_api_key.txt`: (optional) place to store the OpenAI API key read by the pipeline (see `config/openai_api_key.example`)
- `README.md`: Problem statement and target schema
- `run_ipv4_validation.py.txt` and `run.py.txt`: Provided templates/examples (not used directly)

Outputs produced by `run.py`:
- `inventory_clean.csv`: Normalized dataset per target schema
- `anomalies.json`: Structured anomalies for follow-up
