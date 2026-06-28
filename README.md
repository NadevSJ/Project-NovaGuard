# NovaGuard

An LLM-powered agent that detects scam websites and phishing links in the
Sri Lankan context, with a Streamlit dashboard, a Telegram bot interface, and
a reproducible evaluation harness.

## Prerequisites

- Python 3.10 or newer
- Google Chrome (used by Selenium for live page scraping)
- A Google Gemini API key (free tier is sufficient)

## Installation

```bash
git clone <your-repo-url> novaguard
cd novaguard

python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-eval.txt  # only needed for evaluation/analysis

cp .env.example .env
# then open .env and fill in your keys
```

### Getting a Google Gemini API key

1. Visit https://aistudio.google.com/
2. Sign in with a Google account
3. Open **Get API key** and create a new key (free tier available)
4. Paste it into `.env` as `GOOGLE_API_KEY=...`

Optional keys (`TELEGRAM_BOT_TOKEN`, `URLSCAN_API_KEY`, `VIRUSTOTAL_API_KEY`)
unlock the Telegram bot and baseline-comparison features but are not required
to run the core agent.

## Run commands

```bash
# Streamlit web app
streamlit run app.py

# Telegram bot
python bot/novaguard_bot.py

# Evaluation harness (dry run validates wiring without spending tokens)
python run_evaluation.py --dry-run

# Evaluation dashboard
streamlit run evaluation/eval_dashboard.py
```

## Project structure

```
novaguard/
├── agent/          LLM agent: prompts, chains, and orchestration
├── tools/          Tools the agent can call (URL scrapers, WHOIS, etc.)
├── bot/            Telegram bot entrypoint and handlers
├── evaluation/     Reproducible evaluation pipeline
│   ├── dataset/      Ground-truth labeled URLs (ground_truth.json)
│   ├── metrics/      Accuracy, precision/recall, calibration, etc.
│   ├── benchmarks/   Baseline systems (URLScan, VirusTotal, heuristics)
│   ├── experiments/  Experiment configs and runners
│   ├── annotation/   Annotation guidelines and inter-annotator tools
│   └── reporting/    Plotting and report generation
├── logs/           JSONL run logs (gitignored)
├── results/        Per-experiment JSON/CSV outputs (gitignored)
├── reports/        Generated tables and figures (gitignored)
├── config.py       Central configuration and credential loading
├── requirements.txt        Runtime dependencies
└── requirements-eval.txt   Evaluation-only dependencies
```

## Research citation

NovaGuard is part of an ongoing final-year research project on agentic
scam detection for Sri Lankan users. If you use NovaGuard or its evaluation
artifacts in academic work, please cite the accompanying thesis/paper (see
`reports/` for the latest citation entry once released).
