# AI Log Summarizer

## Overview
AI Log Summarizer is a lightweight Python tool that automatically pulls **Microsoft Defender alerts** through the Microsoft Graph Security API, summarizes them using an AI model, and outputs clear, actionable incident reports.  

Goal: help analysts or small IT teams quickly understand what happened, where, and what to do next—without manually parsing dozens of alerts.

---

## Features
- Pull the latest Microsoft Defender alerts via Microsoft Graph Security API (`/security/alerts_v2`)
- Normalize alert metadata (title, severity, status, timestamp, host, owner)
- Summarize alerts with an OpenAI model to produce an executive digest
- Export the report as Markdown or JSON (stdout or file)
- Launch an optional desktop GUI to run reports and manage credentials
- Run locally without persisting sensitive data anywhere else

---

## Prerequisites
- Python 3.9+
- Azure AD app registration with **application permissions** for `SecurityEvents.Read.All` (or broader as needed)
- Client secret issued for the Azure AD application
- Microsoft Defender alerts available in your tenant
- OpenAI API key (optional — summaries fall back to plain data if omitted)
- Tkinter runtime (optional, required for the GUI — install `python3-tk` if missing)

---

## Quick Start
1. **Clone & enter the repo**
   ```bash
   git clone https://github.com/<your-org>/ai-log-summarizer.git
   cd ai-log-summarizer
   ```

2. **Create a virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**  
   Copy `API_keys.env` to `.env` (or export the variables some other way) and fill in:
   - `TENANT_ID`
   - `CLIENT_ID`
   - `CLIENT_SECRET`
   - `GRAPH_SCOPE` (typically `https://graph.microsoft.com/.default`)
   - `OPENAI_API_KEY` (optional)
   - `OPENAI_MODEL` (optional, defaults to `gpt-4o-mini`)

---

## Usage
Fetch the last 24 hours of alerts, summarize them with OpenAI, and emit Markdown:
```bash
python main.py --hours 24 --top 25 --format markdown --output defender-report.md
```

Common flags:
- `--hours`: lookback window (minimum 1, default 24)
- `--top`: maximum number of alerts to return (default 25)
- `--format`: `markdown` (default) or `json`
- `--output`: destination file; omit to print to stdout
- `--verbose`: enable debug logging

If `OPENAI_API_KEY` is not set, the tool still exports raw alerts without an AI summary.

---

## Example
```bash
python main.py --hours 12 --top 10 --format json
```
Outputs structured JSON like:
```json
{
  "generated_at": "2024-05-01T10:13:00+00:00",
  "summary": "High-level defender incidents summary ...",
  "alerts": [
    {
      "id": "da4b9...",
      "title": "Suspicious PowerShell Command",
      "severity": "HIGH",
      "created_utc": "2024-05-01T08:55:22Z",
      "host": "host01.contoso.com",
      "...": "..."
    }
  ]
}
```

---

## GUI Mode
Prefer a desktop interface? Launch the Tkinter app:
```bash
python main.py --gui
```
Use **Report** to fetch and view summaries (Markdown or JSON), and **Settings** to enter your Microsoft Graph/OpenAI credentials. Saved settings are written to `.env` for future runs.
If you run `python main.py` without the required credentials in your environment, the GUI opens automatically so you can configure them.

---

## Troubleshooting
- **`msal` or `openai` not found**: install dependencies with `pip install -r requirements.txt`.
- **`Failed to acquire token`**: verify tenant/client credentials and that the app registration has the correct permissions.
- **`Graph API request failed (403)`**: ensure API permissions are granted and admin-consented.
- **No alerts returned**: confirm Defender is ingesting alerts and adjust `--hours` / `--top`.
- **OpenAI errors**: check model name, network connectivity, and quota.

---

## Roadmap Ideas
- Pull supporting evidence (entities, remediation steps, emails)
- Schedule reports to email/Splunk/Teams
- Correlate related alerts into incidents
- Add unit tests & CI pipeline
