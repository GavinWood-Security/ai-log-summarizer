#!/usr/bin/env python3
"""CLI tool that fetches Microsoft Defender alerts via Graph and produces AI summaries."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv, set_key

try:
    import msal
except ImportError:  # pragma: no cover - handled gracefully at runtime
    msal = None  # type: ignore

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - handled gracefully at runtime
    OpenAI = None  # type: ignore

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
    from tkinter.scrolledtext import ScrolledText
except ImportError:  # pragma: no cover - handled gracefully at runtime
    tk = None  # type: ignore
    messagebox = None  # type: ignore
    ttk = None  # type: ignore
    ScrolledText = None  # type: ignore


GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0/security/alerts_v2"
REQUIRED_ENV_VARS = ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "GRAPH_SCOPE")
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


@dataclass
class Alert:
    """Normalized alert payload used throughout the tool."""

    id: str
    title: str
    description: str
    severity: str
    category: Optional[str]
    created_utc: str
    detection_source: Optional[str]
    status: Optional[str]
    assigned_to: Optional[str]
    host: Optional[str]
    raw: Dict[str, Any]

    @classmethod
    def from_graph(cls, payload: Dict[str, Any]) -> "Alert":
        """Create an Alert from a Graph Security API payload."""
        host = None
        hosts = payload.get("hosts")
        if isinstance(hosts, list) and hosts:
            host_record = hosts[0]
            if isinstance(host_record, dict):
                host = host_record.get("fqdn") or host_record.get("netBiosName")

        return cls(
            id=str(payload.get("id", "")),
            title=str(payload.get("title", "Untitled Alert")),
            description=str(payload.get("description") or "").strip(),
            severity=str(payload.get("severity") or "unknown").upper(),
            category=payload.get("category"),
            created_utc=_safe_datetime(payload.get("createdDateTime")),
            detection_source=payload.get("detectionSource"),
            status=payload.get("status"),
            assigned_to=payload.get("assignedTo"),
            host=host,
            raw=payload,
        )


class GraphSecurityClient:
    """Handles authentication and retrieval of Microsoft Defender alerts."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        scope: str,
    ) -> None:
        if not msal:
            raise RuntimeError(
                "The 'msal' package is required. Install dependencies with `pip install -r requirements.txt`."
            )

        authority = f"https://login.microsoftonline.com/{tenant_id}"
        self._scope = [scope]
        self._app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=authority,
        )

    def fetch_alerts(self, top: int, lookback_hours: int) -> List[Alert]:
        """Fetch alerts from Graph Security API and normalize the payload."""
        token = self._acquire_token()

        created_after = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        params = {
            "$top": top,
            "$orderby": "createdDateTime desc",
            "$filter": f"createdDateTime ge {created_after.isoformat(timespec='seconds')}",
        }
        headers = {
            "Authorization": f"Bearer {token}",
            "ConsistencyLevel": "eventual",
        }

        logging.debug("Requesting alerts: %s", params)
        response = requests.get(
            GRAPH_ENDPOINT, headers=headers, params=params, timeout=30
        )

        if response.status_code >= 400:
            raise RuntimeError(
                f"Graph API request failed ({response.status_code}): {response.text}"
            )

        body = response.json()
        values = body.get("value", [])
        logging.info("Fetched %s alerts from Microsoft Graph.", len(values))

        alerts = [Alert.from_graph(item) for item in values]
        return alerts

    def _acquire_token(self) -> str:
        """Acquire an access token using client credentials flow."""
        result = self._app.acquire_token_silent(self._scope, account=None)
        if not result:
            logging.debug("Token cache miss; requesting new token from Azure AD.")
            result = self._app.acquire_token_for_client(scopes=self._scope)

        if "access_token" not in result:
            raise RuntimeError(f"Failed to acquire token: {result.get('error_description')}")

        return str(result["access_token"])


class OpenAISummarizer:
    """Wraps OpenAI's Responses API for generating human-friendly summaries."""

    def __init__(
        self,
        api_key: str,
        model: str,
        temperature: float = 0.2,
        max_output_tokens: int = 800,
    ) -> None:
        if not OpenAI:
            raise RuntimeError(
                "The 'openai' package is required. Install dependencies with `pip install -r requirements.txt`."
            )

        self._client = OpenAI(api_key=api_key)
        self._model = model
        self._temperature = temperature
        self._max_output_tokens = max_output_tokens

    def summarize(self, alerts: List[Alert]) -> str:
        """Generate a concise executive summary for the provided alerts."""
        if not alerts:
            return "No new Microsoft Defender alerts were returned for the selected time range."

        incidents_json = json.dumps(
            [self._alert_for_llm(alert) for alert in alerts], ensure_ascii=False
        )

        system_prompt = (
            "You are a defensive security analyst drafting an incident digest. "
            "Summaries must be factual, short, and prioritize remediation steps. "
            "Write in professional tone with bullet lists where appropriate."
        )
        user_prompt = (
            "Summarize the following Microsoft Defender alerts. "
            "Include: 1) overall incident narrative, 2) impacted assets, "
            "3) recommended next steps. Ensure every claim is traceable to the source data.\n\n"
            f"ALERT_DATA:\n{incidents_json}"
        )

        response = self._client.responses.create(
            model=self._model,
            temperature=self._temperature,
            max_output_tokens=self._max_output_tokens,
            input=[
                {"role": "system", "content": [{"type": "text", "text": system_prompt}]},
                {"role": "user", "content": [{"type": "text", "text": user_prompt}]},
            ],
        )

        return getattr(response, "output_text", "").strip() or _collect_text(response)

    @staticmethod
    def _alert_for_llm(alert: Alert) -> Dict[str, Any]:
        """Select a subset of fields that help the LLM create focused summaries."""
        data = {
            "id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "category": alert.category,
            "created_utc": alert.created_utc,
            "assigned_to": alert.assigned_to,
            "detection_source": alert.detection_source,
            "status": alert.status,
            "host": alert.host,
        }

        if alert.description:
            data["description"] = alert.description

        return data


class ReportBuilder:
    """Formats alerts and summaries into human-readable outputs."""

    @staticmethod
    def to_markdown(alerts: List[Alert], summary: Optional[str]) -> str:
        generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

        md_lines = [
            f"# Microsoft Defender Daily Digest",
            f"_Generated at {generated_at}_",
            "",
        ]

        if summary:
            md_lines.extend(["## Executive Summary", summary.strip(), ""])
        else:
            md_lines.append("## Executive Summary")
            md_lines.append(
                "AI summary unavailable. Review the detailed alerts below for context."
            )
            md_lines.append("")

        md_lines.append(f"## Detailed Alerts ({len(alerts)})")
        if not alerts:
            md_lines.append("No alerts were returned for the requested window.")
        else:
            for alert in alerts:
                md_lines.extend(
                    [
                        f"### {alert.title} (`{alert.severity}`)",
                        f"- **Alert ID:** {alert.id}",
                        f"- **Created:** {alert.created_utc}",
                        f"- **Category:** {alert.category or 'n/a'}",
                        f"- **Detection Source:** {alert.detection_source or 'n/a'}",
                        f"- **Status:** {alert.status or 'n/a'}",
                        f"- **Assigned To:** {alert.assigned_to or 'unassigned'}",
                        f"- **Host:** {alert.host or 'unknown'}",
                    ]
                )
                if alert.description:
                    md_lines.append("")
                    md_lines.append(alert.description.strip())
                md_lines.append("")

        return "\n".join(md_lines).strip() + "\n"

    @staticmethod
    def to_json(alerts: List[Alert], summary: Optional[str]) -> str:
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": summary,
            "alerts": [asdict(alert) for alert in alerts],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


class SummarizerGUI:
    """Tkinter-based interface for fetching alerts and managing settings."""

    def __init__(self, initial_config: Dict[str, str], default_hours: int, default_top: int) -> None:
        if not tk:
            raise RuntimeError("Tkinter is required for the GUI.")

        self.config = dict(initial_config)
        self.default_hours = default_hours
        self.default_top = default_top
        self.dotenv_path = Path(".env")

        self.root = tk.Tk()
        self.root.title("AI Log Summarizer")
        self.root.minsize(900, 600)

        self.status_var = tk.StringVar(value="Ready.")
        self.hours_var = tk.StringVar(value=str(default_hours))
        self.top_var = tk.StringVar(value=str(default_top))
        self.format_var = tk.StringVar(value="markdown")
        self.setting_vars: Dict[str, tk.StringVar] = {}

        self.fetch_button: ttk.Button
        self.report_text: ScrolledText

        self._build_ui()

    def run(self) -> None:
        self.root.mainloop()

    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=12, pady=12)

        report_tab = ttk.Frame(notebook)
        settings_tab = ttk.Frame(notebook)
        notebook.add(report_tab, text="Report")
        notebook.add(settings_tab, text="Settings")

        self._build_report_tab(report_tab)
        self._build_settings_tab(settings_tab)

    def _build_report_tab(self, parent: ttk.Frame) -> None:
        controls = ttk.Frame(parent)
        controls.pack(fill="x", pady=(0, 8))

        ttk.Label(controls, text="Hours:").grid(row=0, column=0, sticky="w")
        ttk.Entry(controls, width=6, textvariable=self.hours_var).grid(
            row=0, column=1, padx=(4, 12)
        )
        ttk.Label(controls, text="Top:").grid(row=0, column=2, sticky="w")
        ttk.Entry(controls, width=6, textvariable=self.top_var).grid(
            row=0, column=3, padx=(4, 12)
        )
        ttk.Label(controls, text="Format:").grid(row=0, column=4, sticky="w")
        format_box = ttk.Combobox(
            controls,
            textvariable=self.format_var,
            values=("markdown", "json"),
            state="readonly",
            width=12,
        )
        format_box.grid(row=0, column=5, padx=(4, 12))
        format_box.set(self.format_var.get())

        self.fetch_button = ttk.Button(controls, text="Fetch Report", command=self.fetch_report)
        self.fetch_button.grid(row=0, column=6, padx=(8, 0))
        controls.columnconfigure(7, weight=1)

        self.report_text = ScrolledText(parent, wrap="word")
        self.report_text.pack(fill="both", expand=True)
        self.report_text.insert("1.0", "Click 'Fetch Report' to retrieve Microsoft Defender alerts.")

        ttk.Label(parent, textvariable=self.status_var).pack(anchor="w", pady=(8, 0))

    def _build_settings_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)
        fields = [
            ("Tenant ID", "TENANT_ID", False),
            ("Client ID", "CLIENT_ID", False),
            ("Client Secret", "CLIENT_SECRET", True),
            ("Graph Scope", "GRAPH_SCOPE", False),
            ("OpenAI API Key", "OPENAI_API_KEY", True),
            ("OpenAI Model", "OPENAI_MODEL", False),
        ]

        for idx, (label, key, secret) in enumerate(fields):
            ttk.Label(parent, text=label).grid(
                row=idx, column=0, sticky="w", padx=(0, 12), pady=4
            )
            var = tk.StringVar(value=self.config.get(key, ""))
            entry = ttk.Entry(parent, textvariable=var, width=60)
            if secret:
                entry.configure(show="*")
            entry.grid(row=idx, column=1, sticky="ew", pady=4)
            self.setting_vars[key] = var

        ttk.Button(parent, text="Save Settings", command=self.save_settings).grid(
            row=len(fields), column=0, columnspan=2, sticky="e", pady=(12, 0)
        )
        ttk.Label(
            parent,
            text="Saved values are written to .env in this project directory.",
        ).grid(row=len(fields) + 1, column=0, columnspan=2, sticky="w", pady=(8, 0))

    def fetch_report(self) -> None:
        try:
            hours = max(int(self.hours_var.get() or self.default_hours), 1)
            top = max(int(self.top_var.get() or self.default_top), 1)
        except ValueError:
            if messagebox:
                messagebox.showerror("Invalid input", "Hours and Top must be whole numbers.")
            return

        config = self._collect_settings()
        missing = [key for key in REQUIRED_ENV_VARS if not config.get(key)]
        if missing:
            if messagebox:
                messagebox.showerror(
                    "Missing settings", f"Provide values for: {', '.join(missing)}."
                )
            return

        report_format = self.format_var.get() or "markdown"

        self.fetch_button.configure(state=tk.DISABLED)
        self.set_status("Fetching alerts...")

        worker = threading.Thread(
            target=self._fetch_report_worker,
            args=(config, top, hours, report_format),
            daemon=True,
        )
        worker.start()

    def save_settings(self) -> None:
        values = {key: var.get().strip() for key, var in self.setting_vars.items()}
        if not values.get("OPENAI_MODEL"):
            values["OPENAI_MODEL"] = DEFAULT_OPENAI_MODEL

        try:
            if not self.dotenv_path.exists():
                self.dotenv_path.touch()

            for key, value in values.items():
                set_key(str(self.dotenv_path), key, value)

            load_dotenv(dotenv_path=self.dotenv_path, override=True)
            self.config.update(values)
            self.set_status("Settings saved.")
            if messagebox:
                messagebox.showinfo(
                    "Settings saved", f"Configuration stored in {self.dotenv_path.resolve()}."
                )
        except Exception as exc:
            logging.error("Failed to save settings: %s", exc)
            if messagebox:
                messagebox.showerror("Save failed", str(exc))

    def _collect_settings(self) -> Dict[str, str]:
        settings = dict(self.config)
        for key, var in self.setting_vars.items():
            settings[key] = var.get().strip()
        if not settings.get("OPENAI_MODEL"):
            settings["OPENAI_MODEL"] = DEFAULT_OPENAI_MODEL
        return settings

    def _fetch_report_worker(
        self,
        config: Dict[str, str],
        top: int,
        hours: int,
        report_format: str,
    ) -> None:
        try:
            alerts, summary, summary_error = fetch_alerts_and_summary(config, top, hours)
            output = (
                ReportBuilder.to_markdown(alerts, summary)
                if report_format == "markdown"
                else ReportBuilder.to_json(alerts, summary)
            )
            status_message = f"Retrieved {len(alerts)} alert(s)."
            self._deliver_report(output, status_message, summary_error)
        except Exception as exc:
            logging.error("Failed to fetch report: %s", exc)
            self._deliver_error(str(exc))

    def _deliver_report(
        self,
        output: str,
        status_message: str,
        summary_error: Optional[str],
    ) -> None:
        def update() -> None:
            self.report_text.configure(state=tk.NORMAL)
            self.report_text.delete("1.0", tk.END)
            self.report_text.insert(tk.END, output)
            self.fetch_button.configure(state=tk.NORMAL)
            self.set_status(status_message)
            if summary_error and messagebox:
                messagebox.showwarning("AI summary unavailable", summary_error)

        self.root.after(0, update)

    def _deliver_error(self, error_message: str) -> None:
        def update() -> None:
            self.fetch_button.configure(state=tk.NORMAL)
            self.set_status("Failed to fetch alerts.")
            if messagebox:
                messagebox.showerror("Request failed", error_message)

        self.root.after(0, update)

    def set_status(self, message: str) -> None:
        self.status_var.set(message)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch Microsoft Defender alerts and generate an AI summary report."
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="How many hours back to query Defender alerts (default: 24).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=25,
        help="Maximum number of alerts to fetch (default: 25).",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format for the report (default: markdown).",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Optional output file path. If omitted, prints to stdout.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the desktop interface instead of CLI output.",
    )

    return parser.parse_args(argv)


def load_configuration(strict: bool = True) -> Dict[str, str]:
    load_dotenv()
    config = {key: os.getenv(key, "") for key in REQUIRED_ENV_VARS}
    config["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY", "")
    config["OPENAI_MODEL"] = os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL)

    if strict:
        missing = [key for key in REQUIRED_ENV_VARS if not config.get(key)]
        if missing:
            raise RuntimeError(
                f"Missing required environment variables: {', '.join(missing)}. "
                "Store them in a .env file or export them before running the script."
            )

    return config


def fetch_alerts_and_summary(
    config: Dict[str, str],
    top: int,
    hours: int,
) -> Tuple[List[Alert], Optional[str], Optional[str]]:
    graph_client = GraphSecurityClient(
        tenant_id=config["TENANT_ID"],
        client_id=config["CLIENT_ID"],
        client_secret=config["CLIENT_SECRET"],
        scope=config["GRAPH_SCOPE"],
    )
    alerts = graph_client.fetch_alerts(top=top, lookback_hours=hours)

    summary: Optional[str] = None
    summary_error: Optional[str] = None
    api_key = config.get("OPENAI_API_KEY", "")

    if api_key:
        try:
            summarizer = OpenAISummarizer(
                api_key=api_key,
                model=config.get("OPENAI_MODEL") or DEFAULT_OPENAI_MODEL,
            )
            summary = summarizer.summarize(alerts)
        except Exception as exc:  # pragma: no cover - depends on OpenAI runtime
            logging.warning("Failed to generate AI summary: %s", exc)
            summary_error = str(exc)
    else:
        logging.info("OPENAI_API_KEY not provided; skipping AI summary.")

    return alerts, summary, summary_error


def run_cli(args: argparse.Namespace, config: Optional[Dict[str, str]] = None) -> None:
    config = config or load_configuration(strict=True)
    top = max(args.top, 1)
    hours = max(args.hours, 1)
    alerts, summary, summary_error = fetch_alerts_and_summary(config, top, hours)

    if summary_error:
        logging.warning("AI summary unavailable: %s", summary_error)

    if args.format == "markdown":
        output = ReportBuilder.to_markdown(alerts, summary)
    else:
        output = ReportBuilder.to_json(alerts, summary)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
        logging.info("Report written to %s", args.output)
    else:
        sys.stdout.write(output)


def run_gui(default_hours: int, default_top: int) -> None:
    if not tk:
        raise RuntimeError(
            "Tkinter is not available in this environment. Install the tkinter package to launch the GUI."
        )

    config = load_configuration(strict=False)
    app = SummarizerGUI(config, default_hours, default_top)
    app.run()


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    config = load_configuration(strict=False)
    missing = [key for key in REQUIRED_ENV_VARS if not config.get(key)]

    if args.gui or missing:
        if missing and not args.gui:
            logging.info(
                "Required settings missing (%s); launching GUI for configuration.",
                ", ".join(missing),
            )
        try:
            run_gui(max(args.hours, 1), max(args.top, 1))
        except Exception as exc:
            logging.error("%s", exc)
            sys.exit(1)
        return

    try:
        run_cli(args, config=config)
    except Exception as exc:
        logging.error("%s", exc)
        sys.exit(1)


def _safe_datetime(value: Any) -> str:
    """Best-effort serialization of datetime strings for alerts."""
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat(timespec="seconds")
    return "unknown"


def _collect_text(response: Any) -> str:
    """Utility to flatten OpenAI streaming-style responses."""
    chunks: List[str] = []
    for item in getattr(response, "output", []):
        if getattr(item, "type", "") == "output_text":
            chunks.append(getattr(item, "text", ""))
    return "\n".join(chunks).strip()


if __name__ == "__main__":
    main()
