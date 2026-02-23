"""ThreatTriage CLI — command-line interface for log analysis."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from threattriage.analysis.anomaly import AnomalyDetector
from threattriage.analysis.correlator import AlertCorrelator
from threattriage.analysis.detection import DetectionEngine
from threattriage.analysis.mitre_mapper import MitreMapper
from threattriage.analysis.scorer import SeverityScorer
from threattriage.parsers.base import create_registry
from threattriage.reports.generator import ReportGenerator

app = typer.Typer(
    name="threattriage",
    help="🛡️ ThreatTriage — Automated SOC Alert & Log Analysis Engine",
    add_completion=False,
)
console = Console()


@app.command()
def analyze(
    log_file: Path = typer.Argument(..., help="Path to log file to analyze"),
    log_type: Optional[str] = typer.Option(None, "--type", "-t", help="Force log type (syslog, http_access, db_audit)"),
    output_dir: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory for reports"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output results as JSON"),
) -> None:
    """Analyze a log file for threats and generate incident reports."""

    if not log_file.exists():
        console.print(f"[red]Error:[/red] File not found: {log_file}")
        raise typer.Exit(1)

    console.print(Panel.fit(
        "🛡️ [bold cyan]ThreatTriage[/bold cyan] — Automated SOC Analysis",
        border_style="cyan",
    ))

    # Read log file
    lines = log_file.read_text().splitlines()
    console.print(f"\n📄 Loaded [bold]{len(lines)}[/bold] lines from [cyan]{log_file.name}[/cyan]")

    # Parse
    from threattriage.models.base import LogType
    registry = create_registry()
    lt = LogType(log_type) if log_type else None
    parsed = registry.parse_batch(lines, lt)
    console.print(f"✅ Parsed [bold]{len(parsed)}[/bold] log entries")

    # Detect
    engine = DetectionEngine()
    detections = engine.evaluate_batch(parsed)

    anomaly_detector = AnomalyDetector()
    anomalies = anomaly_detector.detect_anomalies(parsed)

    scorer = SeverityScorer()
    for det in detections:
        scored = scorer.score_detection(det)
        det.rule.severity = scored.severity

    console.print(f"🚨 Generated [bold red]{len(detections)}[/bold red] rule detections")
    console.print(f"📊 Found [bold yellow]{len(anomalies)}[/bold yellow] anomalies")

    # Alert Table
    if detections or anomalies:
        table = Table(title="🔔 Alerts", box=box.ROUNDED, show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Type", width=12)
        table.add_column("Name", width=35)
        table.add_column("Source IP", width=18)
        table.add_column("MITRE", width=20)

        severity_colors = {
            "critical": "red", "high": "bright_red",
            "medium": "yellow", "low": "blue", "info": "dim",
        }

        for det in detections:
            sev = det.rule.severity.value
            color = severity_colors.get(sev, "white")
            table.add_row(
                f"[{color}]{sev.upper()}[/{color}]",
                "Rule",
                det.rule.name,
                det.parsed_log.source_ip or "—",
                ", ".join(det.rule.mitre_technique_ids[:3]),
            )

        for anom in anomalies:
            sev = anom.severity.value
            color = severity_colors.get(sev, "white")
            table.add_row(
                f"[{color}]{sev.upper()}[/{color}]",
                "Anomaly",
                anom.anomaly_type.replace("_", " ").title(),
                anom.source_ip or "—",
                ", ".join(anom.mitre_technique_ids[:3]),
            )

        console.print(table)

    # Correlate into incidents
    correlator = AlertCorrelator()
    incidents = correlator.correlate(detections, anomalies)
    console.print(f"\n🔗 Correlated into [bold]{len(incidents)}[/bold] incident(s)")

    # MITRE ATT&CK Summary
    all_techniques: set[str] = set()
    all_tactics: set[str] = set()
    for inc in incidents:
        all_techniques.update(inc.mitre_techniques)
        all_tactics.update(inc.mitre_tactics)

    if all_tactics:
        mapper = MitreMapper()
        console.print(f"\n🎯 [bold]MITRE ATT&CK Coverage:[/bold]")
        console.print(f"   Tactics: [cyan]{' → '.join(sorted(all_tactics))}[/cyan]")
        console.print(f"   Techniques: [cyan]{', '.join(sorted(all_techniques))}[/cyan]")

    # Generate Reports
    if incidents and output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        report_gen = ReportGenerator()

        for inc in incidents:
            paths = report_gen.save_reports(inc, output_dir)
            console.print(f"\n📝 Report saved:")
            console.print(f"   JSON: [green]{paths['json']}[/green]")
            console.print(f"   HTML: [green]{paths['html']}[/green]")
            console.print(f"   MITRE Layer: [green]{paths['mitre_layer']}[/green]")

    elif incidents and not output_dir:
        console.print("\n💡 [dim]Tip: Use --output DIR to save full incident reports[/dim]")

    # JSON output
    if json_output:
        report_gen = ReportGenerator()
        all_reports = [report_gen.generate_json_report(inc) for inc in incidents]
        print(json.dumps(all_reports, indent=2, default=str))

    # Summary
    suspicious = sum(1 for p in parsed if p.is_suspicious)
    console.print(Panel(
        f"[bold]Analysis Complete[/bold]\n"
        f"  📄 Logs parsed: {len(parsed)}\n"
        f"  ⚠️  Suspicious: {suspicious}\n"
        f"  🚨 Alerts: {len(detections) + len(anomalies)}\n"
        f"  🔗 Incidents: {len(incidents)}\n"
        f"  🎯 MITRE Techniques: {len(all_techniques)}",
        title="📊 Summary",
        border_style="green",
    ))


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="API host"),
    port: int = typer.Option(8000, "--port", "-p", help="API port"),
    reload: bool = typer.Option(True, "--reload/--no-reload", help="Enable auto-reload"),
) -> None:
    """Start the ThreatTriage API server."""
    import uvicorn
    console.print(Panel.fit(
        "🛡️ [bold cyan]ThreatTriage API Server[/bold cyan]",
        border_style="cyan",
    ))
    console.print(f"  📡 Starting on [bold]http://{host}:{port}[/bold]")
    console.print(f"  📖 API Docs: [bold]http://{host}:{port}/docs[/bold]")

    uvicorn.run(
        "threattriage.main:app",
        host=host,
        port=port,
        reload=reload,
    )


@app.command()
def demo() -> None:
    """Run analysis on built-in sample data to demonstrate capabilities."""
    sample_dir = Path(__file__).parent.parent.parent / "sample_data"

    console.print(Panel.fit(
        "🛡️ [bold cyan]ThreatTriage Demo Mode[/bold cyan]",
        border_style="cyan",
    ))

    for log_file in sorted(sample_dir.glob("*.log")):
        console.print(f"\n{'='*60}")
        console.print(f"📂 Analyzing: [bold]{log_file.name}[/bold]")
        console.print(f"{'='*60}")

        # Invoke analyze for each sample file
        analyze(log_file=log_file, output_dir=Path("reports"), json_output=False, log_type=None)


if __name__ == "__main__":
    app()
