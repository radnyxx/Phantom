"""Live terminal dashboard using rich."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from analyzer.scorer import RiskAssessment, RiskLevel
from intel.queries import IntelResult

LEVEL_STYLE = {
    RiskLevel.LOW: "bold green",
    RiskLevel.MEDIUM: "bold yellow",
    RiskLevel.HIGH: "bold orange3",
    RiskLevel.CRITICAL: "bold red",
}

LEVEL_BAR = {
    RiskLevel.LOW: "█░░░",
    RiskLevel.MEDIUM: "██░░",
    RiskLevel.HIGH: "███░",
    RiskLevel.CRITICAL: "████",
}


def show_dashboard(
    intel: IntelResult,
    assessment: RiskAssessment,
    hash_match: dict | None = None,
) -> None:
    """Render a live terminal dashboard for scan results."""
    console = Console()

    pixel_3d_banner = (
        "  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗\n"
        "  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║\n"
        "  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║\n"
        "  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║\n"
        "  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║\n"
        "  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝"
    )
    
    console.print(f"[bold #a7c957]{pixel_3d_banner}[/bold #a7c957]")
    console.print("  [dim]Threat Intelligence Dashboard[/dim]\n")
    
    # Target info
    info = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    info.add_column("Key", style="dim")
    info.add_column("Value")
    info.add_row("Target", f"[bold]{intel.target}[/bold]")
    info.add_row("Type", intel.target_type.upper())
    mode = intel.sources.get("mode", "free")
    mode_label = "Enhanced (API keys)" if mode == "enhanced" else "Free (zero-key)"
    info.add_row("Intel Mode", mode_label)
    console.print(info)
    console.print()

    # Risk gauge
    style = LEVEL_STYLE[assessment.level]
    risk_text = Text()
    risk_text.append(f"  {LEVEL_BAR[assessment.level]}  ", style=style)
    risk_text.append(f"{assessment.level.value}", style=style)
    risk_text.append(f"  (score: {assessment.score})", style="dim")
    console.print(Panel(risk_text, title="Risk Level", border_style="white"))
    console.print()

    # Score breakdown
    if assessment.breakdown:
        breakdown = Table(title="Score Breakdown", box=box.ROUNDED, show_lines=False)
        breakdown.add_column("Factor", style="#a7c957")
        breakdown.add_column("Points", justify="right", style="bold")
        for factor, pts in assessment.breakdown.items():
            label = factor.replace("_", " ").title()
            breakdown.add_row(label, f"+{pts}")
        console.print(" [bold #a7c957]Score Breakdown[/bold #a7c957]")
        console.print()

    # Findings
    if intel.raw_findings:
        findings = Table(title="Findings", box=box.ROUNDED)
        findings.add_column("#", style="dim", width=3)
        findings.add_column("Detail")
        for i, finding in enumerate(intel.raw_findings, 1):
            findings.add_row(str(i), finding)
        console.print(" [bold #a7c957]Findings[/bold #a7c957]")
        console.print()

    # Sources summary
    if intel.sources:
        sources = Table(title="Intel Sources", box=box.ROUNDED)
        sources.add_column("Source", style="#a7c957")
        sources.add_column("Status", style="green")
        for name in intel.sources:
            if name == "mode":
                continue
            sources.add_row(name.replace("_", " ").title(), "✓ Data received")
        console.print(sources)
        console.print()

    # Hash check
    if hash_match:
        status = "[red]MATCH — known IOC[/red]" if hash_match.get("found") else "[green]No match[/green]"
        console.print(Panel(
            f"Hash: [dim]{hash_match.get('hash', '')}[/dim]\nResult: {status}",
            title="Local Hash Check (C)",
            border_style="magenta",
        ))
        console.print()

   # Errors
    if intel.errors:
        error_text = "\n".join(f"[bold yellow]![/bold yellow] {err}" for err in intel.errors)
        console.print(Panel(
            f"[yellow]{error_text}[/yellow]", 
            title="System Warnings", 
            border_style="yellow",
            box=box.ROUNDED
        ))
        
        console.print()
    console.print(Panel(
        assessment.summary,
        title="Summary",
        border_style="dim",
    ))
