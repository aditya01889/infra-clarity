"""CLI interface for Infra Clarity."""
import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

from .scanners import TerraformScanner, AWSScanner
from .core.models import ScanResult, Severity

app = typer.Typer()
console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "green"
}

@app.command()
def scan_terraform(
    path: str = typer.Argument(
        ...,
        help="Path to the Terraform directory or file to scan"
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file to save the scan results (JSON format)",
        dir_okay=False,
        writable=True
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Enable debug output"
    )
) -> None:
    """Scan Terraform configurations for potential issues."""
    console.print(Panel.fit("🔍 [bold blue]Scanning Terraform Configuration[/]"))
    
    try:
        scanner = TerraformScanner(path, debug=debug)
        results = scanner.scan()
        _display_results(results)
        
        if output:
            _save_results(results, output)
            
    except Exception as e:
        if debug:
            import traceback
            traceback.print_exc()
        console.print(f"[red]Error during Terraform scan: {str(e)}[/]")
        raise typer.Exit(1)

@app.command()
def scan_aws(
    profile: Optional[str] = typer.Option(
        None,
        "--profile", "-p",
        help="AWS profile to use for authentication"
    ),
    region: str = typer.Option(
        "us-east-1",
        "--region", "-r",
        help="AWS region to scan"
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file to save the scan results (JSON format)",
        dir_okay=False,
        writable=True
    )
) -> None:
    """Scan AWS account for potential issues."""
    console.print(Panel.fit(f"🔍 [bold blue]Scanning AWS Account (Region: {region})[/]"))
    
    try:
        scanner = AWSScanner(profile=profile, region=region)
        results = scanner.scan()
        _display_results(results)
        
        if output:
            _save_results(results, output)
            
    except Exception as e:
        console.print(f"[red]Error during AWS scan: {str(e)}[/]")
        raise typer.Exit(1)

def _display_results(results: ScanResult) -> None:
    """Display scan results in a formatted table."""
    # Summary
    console.print("\n[bold]📊 Scan Results Summary[/]")
    
    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Severity", style="dim")
    summary_table.add_column("Count", justify="right")
    
    severity_counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 0
    }
    
    for finding in results.findings:
        severity_counts[finding.severity] += 1
    
    for severity, count in severity_counts.items():
        if count > 0:
            summary_table.add_row(
                f"[{SEVERITY_COLORS[severity]}]{severity.value}[/]",
                f"[bold]{count}"
            )
    
    console.print(summary_table)
    
    # Detailed findings
    if results.findings:
        console.print("\n[bold]🔎 Detailed Findings[/]")
        
        for finding in sorted(results.findings, key=lambda x: x.severity.value, reverse=True):
            # Convert details to a readable string
            details_str = ""
            if finding.details:
                details_str = "\n[bold]Details:[/]\n"
                for key, value in finding.details.items():
                    details_str += f"  • {key}: {value}\n"
            
            console.print(
                Panel(
                    f"[bold]Resource:[/] {finding.resource_id}\n"
                    f"[bold]Type:[/] {finding.resource_type.value}\n"
                    f"[bold]Finding:[/] {finding.finding_type}\n"
                    f"[bold]Message:[/] {finding.message}\n"
                    f"[bold]Remediation:[/] {finding.remediation or 'No remediation provided'}"
                    f"{details_str}",
                    title=f"[{SEVERITY_COLORS[finding.severity]}]{finding.severity.value}: {finding.finding_type}[/]",
                    border_style=SEVERITY_COLORS[finding.severity]
                )
            )
    else:
        console.print("\n✅ [green]No issues found![/]")

def _save_results(results: ScanResult, output_path: Path) -> None:
    """Save scan results to a JSON file."""
    import json
    
    try:
        with open(output_path, 'w') as f:
            json.dump({
                'findings': [finding.dict() for finding in results.findings],
                'metadata': results.metadata
            }, f, indent=2, default=str)
            
        console.print(f"\n💾 [green]Results saved to {output_path}[/]")
    except Exception as e:
        console.print(f"[red]Error saving results to {output_path}: {str(e)}[/]")
        raise typer.Exit(1)

if __name__ == "__main__":
    app()
