"""ArqSOC CLI - Full-featured SOC analysis terminal toolkit."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from arqsoc import __version__

app = typer.Typer(
    name="arqsoc",
    help="ArqSOC - Full-featured SOC analysis terminal toolkit",
    no_args_is_help=True,
    rich_markup_mode=None,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"arqsoc {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: bool = typer.Option(
        None, "--version", "-V", help="Show version and exit",
        callback=_version_callback, is_eager=True,
    ),
) -> None:
    pass


def _output_result(data: object, output: Optional[str], quiet: bool, json_output: bool) -> None:
    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if json_output or isinstance(data, (dict, list)):
            out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        else:
            out_path.write_text(str(data), encoding="utf-8")
        if not quiet:
            typer.echo(f"Output written to {output}")

    elif json_output:
        typer.echo(json.dumps(data, indent=2, default=str))

    elif not quiet:
        from rich.console import Console
        console = Console()
        if isinstance(data, str):
            console.print(data)
        else:
            console.print(data)


@app.command()
def scan(
    file: Path = typer.Argument(..., help="Binary file to scan", exists=True),
    rules_dir: Optional[Path] = typer.Option(None, "--rules", "-r", help="YARA rules directory"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show imports and strings"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
    html: bool = typer.Option(False, "--html", help="Generate HTML report"),
) -> None:
    """Full malware scan of a binary file."""
    from arqsoc.core.analyzer import scan_file
    from arqsoc.core.formatter import format_scan_result
    from rich.console import Console

    result = scan_file(file, rules_dir=rules_dir)

    if json_output:
        _output_result(result.model_dump(), output, quiet, json_output)
    elif html:
        from arqsoc.reports.html_report import generate_html_report
        out_path = Path(output) if output else file.with_suffix(".report.html")
        html_str = generate_html_report(result, out_path)
        if not quiet:
            typer.echo(f"HTML report written to {out_path}")
    else:
        console = Console()
        format_scan_result(console, result, verbose=verbose)


@app.command()
def strings(
    file: Path = typer.Argument(..., help="Binary file to extract strings from", exists=True),
    min_length: int = typer.Option(4, "--min-length", "-n", help="Minimum string length"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
) -> None:
    """Extract and classify strings from a binary."""
    from arqsoc.core.strings import analyze_strings
    from arqsoc.core.formatter import format_strings
    from rich.console import Console

    result = analyze_strings(file, min_length=min_length)

    if json_output:
        data = [s.model_dump() for s in result]
        _output_result(data, output, quiet, json_output)
    else:
        console = Console()
        format_strings(console, result)


@app.command()
def disasm(
    file: Path = typer.Argument(..., help="Binary file to disassemble", exists=True),
    arch: Optional[str] = typer.Option(None, "--arch", "-a", help="Architecture (x86, x64, arm32, arm64, mips)"),
    section: Optional[str] = typer.Option(None, "--section", "-s", help="Section to disassemble"),
    start_addr: Optional[str] = typer.Option(None, "--addr", help="Start address (hex)"),
    count: int = typer.Option(200, "--count", "-c", help="Number of instructions"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
) -> None:
    """Disassemble a binary file."""
    from arqsoc.core.disassembler import disassemble_file, format_instruction
    from arqsoc.models.scan_result import ArchType

    arch_map = {
        "x86": ArchType.X86, "x64": ArchType.X64,
        "arm32": ArchType.ARM32, "arm64": ArchType.ARM64,
        "mips": ArchType.MIPS,
    }
    detected_arch = arch_map.get(arch, None) if arch else None

    addr_val = None
    if start_addr:
        try:
            addr_val = int(start_addr, 16)
        except ValueError:
            typer.echo(f"Invalid address: {start_addr}", err=True)
            raise typer.Exit(1)

    instructions = disassemble_file(file, arch=detected_arch, section_name=section, start_addr=addr_val, count=count)

    if json_output:
        data = [{"addr": a, "size": s, "mnemonic": m, "op_str": o} for a, s, m, o in instructions]
        _output_result(data, output, quiet, json_output)
    else:
        for addr, size, mnemonic, op_str in instructions:
            typer.echo(format_instruction(addr, size, mnemonic, op_str))


@app.command()
def hexdump(
    file: Path = typer.Argument(..., help="File to hex dump", exists=True),
    offset: int = typer.Option(0, "--offset", help="Start offset (decimal)"),
    length: int = typer.Option(256, "--length", "-n", help="Bytes to dump"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
) -> None:
    """Hex dump of a file."""
    from arqsoc.utils.hexdump import format_hexdump

    data = file.read_bytes()
    result = format_hexdump(data, offset, length)

    if json_output:
        _output_result(result.split("\n"), output, quiet, json_output)
    else:
        typer.echo(result)


@app.command()
def lookup(
    value: str = typer.Argument(..., help="Hash, IP, or domain to look up"),
    vt_key: Optional[str] = typer.Option(None, "--vt-key", help="VirusTotal API key"),
    source: str = typer.Option("auto", "--source", "-s", help="Source: auto, vt, abuseipdb, shodan"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
) -> None:
    """Look up IOC in threat intelligence databases."""
    from arqsoc.utils.vt import vt_auto_lookup, vt_lookup_hash, vt_lookup_ip, vt_lookup_domain
    from arqsoc.utils.abuseipdb import abuseipdb_lookup as abuseipdb_lookup_fn
    from arqsoc.utils.shodan_client import shodan_lookup as shodan_lookup_fn
    from rich.console import Console
    from rich.table import Table

    result: dict[str, str] = {}
    if source == "vt":
        result = vt_auto_lookup(value, api_key=vt_key)
    elif source == "abuseipdb":
        result = abuseipdb_lookup_fn(value)
    elif source == "shodan":
        result = shodan_lookup_fn(value)
    else:
        result = vt_auto_lookup(value, api_key=vt_key)

    if json_output:
        _output_result(result, output, quiet, json_output)
    else:
        console = Console()
        table = Table(title=f"Lookup: {value}", border_style="dim")
        table.add_column("Field", style="bold cyan")
        table.add_column("Value", style="white")
        for k, v in sorted(result.items()):
            table.add_row(k, v)
        console.print(table)


@app.command(name="diff")
def diff_cmd(
    file_a: Path = typer.Argument(..., help="First binary file", exists=True),
    file_b: Path = typer.Argument(..., help="Second binary file", exists=True),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
) -> None:
    """Diff two binary files."""
    from arqsoc.core.diff import compare_binaries
    from rich.console import Console
    from rich.table import Table

    result = compare_binaries(file_a, file_b)

    if json_output:
        _output_result({
            "hash_match": result.hash_match,
            "byte_similarity": result.byte_similarity,
            "added_imports": len(result.added_imports),
            "removed_imports": len(result.removed_imports),
            "added_sections": result.added_sections,
            "removed_sections": result.removed_sections,
            "modified_sections": result.modified_sections,
        }, output, quiet, json_output)
    else:
        console = Console()
        console.print(f"[bold]Binary Diff[/bold]")
        console.print(f"  Hash match:      {result.hash_match}")
        console.print(f"  Byte similarity: {result.byte_similarity:.2%}")
        console.print(f"  Added imports:   {len(result.added_imports)}")
        console.print(f"  Removed imports: {len(result.removed_imports)}")
        if result.added_sections:
            console.print(f"  Added sections:  {', '.join(result.added_sections)}")
        if result.removed_sections:
            console.print(f"  Removed sections: {', '.join(result.removed_sections)}")
        if result.modified_sections:
            console.print(f"  Modified sections: {', '.join(result.modified_sections)}")


@app.command(name="extract-iocs")
def extract_iocs_cmd(
    file: Path = typer.Argument(..., help="Binary file to extract IOCs from", exists=True),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    cef: bool = typer.Option(False, "--cef", help="Output in CEF format"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
) -> None:
    """Extract IOCs from a binary file."""
    from arqsoc.core.ioc_extractor import extract_iocs
    from arqsoc.core.formatter import format_iocs
    from arqsoc.formatters.cef import iocs_to_cef
    from rich.console import Console

    iocs = extract_iocs(file)

    if json_output:
        data = [ioc.model_dump() for ioc in iocs]
        _output_result(data, output, quiet, json_output)
    elif cef:
        cef_lines = iocs_to_cef(iocs)
        for line in cef_lines:
            typer.echo(line)
    else:
        console = Console()
        format_iocs(console, iocs)


@app.command(name="parse-logs")
def parse_logs_cmd(
    path: Path = typer.Argument(..., help="Log file or directory to parse"),
    fmt: Optional[str] = typer.Option(None, "--format", "-f", help="Log format (syslog, auth_log, suricata, zeek, json, plain)"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
) -> None:
    """Parse and normalize security log files."""
    from arqsoc.core.log_parser import parse_log_file, parse_log_directory
    from arqsoc.core.formatter import format_log_events
    from arqsoc.models.log_event import LogFormat
    from rich.console import Console

    log_fmt = None
    if fmt:
        fmt_map = {
            "syslog": LogFormat.SYSLOG, "auth_log": LogFormat.AUTH_LOG,
            "evtx_xml": LogFormat.EVTX_XML, "suricata": LogFormat.SURICATA,
            "zeek": LogFormat.ZEEK, "json": LogFormat.JSON, "plain": LogFormat.PLAIN,
        }
        log_fmt = fmt_map.get(fmt.lower())

    if path.is_dir():
        results = parse_log_directory(path, fmt=log_fmt)
        if json_output:
            data = {k: [e.model_dump() for e in v] for k, v in results.items()}
            _output_result(data, output, quiet, json_output)
        else:
            console = Console()
            for name, events in results.items():
                typer.echo(f"\n== {name} ({len(events)} events) ==")
                format_log_events(console, events)
    else:
        events = parse_log_file(path, fmt=log_fmt)
        if json_output:
            data = [e.model_dump() for e in events]
            _output_result(data, output, quiet, json_output)
        else:
            console = Console()
            format_log_events(console, events)


@app.command()
def correlate(
    binary: Optional[Path] = typer.Option(None, "--binary", "-b", help="Binary file to extract IOCs from"),
    log: Optional[Path] = typer.Option(None, "--log", "-l", help="Log file to correlate against"),
    iocs_file: Optional[Path] = typer.Option(None, "--iocs", help="JSON file of pre-extracted IOCs"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    cef: bool = typer.Option(False, "--cef", help="Output in CEF format"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
) -> None:
    """Correlate IOCs with log events to generate alerts."""
    from arqsoc.core.ioc_extractor import extract_iocs
    from arqsoc.core.log_parser import parse_log_file
    from arqsoc.core.alert_correlator import correlate_iocs_events
    from arqsoc.core.formatter import format_alerts
    from arqsoc.formatters.cef import alerts_to_cef
    from arqsoc.models.ioc import IOC
    from rich.console import Console

    iocs: list[IOC] = []
    if binary:
        iocs = extract_iocs(binary)
    elif iocs_file:
        data = json.loads(iocs_file.read_text(encoding="utf-8"))
        iocs = [IOC.model_validate(i) for i in data]

    events = []
    if log:
        events = parse_log_file(log)

    if not iocs:
        typer.echo("No IOCs provided. Use --binary or --iocs.", err=True)
        raise typer.Exit(1)
    if not events:
        typer.echo("No log events provided. Use --log.", err=True)
        raise typer.Exit(1)

    alerts = correlate_iocs_events(iocs, events)

    if json_output:
        data = [a.model_dump() for a in alerts]
        _output_result(data, output, quiet, json_output)
    elif cef:
        for line in alerts_to_cef(alerts):
            typer.echo(line)
    else:
        console = Console()
        format_alerts(console, alerts)


@app.command()
def enrich(
    file: Optional[Path] = typer.Option(None, "--binary", "-b", help="Binary file to extract and enrich IOCs"),
    iocs_json: Optional[str] = typer.Option(None, "--iocs", help="IOC values (comma-separated types:values)"),
    vt_key: Optional[str] = typer.Option(None, "--vt-key", help="VirusTotal API key"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
) -> None:
    """Enrich IOCs with threat intelligence data."""
    from arqsoc.core.ioc_extractor import extract_iocs
    from arqsoc.core.threat_intel import enrich_ioc
    from arqsoc.core.formatter import format_iocs
    from arqsoc.models.ioc import IOC, IOCType, RiskLevel
    from rich.console import Console

    iocs: list[IOC] = []
    if file:
        iocs = extract_iocs(file)
    elif iocs_json:
        for pair in iocs_json.split(","):
            if ":" in pair:
                ioc_type_str, value = pair.split(":", 1)
                try:
                    ioc_type = IOCType(ioc_type_str.strip())
                    iocs.append(IOC(ioc_type=ioc_type, value=value.strip(), risk_level=RiskLevel.MEDIUM))
                except ValueError:
                    typer.echo(f"Unknown IOC type: {ioc_type_str}", err=True)

    enriched = [enrich_ioc(ioc) for ioc in iocs]

    if json_output:
        data = [ioc.model_dump() for ioc in enriched]
        _output_result(data, output, quiet, json_output)
    else:
        console = Console()
        format_iocs(console, enriched)


@app.command()
def triage(
    path: Path = typer.Argument(..., help="File or directory to triage"),
    vt_lookup_flag: bool = typer.Option(False, "--vt", help="Include VirusTotal lookup"),
    max_files: int = typer.Option(1000, "--max-files", "-m", help="Max files in directory triage"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
) -> None:
    """Triage files by risk score."""
    from arqsoc.core.triage import triage_file, triage_directory
    from arqsoc.core.formatter import format_triage_results
    from rich.console import Console

    if path.is_dir():
        results = triage_directory(path, vt_lookup=vt_lookup_flag, max_files=max_files)
    else:
        results = [triage_file(path, vt_lookup=vt_lookup_flag)]

    if json_output:
        data = [r.model_dump() for r in results]
        _output_result(data, output, quiet, json_output)
    else:
        console = Console()
        format_triage_results(console, results)


@app.command()
def incident(
    binary: Optional[Path] = typer.Option(None, "--binary", "-b", help="Binary file for incident analysis"),
    log: Optional[Path] = typer.Option(None, "--log", "-l", help="Log file for timeline"),
    title: Optional[str] = typer.Option(None, "--title", "-t", help="Incident title"),
    html_report: bool = typer.Option(False, "--html", help="Generate HTML incident report"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
) -> None:
    """Generate an incident report with MITRE ATT&CK mapping."""
    from arqsoc.core.analyzer import scan_file
    from arqsoc.core.ioc_extractor import extract_iocs
    from arqsoc.core.log_parser import parse_log_file
    from arqsoc.core.mitre_mapper import build_mitre_report
    from arqsoc.core.timeline import build_timeline
    from arqsoc.core.alert_correlator import correlate_iocs_events
    from arqsoc.models.incident import IncidentReport, RiskAssessment
    from arqsoc.core.formatter import format_mitre_mappings, format_incident_timeline
    from rich.console import Console

    iocs = []
    imports = []
    strings_list = []
    indicators = []
    events = []
    alerts = []

    if binary:
        scan_result = scan_file(binary)
        iocs = extract_iocs(binary)
        imports = scan_result.imports
        strings_list = scan_result.strings
        indicators = scan_result.threat_indicators

    if log:
        events = parse_log_file(log)

    if iocs and events:
        alerts = correlate_iocs_events(iocs, events)

    mitre_mappings = build_mitre_report(imports, strings_list, indicators)
    timeline_entries = build_timeline(events, iocs=iocs)

    recommendations: list[str] = []
    if any(m.technique_id.startswith("T1055") for m in mitre_mappings):
        recommendations.append("Investigate process injection -- check for injected code in running processes")
    if any(m.technique_id.startswith("T1071") for m in mitre_mappings):
        recommendations.append("Block identified C2 IPs/domains at firewall/proxy")
    if any(m.technique_id.startswith("T1112") for m in mitre_mappings):
        recommendations.append("Check registry persistence keys and clean up")
    if any(m.technique_id.startswith("T1053") for m in mitre_mappings):
        recommendations.append("Review scheduled tasks for malicious entries")
    if any(m.technique_id.startswith("T1003") for m in mitre_mappings):
        recommendations.append("Reset compromised credentials and check for credential dumping tools")
    if not recommendations:
        recommendations.append("Monitor for further suspicious activity")

    max_risk = 0.0
    if indicators:
        max_risk = max(i.confidence for i in indicators)
    if iocs:
        risk_map = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.0}
        ioc_risk = max(risk_map.get(ioc.risk_level.value, 0.0) for ioc in iocs)
        max_risk = max(max_risk, ioc_risk)

    report = IncidentReport(
        title=title or f"Incident Analysis - {binary.name if binary else 'Unknown'}",
        date=__import__("datetime").datetime.now().isoformat(),
        summary=f"Analysis of {'binary ' + str(binary) if binary else ''}{' and ' + str(log) if log else ''}".strip(" and "),
        iocs=iocs,
        alerts=alerts,
        mitre_mappings=mitre_mappings,
        timeline=timeline_entries,
        recommendations=recommendations,
        risk_assessment=RiskAssessment(risk_score=round(max_risk, 2)),
    )

    if json_output:
        _output_result(report.model_dump(), output, quiet, json_output)
    elif html_report:
        from arqsoc.reports.incident_report import generate_incident_report as gen_report
        out_path = Path(output) if output else Path("incident_report.html")
        gen_report(report, out_path)
        if not quiet:
            typer.echo(f"Incident report written to {out_path}")
    else:
        console = Console()
        console.print(f"[bold]Incident: {report.title}[/bold]")
        console.print(f"Risk Score: {report.risk_assessment.risk_score:.0%}")
        format_mitre_mappings(console, report.mitre_mappings)
        format_incident_timeline(console, report.timeline)
        console.print("\n[bold]Recommendations:[/bold]")
        for i, rec in enumerate(report.recommendations, 1):
            console.print(f"  {i}. {rec}")


@app.command()
def config_cmd(
    action: str = typer.Argument(..., help="Action: set, get, delete, list"),
    service: Optional[str] = typer.Option(None, "--service", "-s", help="Service name (vt, abuseipdb, shodan)"),
    key: Optional[str] = typer.Option(None, "--key", "-k", help="API key value"),
) -> None:
    """Manage API keys and configuration."""
    from arqsoc.config import get_api_key, set_api_key, delete_api_key, list_api_keys

    if action == "set":
        if not service or not key:
            typer.echo("Both --service and --key required for set", err=True)
            raise typer.Exit(1)
        set_api_key(service, key)
        typer.echo(f"API key set for {service}")

    elif action == "get":
        if not service:
            typer.echo("--service required for get", err=True)
            raise typer.Exit(1)
        result = get_api_key(service)
        if result:
            typer.echo(f"API key configured for {service}")
        else:
            typer.echo(f"No API key configured for {service}")

    elif action == "delete":
        if not service:
            typer.echo("--service required for delete", err=True)
            raise typer.Exit(1)
        delete_api_key(service)
        typer.echo(f"API key deleted for {service}")

    elif action == "list":
        keys = list_api_keys()
        if keys:
            for svc, configured in keys.items():
                typer.echo(f"  {svc}: {'configured' if configured else 'not set'}")
        else:
            typer.echo("No API keys configured")

    else:
        typer.echo(f"Unknown action: {action}. Use: set, get, delete, list", err=True)
        raise typer.Exit(1)


@app.command()
def plugin(
    action: str = typer.Argument("list", help="Action: list, run, discover"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Plugin name"),
    target: Optional[Path] = typer.Option(None, "--target", "-t", help="Target file for plugin"),
) -> None:
    """Manage and run analysis plugins."""
    from arqsoc.plugins.loader import list_plugins, run_plugin, discover_plugins

    if action == "list":
        plugins = list_plugins()
        if plugins:
            for p in plugins:
                typer.echo(f"  {p['name']} v{p['version']} - {p['description']}")
        else:
            typer.echo("No plugins loaded. Use 'discover' to find plugins.")

    elif action == "discover":
        discovered = discover_plugins()
        if discovered:
            typer.echo(f"Discovered {len(discovered)} plugin(s): {', '.join(discovered)}")
        else:
            typer.echo("No plugins found in ~/.arqsoc/plugins/")

    elif action == "run":
        if not name or not target:
            typer.echo("Both --name and --target required", err=True)
            raise typer.Exit(1)
        result = run_plugin(name, target)
        if result is not None:
            typer.echo(json.dumps(result, indent=2, default=str))
        else:
            typer.echo(f"Plugin '{name}' not found", err=True)
            raise typer.Exit(1)

    else:
        typer.echo(f"Unknown action: {action}. Use: list, run, discover", err=True)
        raise typer.Exit(1)
