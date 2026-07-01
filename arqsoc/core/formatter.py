"""Rich terminal output formatting for ArqSOC."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from arqsoc.core.entropy import entropy_to_bar, entropy_to_color
from arqsoc.models.scan_result import (
    ClassifiedString,
    HashResult,
    IATEntry,
    ImportEntry,
    OverlayInfo,
    PackerResult,
    RichHeaderInfo,
    ScanResult,
    SectionInfo,
    SignatureInfo,
    StringClassification,
    ThreatIndicator,
    ThreatLevel,
    ThreatTimelineEntry,
    TLSInfo,
    YARAMatch,
)
from arqsoc.models.ioc import IOC, RiskLevel
from arqsoc.models.log_event import LogEvent
from arqsoc.models.alert import Alert
from arqsoc.models.batch import TriageResult
from arqsoc.models.incident import MitreMapping, TimelineEntry, IncidentReport

THREAT_COLOR = {
    ThreatLevel.BENIGN: "green",
    ThreatLevel.SUSPICIOUS: "yellow",
    ThreatLevel.MALICIOUS: "bold red",
    ThreatLevel.UNKNOWN: "dim",
}

CLASSIFICATION_COLOR = {
    StringClassification.URL: "cyan",
    StringClassification.IP: "magenta",
    StringClassification.EMAIL: "yellow",
    StringClassification.REGISTRY: "red",
    StringClassification.FILE_PATH: "blue",
    StringClassification.API: "green",
    StringClassification.CRYPTO: "bold yellow",
    StringClassification.BASE64: "dim cyan",
    StringClassification.MUTEX: "magenta",
    StringClassification.C2: "bold red",
    StringClassification.KEY: "bold magenta",
    StringClassification.OTHER: "white",
}

RISK_COLOR = {
    RiskLevel.INFO: "dim",
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
    RiskLevel.CRITICAL: "bold red",
}


def format_file_info(console: Console, result: ScanResult) -> None:
    table = Table(title="File Info", show_header=False, border_style="dim")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")

    fi = result.file_info
    table.add_row("Name", fi.name)
    table.add_row("Path", fi.path)
    table.add_row("Size", _format_size(fi.size))
    table.add_row("Type", fi.binary_type.value.upper())
    table.add_row("Architecture", fi.architecture.value.upper())
    if fi.compiler:
        table.add_row("Compiler", fi.compiler)
    if fi.compile_time:
        table.add_row("Compile Time", fi.compile_time)
    if fi.subsystem:
        table.add_row("Subsystem", fi.subsystem)
    if fi.is_dotnet:
        table.add_row(".NET", "Yes", style="yellow")

    console.print(table)
    console.print()


def format_hashes(console: Console, hashes: HashResult) -> None:
    table = Table(title="Hashes", show_header=False, border_style="dim")
    table.add_column("Algorithm", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("MD5", hashes.md5)
    table.add_row("SHA1", hashes.sha1)
    table.add_row("SHA256", hashes.sha256)
    if hashes.ssdeep:
        table.add_row("SSDeep", hashes.ssdeep)
    if hashes.imphash:
        table.add_row("ImpHash", hashes.imphash)

    console.print(table)
    console.print()


def format_sections(console: Console, sections: list[SectionInfo]) -> None:
    table = Table(title="Sections (Entropy Heatmap)", border_style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Entropy", justify="right")
    table.add_column("Heatmap", justify="left")
    table.add_column("Flags", justify="center")
    table.add_column("Status", justify="center")

    for sec in sections:
        color = entropy_to_color(sec.entropy)
        bar = entropy_to_bar(sec.entropy)

        flags = ""
        if sec.is_readable:
            flags += "R"
        if sec.is_writable:
            flags += "W"
        if sec.is_executable:
            flags += "X"

        status = ""
        status_style = "green"
        if sec.is_suspicious:
            status = "!! HIGH"
            status_style = "bold red"
        elif sec.anomaly_reason:
            status = sec.anomaly_reason
            status_style = "yellow"

        table.add_row(
            sec.name,
            f"[{color}]{sec.entropy:.2f}[/{color}]",
            f"[{color}]{bar}[/{color}]",
            flags,
            f"[{status_style}]{status}[/{status_style}]" if status else "-",
        )

    console.print(table)
    console.print()


def format_imports(console: Console, imports: list[ImportEntry], limit: int = 50) -> None:
    dll_imports: dict[str, list[ImportEntry]] = {}
    for imp in imports:
        dll = imp.dll or "unknown"
        dll_imports.setdefault(dll, []).append(imp)

    table = Table(
        title=f"Imports ({len(imports)} functions, {len(dll_imports)} DLLs)",
        border_style="dim",
    )
    table.add_column("DLL", style="bold cyan")
    table.add_column("Function", style="white")
    table.add_column("Count", justify="right", style="dim")

    shown = 0
    for dll, funcs in sorted(dll_imports.items()):
        if shown >= limit:
            table.add_row("...", f"({len(imports) - shown} more)", "")
            break
        func_names = ", ".join(f.name for f in funcs[:10])
        if len(funcs) > 10:
            func_names += f" (+{len(funcs) - 10} more)"
        table.add_row(dll, func_names, str(len(funcs)))
        shown += len(funcs)

    console.print(table)
    console.print()


def format_strings(console: Console, strings: list[ClassifiedString], limit: int = 50) -> None:
    by_class: dict[StringClassification, list[ClassifiedString]] = {}
    for s in strings:
        by_class.setdefault(s.classification, []).append(s)

    table = Table(
        title=f"Strings ({len(strings)} found, {len(by_class)} categories)",
        border_style="dim",
    )
    table.add_column("Type", style="bold")
    table.add_column("Count", justify="right", style="cyan")
    table.add_column("Sample", style="white")

    for cls in StringClassification:
        if cls not in by_class:
            continue
        items = by_class[cls]
        sample = items[0].value[:60] + ("..." if len(items[0].value) > 60 else "")
        color = CLASSIFICATION_COLOR.get(cls, "white")
        table.add_row(f"[{color}]{cls.value}[/{color}]", str(len(items)), sample)

    console.print(table)
    console.print()

    detailed = Table(title="Notable Strings", border_style="dim", show_lines=True)
    detailed.add_column("Offset", style="dim", justify="right")
    detailed.add_column("Type", style="bold")
    detailed.add_column("Value", style="white")

    notable: list[ClassifiedString] = []
    for cls in (
        StringClassification.URL, StringClassification.IP,
        StringClassification.C2, StringClassification.REGISTRY,
        StringClassification.CRYPTO, StringClassification.MUTEX,
        StringClassification.BASE64,
    ):
        notable.extend(by_class.get(cls, []))

    for s in notable[:limit]:
        cls_color = CLASSIFICATION_COLOR.get(s.classification, "white")
        value = s.value[:80] + ("..." if len(s.value) > 80 else "")
        if s.is_obfuscated and s.decoded_value:
            value += f"\n  [dim]-> decoded: {s.decoded_value[:60]}[/dim]"
        detailed.add_row(
            f"0x{s.offset:x}",
            f"[{cls_color}]{s.classification.value}[/{cls_color}]",
            value,
        )

    if notable:
        console.print(detailed)
        console.print()


def format_packer(console: Console, packer: PackerResult) -> None:
    if packer.is_packed:
        color = "bold red" if packer.confidence >= 0.7 else "yellow"
        console.print(Panel(
            f"[{color}]PACKED: {packer.packer_name} "
            f"(confidence: {packer.confidence:.0%})[/{color}]\n"
            + "\n".join(f"  - {i}" for i in packer.indicators),
            title="Packer Detection",
            border_style=color,
        ))
    elif packer.indicators:
        console.print(Panel(
            "\n".join(f"  - {i}" for i in packer.indicators),
            title="Packer Detection",
            subtitle="No packer identified",
            border_style="dim",
        ))
    console.print()


def format_yara(console: Console, matches: list[YARAMatch]) -> None:
    if not matches:
        console.print("[dim]No YARA matches found.[/dim]\n")
        return

    table = Table(title=f"YARA Matches ({len(matches)})", border_style="dim")
    table.add_column("Rule", style="bold yellow")
    table.add_column("Severity", style="bold")
    table.add_column("Tags", style="cyan")
    table.add_column("Strings", style="dim")

    for m in matches:
        severity = m.meta.get("severity", "unknown")
        sev_map = {
            "high": "red", "medium": "yellow",
            "suspicious": "yellow", "low": "green",
        }
        sev_color = sev_map.get(severity, "white")
        tags = ", ".join(m.tags) if m.tags else "-"
        strings = "\n".join(m.strings_matched[:3])
        table.add_row(m.rule_name, f"[{sev_color}]{severity}[/{sev_color}]", tags, strings)

    console.print(table)
    console.print()


def format_indicators(console: Console, indicators: list[ThreatIndicator]) -> None:
    if not indicators:
        return

    table = Table(title="Threat Indicators", border_style="red")
    table.add_column("Type", style="bold")
    table.add_column("Value", style="white")
    table.add_column("Confidence", justify="right")
    table.add_column("Source", style="dim")

    for ind in indicators:
        conf_color = (
            "red" if ind.confidence >= 0.8
            else "yellow" if ind.confidence >= 0.5
            else "green"
        )
        table.add_row(
            ind.type,
            ind.value[:80],
            f"[{conf_color}]{ind.confidence:.0%}[/{conf_color}]",
            ind.source,
        )

    console.print(table)
    console.print()


def format_timeline(console: Console, timeline: list[ThreatTimelineEntry]) -> None:
    if not timeline:
        return

    tree = Tree(">> Reconstructed Attack Chain")
    for entry in timeline:
        conf_color = (
            "red" if entry.confidence >= 0.8
            else "yellow" if entry.confidence >= 0.5
            else "green"
        )
        label = (
            f"[bold]Step {entry.step}:[/bold] {entry.description} "
            f"[{conf_color}]({entry.confidence:.0%})[/{conf_color}]"
        )
        branch = tree.add(label)
        for ind in entry.indicators:
            branch.add(f"[dim]{ind}[/dim]")

    console.print(tree)
    console.print()


def format_verdict(console: Console, result: ScanResult) -> None:
    color = THREAT_COLOR.get(result.threat_level, "white")
    fill = int(result.overall_confidence * 10)
    confidence_bar = "=" * fill + "-" * (10 - fill)

    verdict_text = Text()
    verdict_text.append("Classification: ", style="bold")
    verdict_text.append(f"{result.threat_level.value.upper()}\n", style=color)
    verdict_text.append("Confidence:    ", style="bold")
    verdict_text.append(f"{result.overall_confidence:.0%} {confidence_bar}\n", style=color)

    console.print(Panel(
        verdict_text,
        title="Verdict",
        border_style=color,
        padding=(1, 2),
    ))
    console.print()


def format_rich_header(console: Console, rich: RichHeaderInfo) -> None:
    if not rich.is_present:
        return

    table = Table(title="Rich Header (Compiler Fingerprint)", border_style="dim")
    table.add_column("Component", style="bold cyan")
    table.add_column("Build", justify="right", style="white")
    table.add_column("Count", justify="right", style="yellow")

    for entry in rich.entries[:20]:
        table.add_row(entry.name, str(entry.build_id), str(entry.count))

    if len(rich.entries) > 20:
        table.add_row("...", f"({len(rich.entries) - 20} more)", "")

    console.print(table)
    if rich.decoded_signature:
        console.print(f"  [dim]Signature: {rich.decoded_signature[:120]}[/dim]")
    console.print(f"  [dim]XOR Key: 0x{rich.XOR_key:08X}[/dim]")
    console.print()


def format_overlay(console: Console, overlay: OverlayInfo) -> None:
    if not overlay.has_overlay:
        return

    color = "yellow" if overlay.entropy > 7.5 else "dim"
    console.print(Panel(
        f"Offset: 0x{overlay.offset:x} | Size: {_format_size(overlay.size)} | "
        f"Entropy: [{color}]{overlay.entropy:.2f}[/{color}]"
        + (f"\nMagic: {overlay.magic}" if overlay.magic else "\nMagic: Unknown"),
        title="Overlay (Appended Data)",
        border_style="yellow" if overlay.entropy > 7.5 else "dim",
    ))
    console.print()


def format_tls(console: Console, tls_info: TLSInfo) -> None:
    if not tls_info.has_tls:
        return

    if not tls_info.callbacks:
        console.print("[dim]TLS directory present but no callbacks found.[/dim]\n")
        return

    table = Table(
        title=f"TLS Callbacks ({len(tls_info.callbacks)})",
        border_style="yellow",
    )
    table.add_column("Callback Address", style="bold red")
    for cb in tls_info.callbacks[:10]:
        table.add_row(cb.callback_hex or f"0x{cb.address:08x}")
    console.print(table)
    console.print()


def format_signature(console: Console, sig: SignatureInfo) -> None:
    if not sig.is_signed:
        console.print("[dim]Not signed[/dim]\n")
        return

    color = "green" if sig.is_valid else "bold red"
    status = "VALID" if sig.is_valid else "INVALID"
    console.print(Panel(
        f"[{color}]Signature: {status}[/{color}]\n"
        + (f"Signer: {sig.signer}\n" if sig.signer else "")
        + (f"Issuer: {sig.issuer}\n" if sig.issuer else "")
        + (f"Serial: {sig.serial}" if sig.serial else ""),
        title="Digital Signature",
        border_style=color,
    ))
    console.print()


def format_dynamic_imports(console: Console, dyn_imports: list[IATEntry]) -> None:
    if not dyn_imports:
        return

    table = Table(
        title=f"Dynamic API Resolution ({len(dyn_imports)} detected)",
        border_style="dim",
    )
    table.add_column("API", style="bold")
    table.add_column("DLL", style="cyan")
    table.add_column("Confidence", justify="right")
    table.add_column("Source", style="dim")

    for imp in dyn_imports[:30]:
        conf_color = (
            "red" if imp.confidence >= 0.7
            else "yellow" if imp.confidence >= 0.5
            else "dim"
        )
        table.add_row(
            imp.api_name,
            imp.dll_name or "-",
            f"[{conf_color}]{imp.confidence:.0%}[/{conf_color}]",
            imp.source,
        )

    if len(dyn_imports) > 30:
        table.add_row("...", f"({len(dyn_imports) - 30} more)", "", "")

    console.print(table)
    console.print()


def format_iocs(console: Console, iocs: list[IOC]) -> None:
    if not iocs:
        console.print("[dim]No IOCs extracted.[/dim]\n")
        return

    table = Table(title=f"IOCs Extracted ({len(iocs)})", border_style="dim")
    table.add_column("Type", style="bold cyan")
    table.add_column("Value", style="white")
    table.add_column("Risk", justify="center")
    table.add_column("Context", style="dim")

    for ioc in iocs[:50]:
        color = RISK_COLOR.get(ioc.risk_level, "white")
        table.add_row(
            ioc.ioc_type.value,
            ioc.value[:60],
            f"[{color}]{ioc.risk_level.value}[/{color}]",
            ioc.context[:40],
        )

    if len(iocs) > 50:
        table.add_row("...", f"({len(iocs) - 50} more)", "", "")

    console.print(table)
    console.print()


def format_log_events(console: Console, events: list[LogEvent], limit: int = 30) -> None:
    if not events:
        console.print("[dim]No log events parsed.[/dim]\n")
        return

    table = Table(title=f"Log Events ({len(events)})", border_style="dim")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Type", style="bold")
    table.add_column("Source", style="dim")
    table.add_column("Message", style="white")

    for event in events[:limit]:
        sev_color = {
            "critical": "bold red", "high": "red",
            "medium": "yellow", "low": "green", "info": "dim",
            "debug": "dim",
        }.get(event.severity.value, "white")
        table.add_row(
            event.timestamp[:19] if event.timestamp else "-",
            f"[{sev_color}]{event.severity.value}[/{sev_color}]",
            event.normalized_type,
            event.source[:20],
            event.raw_line[:60],
        )

    if len(events) > limit:
        table.add_row("...", f"({len(events) - limit} more)", "", "", "")

    console.print(table)
    console.print()


def format_alerts(console: Console, alerts: list[Alert]) -> None:
    if not alerts:
        console.print("[dim]No correlated alerts.[/dim]\n")
        return

    table = Table(title=f"Correlated Alerts ({len(alerts)})", border_style="red")
    table.add_column("Severity", justify="center", style="bold")
    table.add_column("Confidence", justify="right")
    table.add_column("Title", style="white")
    table.add_column("IOCs", style="cyan")

    for alert in alerts:
        sev_color = {
            "critical": "bold red", "high": "red",
            "medium": "yellow", "low": "green", "info": "dim",
        }.get(alert.severity.value, "white")
        ioc_values = ", ".join(i.value for i in alert.related_iocs[:3])
        table.add_row(
            f"[{sev_color}]{alert.severity.value}[/{sev_color}]",
            f"{alert.confidence:.0%}",
            alert.title[:60],
            ioc_values[:40],
        )

    console.print(table)
    console.print()


def format_triage_results(console: Console, results: list[TriageResult]) -> None:
    if not results:
        console.print("[dim]No files triaged.[/dim]\n")
        return

    table = Table(title=f"Triage Results ({len(results)} files)", border_style="dim")
    table.add_column("Priority", justify="center", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("File", style="cyan")
    table.add_column("VT", style="white")
    table.add_column("Summary", style="dim")

    for r in results[:50]:
        pri_color = {
            "critical": "bold red", "high": "red",
            "medium": "yellow", "low": "green", "normal": "dim",
        }.get(r.priority, "white")
        table.add_row(
            f"[{pri_color}]{r.priority}[/{pri_color}]",
            f"{r.risk_score:.0%}",
            r.file_path.split("\\")[-1].split("/")[-1][:30],
            r.vt_detections or "-",
            r.summary[:40],
        )

    console.print(table)
    console.print()


def format_mitre_mappings(console: Console, mappings: list[MitreMapping]) -> None:
    if not mappings:
        console.print("[dim]No MITRE ATT&CK mappings.[/dim]\n")
        return

    table = Table(title=f"MITRE ATT&CK ({len(mappings)} techniques)", border_style="dim")
    table.add_column("ID", style="bold yellow")
    table.add_column("Tactic", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Evidence", style="dim")

    for m in mappings[:20]:
        table.add_row(m.technique_id, m.tactic[:25], m.name[:35], m.evidence[:40])

    console.print(table)
    console.print()


def format_incident_timeline(console: Console, entries: list[TimelineEntry]) -> None:
    if not entries:
        return

    tree = Tree(">> Incident Timeline")
    for entry in entries[:30]:
        sev_color = {
            "critical": "bold red", "high": "red",
            "medium": "yellow", "low": "green", "info": "dim",
        }.get(entry.severity, "white")
        label = f"[{sev_color}][{entry.severity.upper()}][/{sev_color}] {entry.description}"
        tree.add(label)

    console.print(tree)
    console.print()


def format_scan_result(console: Console, result: ScanResult, verbose: bool = False) -> None:
    console.print(Panel.fit(
        f"[bold]ArqSOC v1.0[/bold] -- scan [cyan]{result.file_info.name}[/cyan]",
        border_style="bright_blue",
    ))
    console.print()

    format_file_info(console, result)
    format_hashes(console, result.hashes)
    format_sections(console, result.sections)

    if verbose:
        format_imports(console, result.imports)
        format_strings(console, result.strings)
    else:
        if result.imports:
            console.print(
                f"[dim]  {len(result.imports)} imports found. "
                f"Use --verbose to show.[/dim]\n"
            )
        if result.strings:
            console.print(
                f"[dim]  {len(result.strings)} strings found. "
                f"Use --verbose to show.[/dim]\n"
            )

    format_packer(console, result.packer)
    format_yara(console, result.yara_matches)

    format_rich_header(console, result.rich_header)
    format_overlay(console, result.overlay)
    format_tls(console, result.tls)
    format_signature(console, result.signature)

    if result.dynamic_imports:
        format_dynamic_imports(console, result.dynamic_imports)

    if result.threat_indicators:
        format_indicators(console, result.threat_indicators)

    if result.threat_timeline:
        format_timeline(console, result.threat_timeline)

    format_verdict(console, result)

    if result.errors:
        console.print("[dim]Errors:[/dim]")
        for err in result.errors:
            console.print(f"[dim]  - {err}[/dim]")


def _format_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
