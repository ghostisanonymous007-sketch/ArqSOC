"""YARA signature matching for ArqSOC."""

from __future__ import annotations

from pathlib import Path

from arqsoc.models.scan_result import YARAMatch

DEFAULT_RULES_DIR = Path(__file__).parent.parent.parent / "rules"


def _try_import_yara() -> object | None:
    try:
        import yara as _yara

        return _yara
    except ImportError:
        return None


def load_rules(rules_dir: Path | None = None) -> object | None:
    _yara = _try_import_yara()
    if _yara is None:
        return None

    if rules_dir is None:
        rules_dir = DEFAULT_RULES_DIR

    if not rules_dir.exists():
        return None

    rule_files = sorted(rules_dir.glob("*.yar")) + sorted(rules_dir.glob("*.yara"))
    if not rule_files:
        return None

    filepaths: dict[str, str] = {}
    for rf in rule_files:
        namespace = rf.stem
        filepaths[namespace] = str(rf)

    try:
        compiled = _yara.compile(filepaths=filepaths)
        return compiled
    except Exception:
        return None


def scan_with_yara(
    file_path: Path,
    rules: object | None = None,
    rules_dir: Path | None = None,
) -> list[YARAMatch]:
    _yara = _try_import_yara()
    if _yara is None:
        return []

    if rules is None:
        rules = load_rules(rules_dir)
        if rules is None:
            return []

    matches: list[YARAMatch] = []
    try:
        yara_matches = rules.match(str(file_path))
        for m in yara_matches:
            matched_strings: list[str] = []
            try:
                for string_match in m.strings:
                    for instance in string_match.instances:
                        matched_strings.append(
                            f"0x{instance.offset:x}: "
                            f"{instance.matched_data.decode('utf-8', errors='replace')}"
                        )
            except Exception:
                pass

            matches.append(
                YARAMatch(
                    rule_name=m.rule,
                    namespace=m.namespace or "",
                    tags=list(m.tags) if m.tags else [],
                    meta=dict(m.meta) if m.meta else {},
                    strings_matched=matched_strings,
                )
            )
    except Exception:
        pass

    return matches
