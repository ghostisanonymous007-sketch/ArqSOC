"""Binary diff engine for ArqSOC - compare two binaries side by side."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from arqsoc.core.hashes import calculate_hashes
from arqsoc.core.imports import extract_imports, extract_sections, parse_binary
from arqsoc.models.scan_result import ImportEntry, SectionInfo


@dataclass
class SectionDiff:
    name: str
    in_both: bool
    entropy_delta: float = 0.0
    size_delta: int = 0
    va_delta: int = 0
    was_added: bool = False
    was_removed: bool = False


@dataclass
class ImportDiff:
    dll: str
    function: str
    in_both: bool
    was_added: bool = False
    was_removed: bool = False


@dataclass
class BinaryDiff:
    file_a: str
    file_b: str
    hash_match: bool
    section_diffs: list[SectionDiff] = field(default_factory=list)
    import_diffs: list[ImportDiff] = field(default_factory=list)
    added_imports: list[ImportEntry] = field(default_factory=list)
    removed_imports: list[ImportEntry] = field(default_factory=list)
    shared_imports: list[ImportEntry] = field(default_factory=list)
    added_sections: list[str] = field(default_factory=list)
    removed_sections: list[str] = field(default_factory=list)
    modified_sections: list[str] = field(default_factory=list)
    byte_similarity: float = 0.0


def compare_binaries(file_a: Path, file_b: Path) -> BinaryDiff:
    hashes_a = calculate_hashes(file_a)
    hashes_b = calculate_hashes(file_b)

    hash_match = hashes_a.sha256 == hashes_b.sha256

    binary_a, _ = parse_binary(file_a)
    binary_b, _ = parse_binary(file_b)

    sections_a: list[SectionInfo] = []
    sections_b: list[SectionInfo] = []
    imports_a: list[ImportEntry] = []
    imports_b: list[ImportEntry] = []

    if binary_a is not None:
        sections_a = extract_sections(binary_a)
        imports_a = extract_imports(binary_a)
    if binary_b is not None:
        sections_b = extract_sections(binary_b)
        imports_b = extract_imports(binary_b)

    sec_a_map = {s.name: s for s in sections_a}
    sec_b_map = {s.name: s for s in sections_b}

    section_diffs: list[SectionDiff] = []
    added_sections: list[str] = []
    removed_sections: list[str] = []
    modified_sections: list[str] = []

    all_sec_names = set(sec_a_map.keys()) | set(sec_b_map.keys())
    for name in sorted(all_sec_names):
        in_a = name in sec_a_map
        in_b = name in sec_b_map
        if in_a and in_b:
            sa = sec_a_map[name]
            sb = sec_b_map[name]
            e_delta = abs(sa.entropy - sb.entropy)
            s_delta = sb.raw_size - sa.raw_size
            va_delta = sb.virtual_address - sa.virtual_address
            section_diffs.append(
                SectionDiff(
                    name=name, in_both=True,
                    entropy_delta=round(e_delta, 2),
                    size_delta=s_delta, va_delta=va_delta,
                )
            )
            if e_delta > 0.5 or abs(s_delta) > 256:
                modified_sections.append(name)
        elif in_b:
            added_sections.append(name)
            section_diffs.append(SectionDiff(name=name, in_both=False, was_added=True))
        else:
            removed_sections.append(name)
            section_diffs.append(SectionDiff(name=name, in_both=False, was_removed=True))

    imp_a_set = {(i.dll, i.name) for i in imports_a}
    imp_b_set = {(i.dll, i.name) for i in imports_b}
    imp_a_map = {(i.dll, i.name): i for i in imports_a}
    imp_b_map = {(i.dll, i.name): i for i in imports_b}

    added_imports = [imp_b_map[k] for k in sorted(imp_b_set - imp_a_set)]
    removed_imports = [imp_a_map[k] for k in sorted(imp_a_set - imp_b_set)]
    shared_imports = [imp_a_map[k] for k in sorted(imp_a_set & imp_b_set)]

    import_diffs: list[ImportDiff] = []
    for k in sorted(imp_b_set - imp_a_set):
        import_diffs.append(ImportDiff(dll=k[0], function=k[1], in_both=False, was_added=True))
    for k in sorted(imp_a_set - imp_b_set):
        import_diffs.append(ImportDiff(dll=k[0], function=k[1], in_both=False, was_removed=True))

    data_a = file_a.read_bytes()
    data_b = file_b.read_bytes()
    min_len = min(len(data_a), len(data_b))
    if min_len > 0:
        matching = sum(1 for i in range(min_len) if data_a[i] == data_b[i])
        byte_similarity = matching / max(len(data_a), len(data_b))
    else:
        byte_similarity = 0.0

    return BinaryDiff(
        file_a=str(file_a),
        file_b=str(file_b),
        hash_match=hash_match,
        section_diffs=section_diffs,
        import_diffs=import_diffs,
        added_imports=added_imports,
        removed_imports=removed_imports,
        shared_imports=shared_imports,
        added_sections=added_sections,
        removed_sections=removed_sections,
        modified_sections=modified_sections,
        byte_similarity=round(byte_similarity, 4),
    )
