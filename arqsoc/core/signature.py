"""Digital signature extraction and verification for PE binaries."""

from __future__ import annotations

from pathlib import Path

import lief

from arqsoc.models.scan_result import SignatureInfo


def check_signature(file_path: Path) -> SignatureInfo:
    binary: lief.Binary | None = None
    try:
        binary = lief.parse(str(file_path))
    except Exception:
        return SignatureInfo()

    if binary is None or binary.format != lief.Binary.FORMATS.PE:
        return SignatureInfo()

    try:
        has_sigs = binary.has_signatures
    except Exception:
        return SignatureInfo()

    if not has_sigs:
        return SignatureInfo(is_signed=False)

    signer = ""
    issuer = ""
    serial = ""
    is_valid = False

    try:
        for sig in binary.signatures:
            try:
                for ci in sig.certificates:
                    try:
                        if not signer and hasattr(ci, "subject"):
                            signer = str(ci.subject)
                    except Exception:
                        pass
                    try:
                        if not issuer and hasattr(ci, "issuer"):
                            issuer = str(ci.issuer)
                    except Exception:
                        pass
                    try:
                        if not serial and hasattr(ci, "serial_number"):
                            serial = str(ci.serial_number)
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass

    try:
        vern = binary.verify_signature()
        if vern == lief.PE.VerificationFlags.OK:
            is_valid = True
    except Exception:
        pass

    return SignatureInfo(
        is_signed=True,
        is_valid=is_valid,
        signer=signer,
        issuer=issuer,
        serial=serial,
    )
