"""TLS callback detection for PE binaries."""

from __future__ import annotations

from pathlib import Path

import lief

from arqsoc.models.scan_result import TLSCallback, TLSInfo


def detect_tls(file_path: Path) -> TLSInfo:
    binary: lief.Binary | None = None
    try:
        binary = lief.parse(str(file_path))
    except Exception:
        return TLSInfo()

    if binary is None or binary.format != lief.Binary.FORMATS.PE:
        return TLSInfo()

    try:
        has_tls_dir = binary.has_tls
    except Exception:
        return TLSInfo()

    if not has_tls_dir:
        return TLSInfo(has_tls=False)

    tls_dir = binary.tls
    data_address = 0
    try:
        data_address = tls_dir.addressof_data
    except Exception:
        pass

    callbacks: list[TLSCallback] = []
    try:
        for cb in tls_dir.callbacks:
            addr = 0
            try:
                addr = cb
            except Exception:
                continue
            callbacks.append(
                TLSCallback(
                    address=addr,
                    callback_hex=f"0x{addr:08x}" if addr else "",
                )
            )
    except Exception:
        pass

    if not callbacks:
        try:
            cb_list = tls_dir.callback_index
            if cb_list is not None:
                callbacks.append(
                    TLSCallback(
                        address=int(cb_list),
                        callback_hex=f"0x{int(cb_list):08x}",
                    )
                )
        except Exception:
            pass

    return TLSInfo(
        has_tls=True,
        callbacks=callbacks,
        data_address=data_address,
    )
