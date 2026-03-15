# encoding: utf-8
# sncscan - scanner of SNC configurations for routers and SAP systems
#
# Copyright (C) 2023  usd AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Presentation layer — colours and result formatting.

Intentionally decoupled from the scanner so it can be tested without any
network or pysap dependency.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from pysap.SAPSNC import snc_qop  # noqa: only pysap import in this module

from sncscan.constants import QOP_FLAG_MAX
from sncscan.models import OutputFormat, Protocol, SNCScanResult




class TerminalColors:
    """ANSI escape codes for terminal output.

    When *enabled* is ``False`` every attribute is an empty string so that the
    same f-string templates work in both colour and plain-text modes without
    branching in the formatting code.
    """

    def __init__(self, enabled: bool = True) -> None:
        if enabled:
            self.BLUE   = "\033[94m"
            self.CYAN   = "\033[96m"
            self.GREEN  = "\033[92m"
            self.ORANGE = "\x1b[38;2;240;127;29m"
            self.RED    = "\033[91m"
            self.END    = "\033[0m"
        else:
            self.BLUE = self.CYAN = self.GREEN = self.ORANGE = self.RED = self.END = ""



class ResultFormatter:
    """Renders a :class:`~sncscan.models.SNCScanResult` in any supported format.

    Args:
        colors: :class:`TerminalColors` instance controlling ANSI output.
        stream: Output stream (defaults to ``sys.stdout``).
    """

    def __init__(
        self,
        colors: TerminalColors,
        stream: TextIO = sys.stdout,
    ) -> None:
        self.colors = colors
        self.stream = stream



    def render(self, result: SNCScanResult, fmt: OutputFormat) -> None:
        """Print *result* to the configured stream using *fmt*."""
        if not result.done:
            self._write(f"Target:{result.target} - scan unsuccessful.\n")
            return

        dispatch = {
            OutputFormat.PRETTY:          self._format_pretty,
            OutputFormat.PLAIN:           self._format_plain,
            OutputFormat.JSON:            self._format_json,
            OutputFormat.ONLY_VIOLATIONS: self._format_only_violations,
        }
        self._write(dispatch[fmt](result) + "\n")


    def _write(self, text: str) -> None:
        self.stream.write(text)

    def _qop_line(self, param: str, value: int) -> str:
        c = self.colors.GREEN if value == 3 else self.colors.RED
        return f"\tsnc/data_protection/{param}\t{c}{value} ({snc_qop.get(value)}){self.colors.END}"

    def _format_pretty(self, result: SNCScanResult) -> str:
        c = self.colors
        lines = [f"Target: {result.target}"]

        if not result.enabled:
            lines.append(
                f"SNC enabled system (snc/enabled): "
                f"{c.RED}{int(result.enabled)} (no){c.END}"
            )
            return "\n".join(lines)

        lines.append(
            f"SNC enabled system (snc/enabled): {c.GREEN}{int(result.enabled)} (yes){c.END}"
        )
        lines.append(f"MechID: {result.mechid}")
        lines.append(f"Used Cryptolib: {result.cryptolib}")

        flag_color = c.GREEN if result.qop_flag == QOP_FLAG_MAX else c.RED
        lines.append(f"Flag: {flag_color}{hex(result.qop_flag)}{c.END}")
        lines.append("Quality of Protection")
        for param, value in (
            ("use", result.qop_use),
            ("max", result.qop_max),
            ("min", result.qop_min),
        ):
            lines.append(self._qop_line(param, value))

        if result.target.protocol == Protocol.DIAG:
            allowed = "not " if result.enforced else ""
            enc_color = c.GREEN if result.enforced else c.RED
            val = "1" if result.enforced else "0"
            lines.append(f"\nUnencrypted communication is {allowed}allowed by this system:")
            lines.append(
                f"snc/only_encrypted_gui\t{enc_color}{val} ({result.enforced}){c.END}"
            )

        return "\n".join(lines)

    def _format_only_violations(self, result: SNCScanResult) -> str:
        c = self.colors
        lines = [f"Target: {result.target}"]

        if not result.enabled:
            lines.append(
                f"SNC enabled system (snc/enabled): "
                f"{c.RED}{int(result.enabled)} (no){c.END}"
            )
            return "\n".join(lines)

        if result.qop_flag != QOP_FLAG_MAX:
            lines.append(f"Flag: {c.RED}{hex(result.qop_flag)}{c.END}")

        lines.append("Quality of Protection")
        for param, value in (
            ("use", result.qop_use),
            ("max", result.qop_max),
            ("min", result.qop_min),
        ):
            if value != 3:
                lines.append(self._qop_line(param, value))

        if result.target.protocol == Protocol.DIAG and not result.enforced:
            lines.append("\nUnencrypted communication is allowed by this system:")
            lines.append(f"snc/only_encrypted_gui\t{c.RED}0 (False){c.END}")

        return "\n".join(lines)

    def _format_plain(self, result: SNCScanResult) -> str:
        base = (
            f"Target:{result.target} QoP:{hex(result.qop_flag)} "
            f"Enabled:{result.enabled} MechID:{result.mechid} "
            f"CryptoLib:{result.cryptolib} Done:{result.done}"
        )
        if result.target.protocol == Protocol.DIAG:
            return (
                f"Target:{result.target} QoP:{hex(result.qop_flag)} "
                f"Enabled:{result.enabled} Enforced:{result.enforced} "
                f"MechID:{result.mechid} CryptoLib:{result.cryptolib} Done:{result.done}"
            )
        return base

    def _format_json(self, result: SNCScanResult) -> str:
        data: dict = {
            "target":    str(result.target),
            "qop_use":   result.qop_use,
            "qop_max":   result.qop_max,
            "qop_min":   result.qop_min,
            "enabled":   result.enabled,
            "mechid":    result.mechid,
            "cryptolib": result.cryptolib,
            "done":      result.done,
        }
        if result.target.protocol == Protocol.DIAG:
            data["enforced"] = result.enforced
        return json.dumps(data)