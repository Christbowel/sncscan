# encoding: utf-8
# sncscan - scanner of SNC configurations for routers and SAP systems
#
# Copyright (C) 2023  usd AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Orchestration layer and entry point.

``main()`` is the only function that wires all layers together:

    CLI options → target list → scanner → formatter → output

This is deliberately kept thin so that integration tests can call ``run()``
directly with pre-built :class:`~sncscan.models.SNCScanTarget` objects,
bypassing argparse entirely.
"""

from __future__ import annotations

import logging
import sys
from typing import Iterable, Optional, TextIO

from sncscan.cli import CLIOptions, parse_args
from sncscan.models import OutputFormat, Protocol, SNCScanResult, SNCScanTarget
from sncscan.output import ResultFormatter, TerminalColors





def configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure a predictable, duplication-free logging setup.

    INFO and below → ``stdout``.
    WARNING and above → ``stderr`` with a level prefix.

    Args:
        verbose: Enable DEBUG-level output.
        quiet:   Suppress everything below WARNING.
    """
    level = logging.INFO
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG

    logger = logging.getLogger()
    logger.setLevel(level)
    logger.handlers.clear()  # avoid duplicate handlers on repeated calls

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_handler.addFilter(lambda r: r.levelno <= logging.INFO)
    stdout_handler.setFormatter(logging.Formatter("%(message)s"))

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    logger.addHandler(stdout_handler)
    logger.addHandler(stderr_handler)




def _is_multi_hop_route(entry: str) -> bool:
    """Return ``True`` when *entry* contains two or more ``/H/`` segments."""
    return entry.count("/H/") >= 2


def parse_target_list(raw: str) -> list[SNCScanTarget]:
    """Parse a comma-separated list of route strings into scan targets.

    Each entry is either:
    - a multi-hop route string (``/H/host1/S/port1/H/host2/S/port2``) → kept as-is
    - a single-hop route string (``/H/host/S/port``) → split into host + port

    Malformed entries are logged as warnings and skipped.

    Args:
        raw: Comma-separated route strings (may contain trailing commas or
             whitespace around entries).

    Returns:
        List of valid :class:`SNCScanTarget` objects.
    """
    targets: list[SNCScanTarget] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            if _is_multi_hop_route(entry):
                targets.append(SNCScanTarget.from_route_string(entry, Protocol.DIAG))
            else:
                parts = entry.split("/")
                # Expected: ['', 'H', '<host>', 'S', '<port>']
                host = parts[2]
                port = int(parts[4])
                targets.append(SNCScanTarget.from_host_port(host, port, Protocol.DIAG))
        except (IndexError, ValueError) as exc:
            logging.warning("Could not parse target %r: %s", entry, exc)
    return targets




def run(
    targets: Iterable[SNCScanTarget],
    fmt: OutputFormat,
    formatter: ResultFormatter,
    separator: bool = False,
) -> None:
    """Scan all *targets* and emit formatted results via *formatter*.

    Args:
        targets:   Iterable of :class:`SNCScanTarget` objects to probe.
        fmt:       Desired :class:`OutputFormat`.
        formatter: Configured :class:`ResultFormatter` instance.
        separator: When ``True`` print a 70-char dash line before each result
                   (used in ``pretty`` mode for readability).
    """
    for target in targets:
        if separator:
            formatter.stream.write(70 * "-" + "\n")
        from sncscan.scanner import SNCSecurityScan
        result = SNCSecurityScan(target).scan()
        formatter.render(result, fmt)




def main(argv: Optional[list[str]] = None) -> None:
    """Parse CLI arguments, set up all dependencies, and run the scan(s)."""
    options: CLIOptions = parse_args(argv)

    configure_logging(verbose=options.verbose, quiet=options.quiet)

    # Colors are disabled when output goes to a file (no ANSI in text files).
    use_color = options.color and not options.file_output
    colors    = TerminalColors(enabled=use_color)

    if not options.quiet:
        _print_ascii_art(colors)

    # --- Build target list ---------------------------------------------------
    if options.listfile or options.list_targets:
        if options.listfile:
            with open(options.listfile, "r", encoding="utf-8") as fh:
                raw = fh.read().replace("\n", ",").rstrip(",")
        else:
            raw = options.list_targets  # type: ignore[assignment]
        targets = parse_target_list(raw)
    else:
        protocol = options.protocol or Protocol.DIAG
        targets  = [
            SNCScanTarget(
                host=options.host,
                port=options.port,
                route_string=options.route_string,
                protocol=protocol,
            )
        ]

    # --- Output destination --------------------------------------------------
    if options.file_output:
        with open(options.file_output, "w", encoding="utf-8") as out_file:
            formatter = ResultFormatter(colors=colors, stream=out_file)
            run(
                targets,
                fmt=options.format,
                formatter=formatter,
                separator=(options.format == OutputFormat.PRETTY),
            )
    else:
        formatter = ResultFormatter(colors=colors, stream=sys.stdout)
        run(
            targets,
            fmt=options.format,
            formatter=formatter,
            separator=(options.format == OutputFormat.PRETTY),
        )


def _print_ascii_art(colors: TerminalColors) -> None:
    print(
        colors.CYAN
        + " ___ _ __   ___ ___  ___ __ _ _ __\n"
        + "/ __| '_ \\ / __/ __|/ __/ _` | '_ \\ \n"
        + "\\__ \\ | | | (__ \\__ \\ (_| (_| | | | |\n"
        + "|___/_| |_|\\___|___/\\___\\__,_|_| |_|\n"
        + colors.END
    )


if __name__ == "__main__":
    main()