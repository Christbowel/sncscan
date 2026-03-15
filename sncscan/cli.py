# encoding: utf-8
# sncscan - scanner of SNC configurations for routers and SAP systems
#
# Copyright (C) 2023  usd AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Command-line interface — argument parsing only.

This module is responsible for a single task: turn ``sys.argv`` into a typed
:class:`CLIOptions` dataclass.  All orchestration logic lives in
:mod:`sncscan.main` so that ``CLIOptions`` can be constructed directly in
tests without going through argparse.
"""

from __future__ import annotations

import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from dataclasses import dataclass
from typing import Optional

from sncscan.models import OutputFormat, Protocol




@dataclass
class CLIOptions:
    """Strongly-typed container for parsed command-line options.

    Using a dataclass instead of argparse's ``Namespace`` gives us:
    - explicit type annotations
    - ``__repr__`` for free (useful in debug logs)
    - easy construction in unit tests without argparse
    """

    host:         Optional[str]
    port:         int
    route_string: Optional[str]
    list_targets: Optional[str]
    listfile:     Optional[str]
    protocol:     Optional[Protocol]
    format:       OutputFormat
    verbose:      bool
    quiet:        bool
    color:        bool
    file_output:  Optional[str]




def parse_args(argv: Optional[list[str]] = None) -> CLIOptions:
    """Parse *argv* (defaults to ``sys.argv[1:]``) and return a :class:`CLIOptions`.

    Exits with ``sys.exit(0)`` and prints help when no target is provided.
    """
    parser = _build_parser()
    ns = parser.parse_args(argv)

    if not (ns.host or ns.route_string or ns.list or ns.listfile):
        parser.print_help()
        sys.exit(0)

    # Validate and coerce protocol / format to their enum equivalents
    protocol: Optional[Protocol] = None
    if ns.protocol is not None:
        try:
            protocol = Protocol(ns.protocol)
        except ValueError:
            parser.error(
                f"Invalid protocol {ns.protocol!r}. "
                f"Valid choices: {[p.value for p in Protocol]}"
            )

    try:
        fmt = OutputFormat(ns.format)
    except ValueError:
        parser.error(
            f"Invalid format {ns.format!r}. "
            f"Valid choices: {[f.value for f in OutputFormat]}"
        )

    return CLIOptions(
        host=ns.host,
        port=ns.port,
        route_string=ns.route_string,
        list_targets=ns.list,
        listfile=ns.listfile,
        protocol=protocol,
        format=fmt,
        verbose=ns.verbose,
        quiet=ns.quiet,
        color=ns.color,
        file_output=ns.file_output,
    )




def _build_parser() -> ArgumentParser:
    # Placeholder colours for the description string only.
    # Real colour output is handled by output.TerminalColors after parsing.
    _cyan  = "\033[96m"
    _end   = "\033[0m"
    _orange = "\x1b[38;2;240;127;29m"

    ascii_art = (
        _cyan
        + " ___ _ __   ___ ___  ___ __ _ _ __\n"
        + "/ __| '_ \\ / __/ __|/ __/ _` | '_ \\ \n"
        + "\\__ \\ | | | (__ \\__ \\ (_| (_| | | | |\n"
        + "|___/_| |_|\\___|___/\\___\\__,_|_| |_|\n"
        + _end
    )

    description = (
        f"{ascii_art}\n"
        f"SAP Secure Network Communication analysis tool developed by usd AG "
        f"{_orange}\u25e5{_end}\n"
        f"Based on the pysap library by Martin Gallo."
    )

    usage = (
        "%(prog)s -H <remote host> [-S <port>] -p <diag|router> "
        "[-o <file>] [-v] [-q] [--no-color] [-f <format>]"
        "\n\t%(prog)s --route-string </H/S/H/S/> -p <diag|router> "
        "[-o <file>] [-v] [-q] [--no-color] [-f <format>]"
        "\n\t%(prog)s -L <list>|-iL <file> "
        "[-o <file>] [-v] [-q] [--no-color] [-f <format>]"
    )

    parser = ArgumentParser(
        usage=usage,
        description=description,
        formatter_class=RawTextHelpFormatter,
    )

    # --- Target group ---------------------------------------------------------
    tgt = parser.add_argument_group("Target")
    tgt.add_argument("-H", "--host", dest="host", metavar="HOST", help="Target hostname or IP")
    tgt.add_argument(
        "-S", "--port",
        dest="port",
        type=int,
        default=3299,
        metavar="PORT",
        help="TCP port (default: %(default)s)",
    )
    tgt.add_argument(
        "--route-string",
        dest="route_string",
        metavar="ROUTE",
        help="SAP route string, e.g. /H/10.0.0.1/S/3299/H/10.0.0.2/S/3200",
    )
    tgt.add_argument(
        "-L", "--list",
        dest="list",
        metavar="LIST",
        help="Comma-separated DIAG targets in route-string format",
    )
    tgt.add_argument(
        "-iL", "--listfile",
        dest="listfile",
        metavar="FILE",
        help="File containing DIAG targets (one per line or comma-separated)",
    )
    tgt.add_argument(
        "-p", "--protocol",
        dest="protocol",
        metavar="PROTO",
        help=f"Protocol to use: {' | '.join(p.value for p in Protocol)}",
    )

    # --- Misc options ---------------------------------------------------------
    misc = parser.add_argument_group("Misc options")
    misc.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        help="Enable verbose (DEBUG) output",
    )
    misc.add_argument(
        "-o", "--output",
        dest="file_output",
        metavar="FILE",
        help="Write output to FILE instead of stdout",
    )
    misc.add_argument(
        "-f", "--format",
        dest="format",
        default=OutputFormat.PRETTY.value,
        metavar="FORMAT",
        help=(
            f"Output format (default: %(default)s).\n"
            f"Choices: {' | '.join(f.value for f in OutputFormat)}"
        ),
    )
    misc.add_argument(
        "--no-color",
        dest="color",
        action="store_false",
        help="Disable ANSI colour output",
    )
    misc.add_argument(
        "-q",
        dest="quiet",
        action="store_true",
        help="Suppress informational output (WARNING+ only)",
    )

    return parser