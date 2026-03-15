# encoding: utf-8
# sncscan - scanner of SNC configurations for routers and SAP systems
#
# Copyright (C) 2023  usd AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Core data models.

This module is intentionally import-light: no pysap, no scapy, no output
helpers.  Everything here is a plain Python data structure so that tests can
exercise the models without any network-level dependency installed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional



class Protocol(str, Enum):
    """SAP protocol variant to probe."""

    DIAG   = "diag"
    ROUTER = "router"


class OutputFormat(str, Enum):
    """Supported output formats for scan results."""

    PRETTY          = "pretty"
    PLAIN           = "plain"
    JSON            = "json"
    ONLY_VIOLATIONS = "only_violations"



@dataclass
class SNCScanTarget:
    """A single scan target, either a direct host/port pair or a route string.

    Exactly one of (*host* + *port*) or *route_string* must be provided.

    Attributes:
        host:         IP address or hostname of the SAP system.
        port:         TCP port (e.g. 3200 for DIAG, 3299 for router).
        route_string: Full SAP route string, e.g. ``/H/10.0.0.1/S/3299/H/…``.
        protocol:     :class:`Protocol` variant to use for the scan.
    """

    host: Optional[str]
    port: Optional[int]
    route_string: Optional[str]
    protocol: Protocol

    def __post_init__(self) -> None:
        has_hostport = self.host is not None and self.port is not None
        has_route    = self.route_string is not None
        if not (has_hostport or has_route):
            raise ValueError(
                "SNCScanTarget requires either (host + port) or route_string."
            )

    def __str__(self) -> str:
        if self.route_string:
            return self.route_string
        return f"/H/{self.host}/S/{self.port}"

    @classmethod
    def from_route_string(
        cls, route_string: str, protocol: Protocol = Protocol.DIAG
    ) -> "SNCScanTarget":
        """Create a target from a SAP route string."""
        return cls(host=None, port=None, route_string=route_string, protocol=protocol)

    @classmethod
    def from_host_port(
        cls, host: str, port: int, protocol: Protocol = Protocol.DIAG
    ) -> "SNCScanTarget":
        """Create a target from an explicit host / port pair."""
        return cls(host=host, port=port, route_string=None, protocol=protocol)


@dataclass
class SNCScanResult:
    """Outcome of a single SNC scan.

    Attributes:
        target:    The :class:`SNCScanTarget` that was probed.
        qop_flag:  Raw Quality-of-Protection byte returned by the server.
        enabled:   Whether SNC is enabled on the target system.
        enforced:  (DIAG only) Whether the server rejects unencrypted GUI
                   connections (``snc/only_encrypted_gui = 1``).
        mechid:    Human-readable SNC mechanism identifier string.
        cryptolib: Name of the crypto library advertised by the server.
        done:      ``True`` when the scan completed without a fatal error.
    """

    target:    SNCScanTarget
    qop_flag:  int  = 0
    enabled:   bool = False
    enforced:  bool = False
    mechid:    str  = ""
    cryptolib: str  = ""
    done:      bool = False


    @property
    def qop_use(self) -> int:
        """Default QoP level initiated by the SAP system (snc/data_protection/use)."""
        return (self.qop_flag & 0b1100000) >> 5

    @property
    def qop_max(self) -> int:
        """Highest QoP level initiated by the SAP system (snc/data_protection/max)."""
        return (self.qop_flag & 0b0011000) >> 3

    @property
    def qop_min(self) -> int:
        """Minimum QoP level required for SNC connections (snc/data_protection/min)."""
        return (self.qop_flag & 0b0000110) >> 1


    def is_fully_secure(self) -> bool:
        """Return True when all QoP levels are at maximum (3) and the flag is 0x7E."""
        from sncscan.constants import QOP_FLAG_MAX  # local import avoids circular dep
        return (
            self.enabled
            and self.qop_flag == QOP_FLAG_MAX
            and self.qop_use == 3
            and self.qop_max == 3
            and self.qop_min == 3
        )