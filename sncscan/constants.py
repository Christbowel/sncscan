# encoding: utf-8
# sncscan - scanner of SNC configurations for routers and SAP systems
#
# Copyright (C) 2023  usd AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Protocol-level constants for SAP SNC handshakes.

All raw byte sequences, magic flag values, and low-level strings live here so
that the rest of the codebase never needs to import ``pysap`` just to reference
a constant, and so that tests can mock these values without side-effects.
"""

from binascii import unhexlify as unhex


SNC_TOKEN: bytes = (
    b"\x30\x82\x00\x61\x06\x06\x2b\x24\x03\x01\x25\x01\xa0\x82\x00\x55"
    b"\xa1\x53\x04\x15\x04\x01\x01\x01\x00\x02\x01\x03\x02\x01\x02\x02"
    b"\x02\x03\x02\x02\x03\x01\x02\x01\x04\x04\x20\x64\x9d\x49\xe3\x4a"
    b"\x7d\xf7\xc8\x79\x0b\x59\x12\x5b\x7d\xc8\xda\xc8\xd7\x79\xa2\xfe"
    b"\xd1\xe5\xd7\xaf\x29\x03\x07\x94\x58\x4f\x55\xa1\x18\x30\x0b\x02"
    b"\x01\x03\x04\x06\x00\x09\x00\x0a\x00\x0b\x30\x09\x02\x01\x02\x04"
    b"\x04\x24\x3b\x9d\x64"
)

SNC_DATA: str = "Internal SNC-Adapter (Rev 1.1) to CommonCryptoLib\x00\x00\x00\x00"

# Router uses a 34-byte DN block (CN=MYSAPROUTER2)
SNC_EXT_FIELDS_ROUTER: str = (
    "\x00\x03\x04\x01\x00\x08\x06\x06\x2b\x24\x03\x01\x25\x01\x00\x00"
    "\x00\x19\x30\x17\x31\x15\x30\x13\x06\x03\x55\x04\x03\x13\x0c"
    "\x4d\x59\x53\x41\x50\x52\x4f\x55\x54\x45\x52\x32"
)

# DIAG uses a shorter 3-byte CN block (CN=NPL)
SNC_EXT_FIELDS_DIAG: str = (
    "\x00\x03\x04\x01\x00\x08\x06\x06\x2b\x24\x03\x01\x25\x01\x00\x00"
    "\x00\x10\x30\x0e\x31\x0c\x30\x0a\x06\x03\x55\x04\x03\x13\x03"
    "\x4e\x50\x4c"
)

#: Maximum Quality-of-Protection flag (encryption + integrity + auth)
QOP_FLAG_MAX: int = 0x7E

#: Minimum Quality-of-Protection flag used in DIAG init frames
QOP_FLAG_MIN: int = 0x2A

DIAG_SUPPORT_BITS: bytes = unhex(
    "ff7ffa0d78b737def6196e9325bf1593ef73feebdb5501000000000000000000"
)

ROUTER_HEADER_LENGTH: int = 73
DIAG_HEADER_LENGTH: int = 64

SNC_PROTOCOL_VERSION: int = 6
# QoP level labels — mirrors pysap.SAPSNC.snc_qop
SNC_QOP_LABELS: dict[int, str] = {
    0: "None",
    1: "Auth",
    2: "Integrity",
    3: "Privacy",
}
