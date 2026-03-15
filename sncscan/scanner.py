# encoding: utf-8
# sncscan - scanner of SNC configurations for routers and SAP systems
# Copyright (C) 2023  usd AG
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations
import logging
import traceback
from datetime import datetime
from socket import error as SocketError
from sncscan.constants import (
    DIAG_HEADER_LENGTH, DIAG_SUPPORT_BITS, QOP_FLAG_MAX, QOP_FLAG_MIN,
    ROUTER_HEADER_LENGTH, SNC_DATA, SNC_EXT_FIELDS_DIAG, SNC_EXT_FIELDS_ROUTER,
    SNC_PROTOCOL_VERSION, SNC_TOKEN,
)
from sncscan.models import Protocol, SNCScanResult, SNCScanTarget

log = logging.getLogger(__name__)

def _init_scapy():
    try:
        from scapy.config import conf
        conf.verb = 0
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    except Exception:
        pass

class SNCSecurityScan:
    def __init__(self, target: SNCScanTarget) -> None:
        self.target = target

    def scan(self) -> SNCScanResult:
        log.info("%s", datetime.today().ctime())
        log.info("scanning host: %s", self.target)
        if self.target.protocol == Protocol.DIAG:
            return self._scan_diag()
        if self.target.protocol == Protocol.ROUTER:
            return self._scan_router()
        log.warning("Unknown protocol: %s", self.target.protocol)
        return SNCScanResult(target=self.target)

    @staticmethod
    def _build_snc_frame(flags, ext_fields, header_length, data_length_offset=4):
        from pysap.SAPSNC import SAPSNCFrame
        return SAPSNCFrame(
            token=SNC_TOKEN, token_length=len(SNC_TOKEN),
            protocol_version=SNC_PROTOCOL_VERSION, flags=flags, ext_flags=1,
            ext_field_length=len(ext_fields), ext_fields=ext_fields,
            data=SNC_DATA, data_length=len(SNC_DATA) - data_length_offset,
            header_length=header_length,
        )

    def _sncinit(self, connection, snc_frame):
        from pysap.SAPDiag import SAPDiag, SAPDiagDP
        connection.connect()
        return connection.sr(
            SAPDiagDP(rq_id=0, terminal="sncscan")
            / SAPDiag(com_flag_TERM_INI=1, compress=2, snc_frame=snc_frame)
        )

    def _check_encrypted_gui(self, connection):
        from pysap.SAPDiag import SAPDiag, SAPDiagDP, SAPDiagItem
        from pysap.SAPDiagItems import SAPDiagSupportBits, SAPDiagUserConnect
        connection.connect()
        uc  = SAPDiagItem(item_type=0x10, item_id=0x04, item_sid=0x02,
                          item_value=SAPDiagUserConnect(protocol_version=100200, code_page=1100, ws_type=3000))
        uc2 = SAPDiagItem(item_type=0x10, item_id=0x04, item_sid=0x0B,
                          item_value=SAPDiagSupportBits(DIAG_SUPPORT_BITS))
        return connection.sr(
            SAPDiagDP(terminal=connection.terminal, rq_id=0)
            / SAPDiag(compress=0, com_flag_TERM_INI=1) / uc / uc2
        )

    def _scan_router(self) -> SNCScanResult:
        from pysap.SAPRouter import SAPRouter, SAPRouterError, SAPRoutedStreamSocket
        from pysap.SAPSNC import SAPSNCFrame, snc_mech_id_values
        _init_scapy()
        result = SNCScanResult(target=self.target)
        try:
            conn = SAPRoutedStreamSocket.get_nisocket(self.target.host, self.target.port, self.target.route_string)
            log.info("connect to server o.k.\n")
            snc_frame = self._build_snc_frame(QOP_FLAG_MAX, SNC_EXT_FIELDS_ROUTER, ROUTER_HEADER_LENGTH, 4)
            con_text_val = ""
            req = SAPRouter(type=SAPRouter.SAPROUTER_CONTROL, opcode=70, version=40, return_code=0,
                            control_text_value=con_text_val, control_text_length=len(con_text_val), snc_frame=snc_frame)
            response = conn.sr(req)
            response.decode_payload_as(SAPSNCFrame)
            if response[SAPSNCFrame].frame_type == 4:
                result.enabled   = True
                result.mechid    = snc_mech_id_values.get(response[SAPSNCFrame].mech_id)
                result.qop_flag  = response[SAPSNCFrame].flags
                result.cryptolib = response[SAPSNCFrame].data.decode("utf-8")
            else:
                result.enabled = False
                response.decode_payload_as(SAPRouter)
                err = response.err_text_value
                err.decode_payload_as(SAPRouterError)
                log.info(err.error.decode("utf-8"))
            result.done = True
            conn.close()
        except SocketError:
            log.error("Connection error to %s", self.target)
        except KeyboardInterrupt:
            log.info("Cancelled by the user")
        return result

    def _scan_diag(self) -> SNCScanResult:
        from pysap.SAPDiag import SAPDiag
        from pysap.SAPDiagClient import SAPDiagConnection
        from pysap.SAPSNC import SAPSNCFrame, snc_mech_id_values
        _init_scapy()
        result = SNCScanResult(target=self.target)
        try:
            snc_frame  = self._build_snc_frame(QOP_FLAG_MIN, SNC_EXT_FIELDS_DIAG, DIAG_HEADER_LENGTH, 0)
            connection = SAPDiagConnection(self.target.host, self.target.port, route=self.target.route_string, init=False)
            response   = self._sncinit(connection, snc_frame)
            log.info("connect to server o.k.\n")
            response.payload.decode_payload_as(SAPSNCFrame)
            if response[SAPSNCFrame].frame_type == 4:
                result.enabled   = True
                result.mechid    = snc_mech_id_values.get(response[SAPSNCFrame].mech_id)
                result.qop_flag  = response[SAPSNCFrame].flags
                result.cryptolib = response[SAPSNCFrame].data.decode("utf-8")
                try:
                    conn2 = SAPDiagConnection(self.target.host, self.target.port, route=self.target.route_string, init=False)
                    result.enforced = self._check_encrypted_gui(conn2)["SAPDiag"].err_no == 1
                except Exception:
                    log.debug("Could not determine snc/only_encrypted_gui:\n%s", traceback.format_exc())
            else:
                response.payload.decode_payload_as(SAPDiag)
                result.enabled = False if "SNC" in response[SAPDiag].info else result.enabled
            result.done = True
        except SocketError:
            log.error("Connection error to %s", self.target)
        except KeyboardInterrupt:
            log.info("Cancelled by the user")
        return result
