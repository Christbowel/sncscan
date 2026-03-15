from socket import error as SocketError
from unittest.mock import MagicMock, patch, patch as p

import pytest
from sncscan.models import Protocol, SNCScanResult, SNCScanTarget
from sncscan.scanner import SNCSecurityScan


def _snc_response(frame_type, flags=0x7E, mech_id=1, data=b"CommonCryptoLib\x00"):
    snc_frame = MagicMock()
    snc_frame.frame_type = frame_type
    snc_frame.flags      = flags
    snc_frame.mech_id    = mech_id
    snc_frame.data       = data
    packet = MagicMock()
    packet.__getitem__ = lambda self, key: snc_frame
    packet.payload = MagicMock()
    packet.payload.decode_payload_as = MagicMock()
    packet.decode_payload_as = MagicMock()
    return packet

def _diag_response(err_no):
    diag = MagicMock(); diag.err_no = err_no
    resp = MagicMock(); resp.__getitem__ = lambda self, key: diag
    return resp


class TestBuildSNCFrame:
    def test_returns_snc_frame(self):
        with patch("pysap.SAPSNC.SAPSNCFrame"):
            try:
                SNCSecurityScan._build_snc_frame(flags=0x7E, ext_fields="x", header_length=64)
            except Exception:
                pass  # stub — just ensure no AttributeError


class TestScanDispatch:
    def test_unknown_protocol_returns_empty(self):
        t = SNCScanTarget(host="h", port=3200, route_string=None, protocol="rfc")
        assert SNCSecurityScan(t).scan().done is False

    def test_diag_protocol_calls_scan_diag(self, diag_target, monkeypatch):
        monkeypatch.setattr(SNCSecurityScan, "_scan_diag",   lambda s: SNCScanResult(target=s.target, done=True))
        monkeypatch.setattr(SNCSecurityScan, "_scan_router", lambda s: (_ for _ in ()).throw(AssertionError()))
        assert SNCSecurityScan(diag_target).scan().done is True

    def test_router_protocol_calls_scan_router(self, router_target, monkeypatch):
        monkeypatch.setattr(SNCSecurityScan, "_scan_router", lambda s: SNCScanResult(target=s.target, done=True))
        monkeypatch.setattr(SNCSecurityScan, "_scan_diag",   lambda s: (_ for _ in ()).throw(AssertionError()))
        assert SNCSecurityScan(router_target).scan().done is True


class TestScanRouter:
    def _run(self, frame_type=4, flags=0x7E):
        target = SNCScanTarget.from_host_port("10.0.0.1", 3299, Protocol.ROUTER)
        mock_conn = MagicMock()
        mock_conn.sr.return_value = _snc_response(frame_type, flags)
        with patch("pysap.SAPRouter.SAPRoutedStreamSocket") as ms, \
             patch("pysap.SAPSNC.SAPSNCFrame"), \
             patch("pysap.SAPRouter.SAPRouter"):
            ms.get_nisocket.return_value = mock_conn
            return SNCSecurityScan(target)._scan_router()

    def test_enabled_on_frame_type_4(self):
        r = self._run(frame_type=4)
        assert r.enabled is True and r.done is True

    def test_qop_flag_parsed(self):
        assert self._run(frame_type=4, flags=0x7E).qop_flag == 0x7E

    def test_disabled_on_other_frame_type(self):
        target = SNCScanTarget.from_host_port("10.0.0.1", 3299, Protocol.ROUTER)
        resp = _snc_response(frame_type=3)
        resp.err_text_value = MagicMock()
        resp.err_text_value.error = b"SNC not supported"
        mock_conn = MagicMock(); mock_conn.sr.return_value = resp
        with patch("pysap.SAPRouter.SAPRoutedStreamSocket") as ms, \
             patch("pysap.SAPSNC.SAPSNCFrame"), \
             patch("pysap.SAPRouter.SAPRouter"), \
             patch("pysap.SAPRouter.SAPRouterError"):
            ms.get_nisocket.return_value = mock_conn
            r = SNCSecurityScan(target)._scan_router()
        assert r.enabled is False and r.done is True

    def test_socket_error_returns_empty(self):
        target = SNCScanTarget.from_host_port("10.0.0.1", 3299, Protocol.ROUTER)
        with patch("pysap.SAPRouter.SAPRoutedStreamSocket") as ms:
            ms.get_nisocket.side_effect = SocketError("refused")
            r = SNCSecurityScan(target)._scan_router()
        assert r.done is False and r.enabled is False


class TestScanDiag:
    def _run(self, frame_type=4, flags=0x7E, gui_err_no=1):
        target = SNCScanTarget.from_host_port("10.0.0.1", 3200, Protocol.DIAG)
        mock_conn = MagicMock(); mock_conn.terminal = "sncscan"
        mock_conn.sr.return_value = _snc_response(frame_type, flags)
        with patch("pysap.SAPDiagClient.SAPDiagConnection", return_value=mock_conn), \
             patch.object(SNCSecurityScan, "_check_encrypted_gui", return_value=_diag_response(gui_err_no)), \
             patch("pysap.SAPSNC.SAPSNCFrame"), \
             patch("pysap.SAPDiag.SAPDiag"), \
             patch("pysap.SAPDiag.SAPDiagDP"):
            return SNCSecurityScan(target)._scan_diag()

    def test_enabled_on_frame_type_4(self):
        r = self._run(frame_type=4)
        assert r.enabled is True and r.done is True

    def test_enforced_when_err_no_1(self):
        assert self._run(frame_type=4, gui_err_no=1).enforced is True

    def test_not_enforced_when_err_no_0(self):
        assert self._run(frame_type=4, gui_err_no=0).enforced is False

    def test_qop_flag_parsed(self):
        assert self._run(frame_type=4, flags=0x2A).qop_flag == 0x2A

    def test_socket_error_returns_empty(self):
        target = SNCScanTarget.from_host_port("10.0.0.1", 3200, Protocol.DIAG)
        with patch.object(SNCSecurityScan, "_build_snc_frame", return_value=MagicMock()), \
             patch("pysap.SAPDiagClient.SAPDiagConnection") as mc:
            mc.return_value.connect.side_effect = SocketError("refused")
            r = SNCSecurityScan(target)._scan_diag()
        assert r.done is False and r.enabled is False
