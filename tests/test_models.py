"""Tests for sncscan.models — pure data, no network."""

import pytest
from sncscan.models import OutputFormat, Protocol, SNCScanResult, SNCScanTarget


# ---------------------------------------------------------------------------
# Protocol enum
# ---------------------------------------------------------------------------

class TestProtocol:
    def test_values(self):
        assert Protocol.DIAG.value   == "diag"
        assert Protocol.ROUTER.value == "router"

    def test_from_string(self):
        assert Protocol("diag")   is Protocol.DIAG
        assert Protocol("router") is Protocol.ROUTER

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            Protocol("rfc")


# ---------------------------------------------------------------------------
# OutputFormat enum
# ---------------------------------------------------------------------------

class TestOutputFormat:
    def test_all_values(self):
        expected = {"pretty", "plain", "json", "only_violations"}
        assert {f.value for f in OutputFormat} == expected

    def test_from_string(self):
        assert OutputFormat("json") is OutputFormat.JSON


# ---------------------------------------------------------------------------
# SNCScanTarget
# ---------------------------------------------------------------------------

class TestSNCScanTarget:
    def test_from_host_port_str(self):
        t = SNCScanTarget.from_host_port("192.168.1.1", 3200, Protocol.DIAG)
        assert str(t) == "/H/192.168.1.1/S/3200"

    def test_from_route_string_str(self):
        rs = "/H/10.0.0.1/S/3299/H/10.0.0.2/S/3200"
        t  = SNCScanTarget.from_route_string(rs, Protocol.DIAG)
        assert str(t) == rs

    def test_route_string_takes_priority_in_str(self):
        # When route_string is set it should appear in __str__, not host/port
        t = SNCScanTarget(
            host="10.0.0.1", port=3200,
            route_string="/H/proxy/S/3299/H/10.0.0.1/S/3200",
            protocol=Protocol.DIAG,
        )
        assert "/H/proxy" in str(t)

    def test_missing_host_and_route_raises(self):
        with pytest.raises(ValueError, match="requires either"):
            SNCScanTarget(host=None, port=None, route_string=None, protocol=Protocol.DIAG)

    def test_default_protocol_from_host_port(self):
        t = SNCScanTarget.from_host_port("h", 3200)
        assert t.protocol is Protocol.DIAG

    def test_default_protocol_from_route(self):
        t = SNCScanTarget.from_route_string("/H/h/S/3200")
        assert t.protocol is Protocol.DIAG


# ---------------------------------------------------------------------------
# SNCScanResult — QoP properties
# ---------------------------------------------------------------------------

class TestSNCScanResultQoP:
    """Verify qop_use / qop_max / qop_min bit extraction."""

    @pytest.mark.parametrize("flag,use,max_,min_", [
        (0x7E, 3, 3, 3),   # all max — Privacy
        (0x2A, 1, 1, 1),   # all min — Auth
        (0x00, 0, 0, 0),   # all zero — None
        (0x6E, 3, 1, 3),   # mixed
        (0x4A, 2, 1, 1),   # mixed
    ])
    def test_qop_extraction(self, diag_target, flag, use, max_, min_):
        r = SNCScanResult(target=diag_target, qop_flag=flag, done=True)
        assert r.qop_use == use
        assert r.qop_max == max_
        assert r.qop_min == min_

    def test_default_qop_flag_is_zero(self, diag_target):
        r = SNCScanResult(target=diag_target)
        assert r.qop_flag == 0
        assert r.qop_use == r.qop_max == r.qop_min == 0


# ---------------------------------------------------------------------------
# SNCScanResult — is_fully_secure()
# ---------------------------------------------------------------------------

class TestIsFullySecure:
    def test_fully_secure(self, full_result):
        assert full_result.is_fully_secure() is True

    def test_not_secure_when_disabled(self, diag_target):
        r = SNCScanResult(target=diag_target, enabled=False, qop_flag=0x7E, done=True)
        assert r.is_fully_secure() is False

    def test_not_secure_when_flag_low(self, diag_target):
        r = SNCScanResult(target=diag_target, enabled=True, qop_flag=0x2A, done=True)
        assert r.is_fully_secure() is False

    def test_not_secure_when_not_done(self, diag_target):
        r = SNCScanResult(target=diag_target, enabled=True, qop_flag=0x7E, done=False)
        # done=False doesn't affect is_fully_secure — that's output's responsibility
        # but we verify enabled + flag dominate
        assert r.is_fully_secure() is True


# ---------------------------------------------------------------------------
# SNCScanResult — defaults
# ---------------------------------------------------------------------------

class TestSNCScanResultDefaults:
    def test_defaults(self, diag_target):
        r = SNCScanResult(target=diag_target)
        assert r.qop_flag  == 0
        assert r.enabled   is False
        assert r.enforced  is False
        assert r.mechid    == ""
        assert r.cryptolib == ""
        assert r.done      is False