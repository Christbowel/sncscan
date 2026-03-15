"""Tests for sncscan.output — formatting and colour rendering."""

import io
import json

import pytest

from sncscan.models import OutputFormat, Protocol, SNCScanResult, SNCScanTarget
from sncscan.output import ResultFormatter, TerminalColors

ANSI_ESC = "\033["


# ---------------------------------------------------------------------------
# TerminalColors
# ---------------------------------------------------------------------------

class TestTerminalColors:
    def test_ansi_enabled(self):
        c = TerminalColors(enabled=True)
        assert ANSI_ESC in c.RED
        assert ANSI_ESC in c.GREEN
        assert c.END != ""

    def test_ansi_disabled(self):
        c = TerminalColors(enabled=False)
        for attr in ("BLUE", "CYAN", "GREEN", "ORANGE", "RED", "END"):
            assert getattr(c, attr) == ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def render(result, fmt, color=False) -> str:
    buf = io.StringIO()
    c   = TerminalColors(enabled=color)
    ResultFormatter(c, stream=buf).render(result, fmt)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# ResultFormatter — unsuccessful scan
# ---------------------------------------------------------------------------

class TestUnsuccessfulScan:
    def test_done_false_prints_unsuccessful(self, diag_target):
        r = SNCScanResult(target=diag_target, done=False)
        out = render(r, OutputFormat.PRETTY)
        assert "scan unsuccessful" in out

    def test_done_false_skips_formatting(self, diag_target):
        r = SNCScanResult(target=diag_target, done=False)
        out = render(r, OutputFormat.PRETTY)
        assert "SNC enabled" not in out


# ---------------------------------------------------------------------------
# PRETTY format
# ---------------------------------------------------------------------------

class TestPrettyFormat:
    def test_snc_enabled_yes(self, full_result):
        out = render(full_result, OutputFormat.PRETTY)
        assert "1 (yes)" in out

    def test_snc_enabled_no(self, diag_target):
        r = SNCScanResult(target=diag_target, enabled=False, done=True)
        out = render(r, OutputFormat.PRETTY)
        assert "0 (no)" in out

    def test_qop_all_privacy(self, full_result):
        out = render(full_result, OutputFormat.PRETTY)
        assert out.count("Privacy") == 3

    def test_mechid_and_cryptolib(self, full_result):
        out = render(full_result, OutputFormat.PRETTY)
        assert "SAPGSSPAPI"         in out
        assert "CommonCryptoLib 8.5" in out

    def test_enforced_true(self, full_result):
        out = render(full_result, OutputFormat.PRETTY)
        assert "not allowed"  in out
        assert "1 (True)"     in out

    def test_enforced_false(self, diag_target):
        r = SNCScanResult(target=diag_target, qop_flag=0x7E,
                          enabled=True, enforced=False, done=True)
        out = render(r, OutputFormat.PRETTY)
        assert "0 (False)" in out

    def test_router_no_enforced_line(self, router_target):
        r = SNCScanResult(target=router_target, qop_flag=0x7E,
                          enabled=True, done=True)
        out = render(r, OutputFormat.PRETTY)
        assert "only_encrypted_gui" not in out

    def test_target_displayed(self, full_result):
        out = render(full_result, OutputFormat.PRETTY)
        assert "10.0.0.1" in out

    def test_good_flag_green_bad_flag_red(self, diag_target):
        # Good flag → GREEN code
        r_good = SNCScanResult(target=diag_target, qop_flag=0x7E,
                               enabled=True, done=True)
        out_good = render(r_good, OutputFormat.PRETTY, color=True)
        assert "\033[92m" in out_good   # GREEN

        # Bad flag → RED code
        r_bad = SNCScanResult(target=diag_target, qop_flag=0x2A,
                              enabled=True, done=True)
        out_bad = render(r_bad, OutputFormat.PRETTY, color=True)
        assert "\033[91m" in out_bad    # RED


# ---------------------------------------------------------------------------
# PLAIN format
# ---------------------------------------------------------------------------

class TestPlainFormat:
    def test_diag_contains_enforced(self, full_result):
        out = render(full_result, OutputFormat.PLAIN)
        assert "Enforced:" in out

    def test_router_no_enforced(self, router_target):
        r = SNCScanResult(target=router_target, qop_flag=0x7E,
                          enabled=True, done=True)
        out = render(r, OutputFormat.PLAIN)
        assert "Enforced:" not in out

    def test_contains_all_fields(self, full_result):
        out = render(full_result, OutputFormat.PLAIN)
        for field in ("Target:", "QoP:", "Enabled:", "MechID:", "CryptoLib:", "Done:"):
            assert field in out


# ---------------------------------------------------------------------------
# JSON format
# ---------------------------------------------------------------------------

class TestJsonFormat:
    def test_valid_json(self, full_result):
        out = render(full_result, OutputFormat.JSON)
        parsed = json.loads(out)
        assert isinstance(parsed, dict)

    def test_diag_keys(self, full_result):
        parsed = json.loads(render(full_result, OutputFormat.JSON))
        for key in ("target","qop_use","qop_max","qop_min","enabled","enforced","mechid","cryptolib","done"):
            assert key in parsed

    def test_router_no_enforced_key(self, router_target):
        r      = SNCScanResult(target=router_target, qop_flag=0x7E, enabled=True, done=True)
        parsed = json.loads(render(r, OutputFormat.JSON))
        assert "enforced" not in parsed

    def test_qop_values_correct(self, full_result):
        parsed = json.loads(render(full_result, OutputFormat.JSON))
        assert parsed["qop_use"] == 3
        assert parsed["qop_max"] == 3
        assert parsed["qop_min"] == 3

    def test_enabled_false(self, diag_target):
        r      = SNCScanResult(target=diag_target, enabled=False, done=True)
        parsed = json.loads(render(r, OutputFormat.JSON))
        assert parsed["enabled"] is False


# ---------------------------------------------------------------------------
# ONLY_VIOLATIONS format
# ---------------------------------------------------------------------------

class TestOnlyViolationsFormat:
    def test_no_output_when_fully_secure(self, full_result):
        # A fully-secure result should not mention any flag / qop violation
        out = render(full_result, OutputFormat.ONLY_VIOLATIONS)
        assert "0x" not in out
        assert "False" not in out

    def test_snc_disabled_shown(self, diag_target):
        r   = SNCScanResult(target=diag_target, enabled=False, done=True)
        out = render(r, OutputFormat.ONLY_VIOLATIONS)
        assert "0 (no)" in out

    def test_low_flag_shown(self, diag_target):
        r   = SNCScanResult(target=diag_target, enabled=True, qop_flag=0x2A, done=True)
        out = render(r, OutputFormat.ONLY_VIOLATIONS)
        assert hex(0x2A) in out

    def test_low_qop_shown(self, diag_target):
        r   = SNCScanResult(target=diag_target, enabled=True, qop_flag=0x2A, done=True)
        out = render(r, OutputFormat.ONLY_VIOLATIONS)
        assert "Auth" in out   # qop value 1 maps to "Auth" via snc_qop mock

    def test_gui_not_enforced_shown(self, diag_target):
        r   = SNCScanResult(target=diag_target, enabled=True, qop_flag=0x7E,
                            enforced=False, done=True)
        out = render(r, OutputFormat.ONLY_VIOLATIONS)
        assert "only_encrypted_gui" in out
        assert "0 (False)"          in out

    def test_router_no_gui_line(self, router_target):
        r   = SNCScanResult(target=router_target, enabled=True, qop_flag=0x2A, done=True)
        out = render(r, OutputFormat.ONLY_VIOLATIONS)
        assert "only_encrypted_gui" not in out