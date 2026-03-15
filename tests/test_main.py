"""Tests for sncscan.main — orchestration helpers."""

import io
import logging

import pytest

from sncscan.main import configure_logging, parse_target_list
from sncscan.models import OutputFormat, Protocol, SNCScanResult, SNCScanTarget


# ---------------------------------------------------------------------------
# parse_target_list
# ---------------------------------------------------------------------------

class TestParseTargetList:
    def test_single_host(self):
        targets = parse_target_list("/H/192.168.1.1/S/3200")
        assert len(targets) == 1
        assert targets[0].host == "192.168.1.1"
        assert targets[0].port == 3200

    def test_two_hosts(self):
        targets = parse_target_list("/H/192.168.1.1/S/3200,/H/192.168.1.2/S/3206")
        assert len(targets) == 2
        assert targets[1].host == "192.168.1.2"
        assert targets[1].port == 3206

    def test_multi_hop_route(self):
        rs      = "/H/10.0.0.1/S/3299/H/10.0.0.2/S/3200"
        targets = parse_target_list(rs)
        assert len(targets) == 1
        assert targets[0].route_string == rs
        assert targets[0].host is None

    def test_all_diag_protocol(self):
        targets = parse_target_list("/H/10.0.0.1/S/3200")
        assert targets[0].protocol is Protocol.DIAG

    def test_whitespace_around_entries(self):
        targets = parse_target_list(" /H/10.0.0.1/S/3200 , /H/10.0.0.2/S/3201 ")
        assert len(targets) == 2

    def test_trailing_comma_ignored(self):
        targets = parse_target_list("/H/10.0.0.1/S/3200,")
        assert len(targets) == 1

    def test_malformed_entry_skipped(self, caplog):
        with caplog.at_level(logging.WARNING):
            targets = parse_target_list("/H/10.0.0.1/S/3200,NOT_VALID,/H/10.0.0.2/S/3201")
        assert len(targets) == 2
        assert any("NOT_VALID" in r.message for r in caplog.records)

    def test_hostname_with_h_letter(self):
        """Regression: original split('H') misidentified hostnames containing H."""
        targets = parse_target_list("/H/HOST-HAP/S/3200")
        assert len(targets) == 1
        assert targets[0].host == "HOST-HAP"
        assert targets[0].route_string is None


# ---------------------------------------------------------------------------
# configure_logging
# ---------------------------------------------------------------------------

class TestConfigureLogging:
    def test_default_level_is_info(self):
        configure_logging()
        assert logging.getLogger().level == logging.INFO

    def test_verbose_sets_debug(self):
        configure_logging(verbose=True)
        assert logging.getLogger().level == logging.DEBUG

    def test_quiet_sets_warning(self):
        configure_logging(quiet=True)
        assert logging.getLogger().level == logging.WARNING

    def test_no_duplicate_handlers(self):
        configure_logging()
        configure_logging()   # call twice
        assert len(logging.getLogger().handlers) == 2  # always exactly 2


# ---------------------------------------------------------------------------
# run() — orchestration (scanner mocked)
# ---------------------------------------------------------------------------

class TestRun:
    """Test run() with a stubbed SNCSecurityScan so no network is needed."""

    def _make_formatter(self, color=False):
        from sncscan.output import ResultFormatter, TerminalColors
        return ResultFormatter(TerminalColors(enabled=color), stream=io.StringIO())

    def test_run_single_target(self, monkeypatch, diag_target, full_result):
        from sncscan import main as main_mod
        from sncscan.scanner import SNCSecurityScan
        monkeypatch.setattr(SNCSecurityScan, "scan", lambda self: full_result)
        fmt = self._make_formatter()
        main_mod.run([diag_target], OutputFormat.PRETTY, fmt, separator=False)
        assert "10.0.0.1" in fmt.stream.getvalue()

    def test_run_multiple_targets(self, monkeypatch, diag_target, full_result):
        from sncscan import main as main_mod
        from sncscan.scanner import SNCSecurityScan
        monkeypatch.setattr(SNCSecurityScan, "scan", lambda self: full_result)
        fmt = self._make_formatter()
        main_mod.run([diag_target, diag_target, diag_target], OutputFormat.JSON, fmt, separator=False)
        lines = [l for l in fmt.stream.getvalue().splitlines() if l.strip()]
        assert len(lines) == 3

    def test_separator_pretty(self, monkeypatch, diag_target, full_result):
        from sncscan import main as main_mod
        from sncscan.scanner import SNCSecurityScan
        monkeypatch.setattr(SNCSecurityScan, "scan", lambda self: full_result)
        fmt = self._make_formatter()
        main_mod.run([diag_target, diag_target], OutputFormat.PRETTY, fmt, separator=True)
        assert fmt.stream.getvalue().count("-" * 70) == 2

    def test_run_failed_scan(self, monkeypatch, diag_target):
        from sncscan import main as main_mod
        from sncscan.scanner import SNCSecurityScan
        failed = SNCScanResult(target=diag_target, done=False)
        monkeypatch.setattr(SNCSecurityScan, "scan", lambda self: failed)
        fmt = self._make_formatter()
        main_mod.run([diag_target], OutputFormat.PRETTY, fmt)
        assert "scan unsuccessful" in fmt.stream.getvalue()
