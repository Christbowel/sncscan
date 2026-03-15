"""Tests for sncscan.cli — argument parsing."""

import pytest

from sncscan.cli import parse_args
from sncscan.models import OutputFormat, Protocol


class TestParseArgsBasic:
    def test_host_and_protocol(self):
        opts = parse_args(["-H", "10.0.0.1", "-p", "diag"])
        assert opts.host     == "10.0.0.1"
        assert opts.protocol is Protocol.DIAG

    def test_default_port(self):
        opts = parse_args(["-H", "10.0.0.1", "-p", "router"])
        assert opts.port == 3299

    def test_custom_port(self):
        opts = parse_args(["-H", "10.0.0.1", "-S", "3200", "-p", "diag"])
        assert opts.port == 3200

    def test_route_string(self):
        rs   = "/H/10.0.0.1/S/3299/H/10.0.0.2/S/3200"
        opts = parse_args(["--route-string", rs, "-p", "diag"])
        assert opts.route_string == rs

    def test_list_targets(self):
        opts = parse_args(["-L", "/H/10.0.0.1/S/3200,/H/10.0.0.2/S/3206"])
        assert opts.list_targets is not None

    def test_listfile(self):
        opts = parse_args(["-iL", "targets.txt"])
        assert opts.listfile == "targets.txt"


class TestParseArgsFlags:
    def test_verbose(self):
        opts = parse_args(["-H", "h", "-v"])
        assert opts.verbose is True

    def test_quiet(self):
        opts = parse_args(["-H", "h", "-q"])
        assert opts.quiet is True

    def test_no_color(self):
        opts = parse_args(["-H", "h", "--no-color"])
        assert opts.color is False

    def test_color_default_true(self):
        opts = parse_args(["-H", "h"])
        assert opts.color is True

    def test_output_file(self):
        opts = parse_args(["-H", "h", "-o", "out.txt"])
        assert opts.file_output == "out.txt"


class TestParseArgsFormat:
    def test_default_format(self):
        opts = parse_args(["-H", "h"])
        assert opts.format is OutputFormat.PRETTY

    @pytest.mark.parametrize("fmt", ["pretty", "plain", "json", "only_violations"])
    def test_all_formats(self, fmt):
        opts = parse_args(["-H", "h", "-f", fmt])
        assert opts.format == OutputFormat(fmt)

    def test_invalid_format_exits(self):
        with pytest.raises(SystemExit):
            parse_args(["-H", "h", "-f", "xml"])


class TestParseArgsProtocol:
    def test_diag(self):
        opts = parse_args(["-H", "h", "-p", "diag"])
        assert opts.protocol is Protocol.DIAG

    def test_router(self):
        opts = parse_args(["-H", "h", "-p", "router"])
        assert opts.protocol is Protocol.ROUTER

    def test_invalid_protocol_exits(self):
        with pytest.raises(SystemExit):
            parse_args(["-H", "h", "-p", "rfc"])

    def test_no_protocol_gives_none(self):
        opts = parse_args(["-H", "h"])
        assert opts.protocol is None


class TestParseArgsNoTarget:
    def test_no_args_exits(self):
        with pytest.raises(SystemExit):
            parse_args([])

    def test_only_verbose_exits(self):
        with pytest.raises(SystemExit):
            parse_args(["-v"])