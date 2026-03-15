"""Tests for sncscan.constants — sanity checks on protocol constants."""

from sncscan import constants as C


class TestSNCToken:
    def test_is_bytes(self):
        assert isinstance(C.SNC_TOKEN, bytes)

    def test_length(self):
        # The original token is 101 bytes
        assert len(C.SNC_TOKEN) == 101

    def test_starts_with_asn1_sequence(self):
        # ASN.1 SEQUENCE tag = 0x30
        assert C.SNC_TOKEN[0] == 0x30


class TestSNCData:
    def test_is_str(self):
        assert isinstance(C.SNC_DATA, str)

    def test_contains_crypto_lib_name(self):
        assert "CommonCryptoLib" in C.SNC_DATA

    def test_ends_with_null_padding(self):
        assert C.SNC_DATA.endswith("\x00\x00\x00\x00")

    def test_data_length_offset_router(self):
        # Router data_length = len(SNC_DATA) - 4
        assert len(C.SNC_DATA) - 4 > 0

    def test_data_length_offset_diag(self):
        # DIAG data_length = len(SNC_DATA) - 0
        assert len(C.SNC_DATA) > 0


class TestExtFields:
    def test_router_ext_is_str(self):
        assert isinstance(C.SNC_EXT_FIELDS_ROUTER, str)

    def test_diag_ext_is_str(self):
        assert isinstance(C.SNC_EXT_FIELDS_DIAG, str)

    def test_router_longer_than_diag(self):
        # Router ext_fields carries a longer DN (CN=MYSAPROUTER2 vs CN=NPL)
        assert len(C.SNC_EXT_FIELDS_ROUTER) > len(C.SNC_EXT_FIELDS_DIAG)


class TestQoPFlags:
    def test_max_flag(self):
        assert C.QOP_FLAG_MAX == 0x7E

    def test_min_flag(self):
        assert C.QOP_FLAG_MIN == 0x2A

    def test_min_less_than_max(self):
        assert C.QOP_FLAG_MIN < C.QOP_FLAG_MAX


class TestHeaderLengths:
    def test_router_header(self):
        assert C.ROUTER_HEADER_LENGTH == 73

    def test_diag_header(self):
        assert C.DIAG_HEADER_LENGTH == 64


class TestMiscConstants:
    def test_protocol_version(self):
        assert C.SNC_PROTOCOL_VERSION == 6

    def test_diag_support_bits_is_bytes(self):
        assert isinstance(C.DIAG_SUPPORT_BITS, bytes)

    def test_diag_support_bits_length(self):
        assert len(C.DIAG_SUPPORT_BITS) == 32