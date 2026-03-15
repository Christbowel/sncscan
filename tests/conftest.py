import sys, types, pytest

def _mod(name, **attrs):
    m = types.ModuleType(name); [setattr(m,k,v) for k,v in attrs.items()]; sys.modules[name]=m; return m

_mod("scapy"); _mod("scapy.config", conf=types.SimpleNamespace(verb=0))
_mod("scapy.fields"); _mod("scapy.base_classes"); _mod("pysap")
_mod("pysap.SAPSNC", snc_qop={0:"None",1:"Auth",2:"Integrity",3:"Privacy"}, snc_mech_id_values={1:"SAPGSSPAPI"}, SAPSNCFrame=type("SAPSNCFrame",(),{}))
_mod("pysap.SAPDiag", SAPDiag=type("SAPDiag",(),{}), SAPDiagDP=type("SAPDiagDP",(),{}), SAPDiagItem=type("SAPDiagItem",(),{}))
_mod("pysap.SAPDiagClient", SAPDiagConnection=type("SAPDiagConnection",(),{}))
_mod("pysap.SAPDiagItems", SAPDiagUserConnect=type("SAPDiagUserConnect",(),{}), SAPDiagSupportBits=type("SAPDiagSupportBits",(),{}))
_mod("pysap.SAPRouter", SAPRouter=type("SAPRouter",(),{"SAPROUTER_CONTROL":0}), SAPRouterError=type("SAPRouterError",(),{}), SAPRoutedStreamSocket=type("SAPRoutedStreamSocket",(),{}))

@pytest.fixture()
def diag_target():
    from sncscan.models import Protocol, SNCScanTarget
    return SNCScanTarget.from_host_port("10.0.0.1", 3200, Protocol.DIAG)

@pytest.fixture()
def router_target():
    from sncscan.models import Protocol, SNCScanTarget
    return SNCScanTarget.from_host_port("10.0.0.1", 3299, Protocol.ROUTER)

@pytest.fixture()
def full_result(diag_target):
    from sncscan.models import SNCScanResult
    return SNCScanResult(target=diag_target, qop_flag=0x7E, enabled=True, enforced=True, mechid="SAPGSSPAPI", cryptolib="CommonCryptoLib 8.5", done=True)

@pytest.fixture()
def plain_colors():
    from sncscan.output import TerminalColors
    return TerminalColors(enabled=False)
