from sncscan.models import OutputFormat, Protocol, SNCScanResult, SNCScanTarget

__version__ = "2.0.0"
__all__ = [
    "OutputFormat",
    "Protocol",
    "SNCScanResult",
    "SNCScanTarget",
    "SNCSecurityScan",
]

def __getattr__(name: str):
    if name == "SNCSecurityScan":
        from sncscan.scanner import SNCSecurityScan
        return SNCSecurityScan
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
