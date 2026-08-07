"""ranemu.transport — N2(SCTP/NGAP)·N3(GTP-U) 전송 계층."""
from . import sctp, gtpu
from .sctp import SctpClient, SctpServer, SctpError, PPID_NGAP
from .gtpu import GtpuSocket, GtpuPacket, GtpuError, encode as gtpu_encode, decode as gtpu_decode

__all__ = ["sctp", "gtpu", "SctpClient", "SctpServer", "SctpError", "PPID_NGAP",
           "GtpuSocket", "GtpuPacket", "GtpuError", "gtpu_encode", "gtpu_decode"]


def selftest(verbose: bool = False) -> bool:
    results = [("SCTP", sctp.selftest(verbose)), ("GTP-U", gtpu.selftest(verbose))]
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  transport/{name}")
    return all(ok for _, ok in results)
