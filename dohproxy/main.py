"""Entry point: wire DoH client and the platform-specific capture path.

macOS uses temporary pf rdr rules that redirect DNS and TCP/443 to local
proxies. Ctrl+C stops the active platform path and restores normal DNS.
"""

from __future__ import annotations

import ctypes
import logging
import os
import platform
import sys
import threading
import time

from . import config, doh


def _is_admin() -> bool:
    if platform.system() == "Darwin":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    log = logging.getLogger("dohproxy")

    if not _is_admin():
        if platform.system() == "Darwin":
            log.error(
                "Root privileges required (macOS pf rules redirect DNS traffic). "
                "Re-run with sudo."
            )
        else:
            log.error(
                "Administrator privileges required (WinDivert loads a kernel driver). "
                "Re-run this from an elevated terminal, or use the packaged .exe."
            )
        return 1

    log.info("FreeGSM starting. Upstream: %s  (fail-%s)",
             config.DOH_URL, "open" if config.FAIL_OPEN else "closed")
    if config.DPI_BYPASS:
        log.info("SNI/DPI bypass: ON (TLS record fragmentation via local relay "
                 "on TCP/443)")
    else:
        log.info("SNI/DPI bypass: OFF (set FREEGSM_DPI=1 to enable)")

    doh.start()

    # Probe the upstream BEFORE touching DNS. With fail-closed, starting against
    # an unreachable upstream would kill all DNS; refusing to start keeps the
    # machine's DNS untouched and tells the user how to fix it.
    log.info("Probing DoH upstream...")
    ok, detail = doh.probe()
    if not ok:
        log.error("DoH upstream %s is unreachable (%s).", config.DOH_URL, detail)
        log.error(
            "Not starting (fail-closed would break all DNS). Some networks block "
            "1.1.1.1 specifically. Set a reachable upstream and retry, e.g.:"
        )
        log.error('    set FREEGSM_DOH_URL=https://8.8.8.8/dns-query')
        log.error('    set FREEGSM_DOH_URL=https://9.9.9.9/dns-query')
        doh.stop()
        return 1
    log.info("DoH upstream reachable.")

    runtime = _start_platform()
    log.info("Running. DNS is now upgraded to DoH. Press Ctrl+C to stop.")

    try:
        while runtime.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        runtime.stop()
        doh.stop()
        log.info("Stopped. Normal DNS restored.")

    return 0


class _WindowsRuntime:
    def __init__(self) -> None:
        from . import divert, https_proxy, tcp_proxy

        self._tcp_server = tcp_proxy.start_server()
        self._https_server = https_proxy.start_server() if config.DPI_BYPASS else None
        self._diverter = divert.Diverter()
        self._worker = threading.Thread(target=self._diverter.run, name="capture", daemon=True)
        self._worker.start()

    def is_alive(self) -> bool:
        return self._worker.is_alive()

    def stop(self) -> None:
        self._diverter.stop()
        self._tcp_server.shutdown()
        if self._https_server is not None:
            self._https_server.shutdown()


def _start_platform():
    system = platform.system()
    if system == "Darwin":
        from . import macos

        return macos.start()
    if system == "Windows":
        return _WindowsRuntime()
    raise RuntimeError(f"unsupported platform: {system}")


if __name__ == "__main__":
    sys.exit(main())
