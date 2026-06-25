//! FreeGSM: transparent DNS-over-HTTPS + SNI/DPI bypass on macOS.
//!
//! Run from an elevated context. macOS uses pf rules while Windows uses
//! WinDivert. Ctrl+C removes the temporary redirect state.

// A console app; no Windows subsystem flag so logs go to the terminal.

mod config;
#[cfg(windows)]
mod divert;
mod dnsutil;
mod doh;
#[cfg(any(windows, target_os = "macos"))]
mod dpi;
#[cfg(windows)]
mod https_proxy;
mod logging;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod netpkt;
#[cfg(any(windows, target_os = "macos"))]
mod rng;
#[cfg(windows)]
mod tcp_proxy;
#[cfg(windows)]
mod udp;

use std::time::Duration;

use anyhow::Result;

#[cfg(windows)]
use crate::divert::Diverter;

#[cfg(windows)]
#[link(name = "shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
}

#[cfg(windows)]
fn is_admin() -> bool {
    // SAFETY: IsUserAnAdmin takes no args and returns a BOOL.
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(target_os = "macos")]
fn is_admin() -> bool {
    match std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
    {
        Some(uid) => uid.trim() == "0",
        None => false,
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn is_admin() -> bool {
    true
}

fn run() -> Result<i32> {
    logging::init();

    if !is_admin() {
        #[cfg(windows)]
        log::error!(target: "freegsm",
            "Administrator privileges required (WinDivert loads a kernel driver). \
             Re-run this from an elevated terminal, or use the packaged .exe.");
        #[cfg(target_os = "macos")]
        log::error!(target: "freegsm",
            "Root privileges required (macOS pf rules redirect DNS traffic). \
             Re-run with sudo.");
        return Ok(1);
    }

    let cfg = config::init();

    log::info!(target: "freegsm",
        "FreeGSM starting. Upstream: {}  (fail-{})",
        cfg.doh_url,
        if config::FAIL_OPEN { "open" } else { "closed" });
    if cfg.dpi_bypass {
        log::info!(target: "freegsm",
            "SNI/DPI bypass: ON (TLS record fragmentation via local relay on TCP/443)");
    } else {
        log::info!(target: "freegsm", "SNI/DPI bypass: OFF (set FREEGSM_DPI=1 to enable)");
    }

    doh::start()?;

    // Probe the upstream BEFORE touching DNS. With fail-closed, starting against
    // an unreachable upstream would kill all DNS; refusing to start keeps the
    // machine's DNS untouched and tells the user how to fix it.
    log::info!(target: "freegsm", "Probing DoH upstream...");
    let (ok, detail) = doh::probe();
    if !ok {
        log::error!(target: "freegsm", "DoH upstream {} is unreachable ({detail}).", cfg.doh_url);
        log::error!(target: "freegsm",
            "Not starting (fail-closed would break all DNS). Some networks block \
             1.1.1.1 specifically. Set a reachable upstream and retry, e.g.:");
        log::error!(target: "freegsm", "    set FREEGSM_DOH_URL=https://8.8.8.8/dns-query");
        log::error!(target: "freegsm", "    set FREEGSM_DOH_URL=https://9.9.9.9/dns-query");
        return Ok(1);
    }
    log::info!(target: "freegsm", "DoH upstream reachable.");

    start_platform(cfg)?;

    log::info!(target: "freegsm", "Stopped. Normal DNS restored.");
    Ok(0)
}

#[cfg(windows)]
fn start_platform(cfg: &config::Config) -> Result<()> {
    tcp_proxy::start_server()?;
    if cfg.dpi_bypass {
        https_proxy::start_server()?;
    }

    let diverter = Diverter::new()?;
    let _capture = std::thread::Builder::new()
        .name("capture".into())
        .spawn(move || {
            diverter.run();
            divert::request_stop();
        })?;

    let _ = ctrlc::set_handler(|| {
        log::info!(target: "freegsm", "Shutting down...");
        divert::request_stop();
    });

    log::info!(target: "freegsm", "Running. DNS is now upgraded to DoH. Press Ctrl+C to stop.");
    while !divert::is_stopped() {
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn start_platform(_cfg: &config::Config) -> Result<()> {
    let runtime = macos::start()?;
    let _ = ctrlc::set_handler(|| {
        log::info!(target: "freegsm", "Shutting down...");
        macos::request_stop();
    });

    log::info!(target: "freegsm", "Running. DNS is now upgraded to DoH. Press Ctrl+C to stop.");
    while !macos::is_stopped() {
        std::thread::sleep(Duration::from_millis(200));
    }
    drop(runtime);
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn start_platform(_cfg: &config::Config) -> Result<()> {
    anyhow::bail!("FreeGSM currently supports Windows and macOS only")
}

fn main() {
    let code = run().unwrap_or_else(|e| {
        log::error!(target: "freegsm", "fatal: {e:#}");
        1
    });
    std::process::exit(code);
}
