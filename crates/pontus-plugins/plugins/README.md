# Bundled Pontus plugins

Point a scan at this directory to run them:

```bash
pontus-cli scan 192.168.1.0/24 --scope 192.168.1.0/24 --plugins crates/pontus-plugins/plugins
pontus-cli findings            # list what they recorded
```

In the GUI, set the **Plugins** field in the New-scan dialog to this directory, then
open **View ▸ Plugin findings…** (Ctrl+F) after the scan.

Plugins are dispatched by extension: `.lua`, `.wasm`/`.wat`, and `.py` (the last
needs a `--features python` build of the CLI). Findings are recorded against the
scanned asset.

## The contract

A plugin receives a **target** and returns a list of **findings**.

- `target`: `{ ip, hostname, ports }`, where each port is
  `{ port, proto, service, version }` (`service`/`version` come from detection and
  may be absent).
- a finding: `{ title (required), severity, description, metadata }`, where
  `severity` is one of `info | low | medium | high | critical` and `metadata` is a
  flat table of string keys/values.

Lua plugins define a global `check(target)`; Python plugins define a top-level
`check(target)`; WASM plugins export `run` (see the crate docs). The runner stamps
the producing plugin's name onto each finding.

## Included

| File | Fires on | What it flags |
|------|----------|---------------|
| `cleartext-services.lua` | open TCP ports (HTTP, FTP, Telnet, POP3/IMAP, SNMP, LDAP, VNC, r-services) | services that carry data/credentials in the clear |
| `exposed-discovery.lua` | UPnP/SSDP, mDNS, NetBIOS, WS-Discovery, IPP (mostly UDP — scan with `--udp-ports`) | discovery/IoT services reachable on the network |
| `telnet.lua`, `telnet.py` | TCP/23 | minimal one-protocol examples of the API |

All signatures are clean-room — derived from public well-known-port/protocol
knowledge, not from any third-party dataset (C-001).
