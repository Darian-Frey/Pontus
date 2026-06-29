# telnet.py — flag plaintext Telnet exposure.
#
# A Pontus Python plugin (F-020). Define a top-level `check(target)` that returns
# a list of findings. `target` is a dict: ip (str), hostname (str or None) and
# ports (list of {port, proto, service, version}). Each finding is a dict with
# title (required) plus optional severity (info|low|medium|high|critical),
# description and a metadata dict of string keys/values.
#
# This is the trusted, full-power tier: the runner does NOT sandbox Python. Run
# untrusted code in the WASM tier instead.


def check(target):
    findings = []
    for p in target["ports"]:
        if p["proto"] == "tcp" and p["port"] == 23:
            findings.append(
                {
                    "title": "Telnet exposed",
                    "severity": "high",
                    "description": (
                        "Port 23/tcp (Telnet) is open. Telnet transmits "
                        "credentials in cleartext; use SSH instead."
                    ),
                    "metadata": {"port": "23", "proto": "tcp"},
                }
            )
    return findings
