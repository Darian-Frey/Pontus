-- telnet.lua — flag plaintext Telnet exposure.
--
-- A Pontus Lua plugin (F-020). Define a global `check(target)` that returns a
-- list of findings. `target` has: ip (string), hostname (string or nil) and
-- ports (a list of { port, proto, service, version }). Each finding is a table
-- with title (required) plus optional severity (info|low|medium|high|critical),
-- description and a metadata table of string keys/values.
--
-- The runtime is sandboxed: no io, os, require — only base/table/string/math.

function check(target)
  local findings = {}
  for _, p in ipairs(target.ports) do
    if p.proto == "tcp" and p.port == 23 then
      findings[#findings + 1] = {
        title = "Telnet exposed",
        severity = "high",
        description = "Port 23/tcp (Telnet) is open. Telnet transmits credentials "
          .. "in cleartext; use SSH instead.",
        metadata = { port = "23", proto = "tcp" },
      }
    end
  end
  return findings
end
