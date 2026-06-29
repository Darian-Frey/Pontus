-- exposed-discovery.lua — note discovery / IoT services that are reachable. These
-- are rarely meant to face untrusted hosts: UPnP can expose device control and
-- port-forwarding, and mDNS/NetBIOS leak hostnames and services. Informational by
-- default — they're inventory context, not necessarily defects.
--
-- Clean-room well-known-port knowledge (C-001). Most of these are UDP, so scan
-- with UDP ports set (e.g. --udp-ports 1900,5353) to see them. Entry: check(target).

local DISCOVERY = {
  ["udp/1900"] = { name = "SSDP/UPnP",   sev = "low",  note = "UPnP control can expose port-forwarding and device control" },
  ["tcp/1900"] = { name = "UPnP (HTTP)", sev = "low",  note = "UPnP device/control description served over HTTP" },
  ["udp/5353"] = { name = "mDNS",        sev = "info", note = "multicast DNS advertises hostnames/services on the segment" },
  ["udp/137"]  = { name = "NetBIOS-NS",  sev = "low",  note = "NetBIOS name service leaks host/workgroup names" },
  ["udp/138"]  = { name = "NetBIOS-DGM", sev = "info", note = "NetBIOS datagram service" },
  ["udp/3702"] = { name = "WS-Discovery",sev = "info", note = "web-services discovery, commonly used by printers/cameras" },
  ["tcp/631"]  = { name = "IPP/CUPS",    sev = "info", note = "printing service; can expose printer/admin endpoints" },
}

function check(target)
  local out = {}
  for _, p in ipairs(target.ports) do
    local key = p.proto .. "/" .. p.port
    local d = DISCOVERY[key]
    if d then
      out[#out + 1] = {
        title = d.name .. " reachable",
        severity = d.sev,
        description = key .. " — " .. d.note,
        metadata = { port = tostring(p.port), proto = p.proto },
      }
    end
  end
  return out
end
