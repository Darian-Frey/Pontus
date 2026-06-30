-- snmp-info.lua — probe SNMP with common community strings and report what's
-- readable. A device answering SNMP v2c to a default community ("public"/
-- "private") is a classic exposure: it leaks system details and, with "private",
-- is often writable. Uses the host-mediated, scope-enforced `pontus.snmp_get`
-- capability (F-021) over UDP 161.
--
-- Needs 161/udp observed, so scan with `--udp-ports 161`. Clean-room (well-known
-- SNMPv2-MIB system OIDs, C-001). Entry point: check(target).

local COMMUNITIES = { "public", "private" }

-- System group scalars worth disclosing if readable.
local SYS = {
  { oid = "1.3.6.1.2.1.1.1.0", name = "sysDescr" },
  { oid = "1.3.6.1.2.1.1.5.0", name = "sysName" },
  { oid = "1.3.6.1.2.1.1.6.0", name = "sysLocation" },
  { oid = "1.3.6.1.2.1.1.4.0", name = "sysContact" },
}

local function snmp_open(target)
  for _, p in ipairs(target.ports) do
    if p.proto == "udp" and p.port == 161 then
      return true
    end
  end
  return false
end

function check(target)
  local out = {}
  if not snmp_open(target) then
    return out -- avoid pointless UDP waits when 161/udp wasn't observed
  end

  for _, community in ipairs(COMMUNITIES) do
    local descr = pontus.snmp_get(target.ip, community, "1.3.6.1.2.1.1.1.0")
    if descr then
      out[#out + 1] = {
        title = "SNMP readable with community '" .. community .. "'",
        severity = "medium",
        description = "SNMP v2c GET succeeded with the default community '" .. community
          .. "' — sysDescr: " .. descr,
        metadata = { community = community },
      }
      for _, s in ipairs(SYS) do
        if s.name ~= "sysDescr" then
          local v = pontus.snmp_get(target.ip, community, s.oid)
          if v and v ~= "" then
            out[#out + 1] = {
              title = s.name .. " disclosed via SNMP",
              severity = "info",
              description = s.name .. ": " .. v,
              metadata = { community = community, oid = s.oid },
            }
          end
        end
      end
      break -- one working community is enough
    end
  end
  return out
end
