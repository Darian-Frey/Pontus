-- smb-enum.lua — list a host's SMB shares over a null (anonymous) session. A host
-- that lets an unauthenticated client enumerate its shares is a classic exposure
-- (information disclosure, often a foothold). Uses the host-mediated
-- `pontus.smb_shares` capability (F-021), which shells out to the user's own
-- `smbclient` (D-006).
--
-- Probes hosts with SMB observed (445/tcp, 139/tcp, or the microsoft-ds /
-- netbios-ssn service). Entry point: check(target).

local function has_smb(target)
  for _, p in ipairs(target.ports) do
    if p.proto == "tcp" and (p.port == 445 or p.port == 139
        or p.service == "microsoft-ds" or p.service == "netbios-ssn") then
      return true
    end
  end
  return false
end

function check(target)
  local out = {}
  if not has_smb(target) then
    return out
  end
  local ok, shares = pcall(pontus.smb_shares, target.ip)
  if not ok or not shares or #shares == 0 then
    return out -- access denied / not SMB / unreachable
  end

  out[#out + 1] = {
    title = "Anonymous SMB share enumeration allowed",
    severity = "medium",
    description = "A null (unauthenticated) session listed " .. tostring(#shares)
      .. " share(s) on this host.",
    metadata = { shares = tostring(#shares) },
  }
  for _, s in ipairs(shares) do
    local desc = (s.comment ~= "" and s.comment) or (s.kind .. " share")
    out[#out + 1] = {
      title = "SMB share: " .. s.name .. " (" .. s.kind .. ")",
      severity = "info",
      description = desc,
      metadata = { name = s.name, kind = s.kind },
    }
  end
  return out
end
