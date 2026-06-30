-- ssh-hostkey.lua — record a host's SSH host keys and flag weak/deprecated ones.
-- Host keys are a stable identity signal and an audit point: DSA is deprecated and
-- short RSA keys are weak. Uses the host-mediated `pontus.ssh_hostkey` capability
-- (F-021), which shells out to the user's own `ssh-keyscan`/`ssh-keygen` (D-006).
--
-- Probes any observed SSH port (22/tcp or a port detected as the `ssh` service).
-- Clean-room (well-known key-algorithm policy, C-001). Entry point: check(target).

local function ssh_ports(target)
  local ports = {}
  for _, p in ipairs(target.ports) do
    if p.proto == "tcp" and (p.port == 22 or p.service == "ssh") then
      ports[#ports + 1] = p.port
    end
  end
  return ports
end

function check(target)
  local out = {}
  for _, port in ipairs(ssh_ports(target)) do
    local ok, keys = pcall(pontus.ssh_hostkey, target.ip, port)
    if ok and keys then
      for _, k in ipairs(keys) do
        out[#out + 1] = {
          title = "SSH host key (" .. k.algo .. ")",
          severity = "info",
          description = k.algo .. " " .. tostring(k.bits) .. "-bit host key on port "
            .. tostring(port) .. ": " .. k.fingerprint,
          metadata = { port = tostring(port), algo = k.algo, bits = tostring(k.bits),
                       fingerprint = k.fingerprint },
        }
        local a = string.upper(k.algo)
        if a == "DSA" or a == "DSS" then
          out[#out + 1] = {
            title = "Deprecated SSH host key (DSA)",
            severity = "medium",
            description = "DSA host keys are deprecated and disabled by default in modern OpenSSH.",
            metadata = { port = tostring(port), algo = k.algo },
          }
        elseif a == "RSA" and k.bits > 0 and k.bits < 2048 then
          out[#out + 1] = {
            title = "Weak SSH RSA host key (<2048 bits)",
            severity = "medium",
            description = "RSA host key is only " .. tostring(k.bits) .. " bits; use \u{2265}2048 (or Ed25519).",
            metadata = { port = tostring(port), algo = k.algo, bits = tostring(k.bits) },
          }
        end
      end
    end
  end
  return out
end
