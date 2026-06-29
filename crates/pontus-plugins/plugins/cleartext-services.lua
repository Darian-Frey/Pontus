-- cleartext-services.lua — flag services that carry data or credentials in the
-- clear, so they stand out in the inventory. Clean-room: this is well-known
-- port/protocol knowledge, not derived from any third-party dataset (C-001).
--
-- A Pontus first-party plugin (F-020/F-021). Entry point: check(target).

local CLEARTEXT = {
  [21]   = { name = "FTP",    sev = "high",   note = "credentials and data sent in cleartext; use SFTP/FTPS" },
  [23]   = { name = "Telnet", sev = "high",   note = "credentials sent in cleartext; use SSH" },
  [25]   = { name = "SMTP",   sev = "low",    note = "ensure STARTTLS is enforced" },
  [80]   = { name = "HTTP",   sev = "low",    note = "unencrypted web traffic; prefer HTTPS" },
  [110]  = { name = "POP3",   sev = "medium", note = "mail credentials in cleartext without TLS" },
  [143]  = { name = "IMAP",   sev = "medium", note = "mail credentials in cleartext without TLS" },
  [161]  = { name = "SNMP",   sev = "medium", note = "v1/v2c community strings are unauthenticated and cleartext" },
  [389]  = { name = "LDAP",   sev = "medium", note = "directory credentials in cleartext; use LDAPS" },
  [512]  = { name = "rexec",  sev = "high",   note = "legacy r-service; cleartext and deprecated" },
  [513]  = { name = "rlogin", sev = "high",   note = "legacy r-service; cleartext and deprecated" },
  [514]  = { name = "rsh",    sev = "high",   note = "legacy r-service; cleartext and deprecated" },
  [5900] = { name = "VNC",    sev = "medium", note = "remote desktop, frequently weakly authenticated/unencrypted" },
  [8080] = { name = "HTTP",   sev = "low",    note = "unencrypted web traffic (alt port); prefer HTTPS" },
}

function check(target)
  local out = {}
  for _, p in ipairs(target.ports) do
    if p.proto == "tcp" then
      local c = CLEARTEXT[p.port]
      if c then
        out[#out + 1] = {
          title = c.name .. " exposed (cleartext)",
          severity = c.sev,
          description = "Port " .. p.port .. "/tcp — " .. c.note,
          metadata = { port = tostring(p.port), service = c.name },
        }
      end
    end
  end
  return out
end
