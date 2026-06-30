-- http-header-audit.lua — actively fetch each HTTP(S) endpoint and flag missing
-- security headers and software disclosure. This is a *probing* plugin: it uses
-- the host-mediated, scope-enforced `pontus.http_get` capability (F-021), so it
-- only ever contacts hosts already in the scan's scope.
--
-- Clean-room (well-known HTTP security headers, C-001). Entry point: check(target).

local HTTP_PORTS = { [80] = "http", [8080] = "http", [8000] = "http", [443] = "https", [8443] = "https" }

local function add(out, port, title, sev, desc)
  out[#out + 1] = { title = title, severity = sev, description = desc, metadata = { port = tostring(port) } }
end

function check(target)
  local out = {}
  for _, p in ipairs(target.ports) do
    local scheme = (p.proto == "tcp") and HTTP_PORTS[p.port] or nil
    if scheme then
      local url = scheme .. "://" .. target.ip .. ":" .. p.port .. "/"
      -- pcall: an unreachable/out-of-scope endpoint must not abort the whole plugin.
      local ok, r = pcall(pontus.http_get, url)
      if ok and r and r.headers then
        local h = r.headers
        if scheme == "https" and not h["strict-transport-security"] then
          add(out, p.port, "HSTS not set", "low",
              "HTTPS endpoint sends no Strict-Transport-Security header.")
        end
        if not h["content-security-policy"] then
          add(out, p.port, "No Content-Security-Policy", "low",
              "No Content-Security-Policy header — weaker XSS/injection defences.")
        end
        if not h["x-content-type-options"] then
          add(out, p.port, "X-Content-Type-Options missing", "info",
              "Missing `X-Content-Type-Options: nosniff`.")
        end
        if not h["x-frame-options"] and not h["content-security-policy"] then
          add(out, p.port, "Clickjacking defences missing", "info",
              "Neither X-Frame-Options nor a CSP frame-ancestors directive is set.")
        end
        if h["server"] and h["server"] ~= "" then
          add(out, p.port, "Server header discloses software", "info", "Server: " .. h["server"])
        end
        if h["x-powered-by"] then
          add(out, p.port, "X-Powered-By discloses software", "info", "X-Powered-By: " .. h["x-powered-by"])
        end
      end
    end
  end
  return out
end
