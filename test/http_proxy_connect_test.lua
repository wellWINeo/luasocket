package.path = "src/?.lua;" .. package.path
local unpack = table.unpack or unpack

local socket = {
    sourcet = {},
    sinkt = {},
    tcp_calls = 0
}

function socket.tcp()
    socket.tcp_calls = socket.tcp_calls + 1
    return {}
end

function socket.try(value, message)
    if not value then error(message, 0) end
    return value
end

function socket.protect(f)
    return function(...)
        local result = { pcall(f, ...) }
        if not result[1] then return nil, result[2] end
        table.remove(result, 1)
        return unpack(result)
    end
end

function socket.skip(count, ...)
    return select(count + 1, ...)
end

package.preload["socket"] = function() return socket end
package.preload["ltn12"] = function()
    return {
        source = { empty = function() return function() end end },
        sink = { null = function() return function() end end },
        pump = {}
    }
end
package.preload["mime"] = function()
    return { b64 = function(value) return value end }
end
package.preload["socket.headers"] = function()
    return { canonic = {} }
end
package.preload["socket.url"] = function()
    return assert(loadfile("src/url.lua"))()
end
package.preload["socket.http"] = function()
    return assert(loadfile("src/http.lua"))()
end

local https_state = { calls = 0 }
package.preload["ssl.https"] = function()
    return {
        PROXY_TUNNEL = true,
        tcp = function(params)
            https_state.calls = https_state.calls + 1
            https_state.params = params
            return function()
                https_state.created = https_state.created + 1
                return { kind = "https" }
            end
        end
    }
end

local http = require("socket.http")
local state = {}

local function reset(responses)
    state.opens = {}
    state.responses = responses
    state.response_index = 0
    https_state.calls = 0
    https_state.params = nil
    https_state.created = 0
end

http.open = function(host, port, create)
    state.response_index = state.response_index + 1
    local response = state.responses[state.response_index]
    local record = { host = host, port = port, create = create }
    table.insert(state.opens, record)
    record.connection = create()
    function record.connection:sendrequestline(method, uri)
        record.method, record.uri = method, uri
    end
    function record.connection:sendheaders(headers)
        record.headers = headers
    end
    function record.connection:receivestatusline()
        return response.code or 200, response.status
    end
    function record.connection:receiveheaders()
        return response.headers or {}
    end
    function record.connection:receivebody(headers, sink)
        assert(not record.closed, "receivebody called after connection close")
        if response.body then sink(response.body) end
        return 1
    end
    function record.connection:close()
        record.closed = true
    end
    return record.connection
end

local function request(reqt)
    local result, code, headers = http.request(reqt)
    assert(result == 1, tostring(code))
    return code, headers
end

local function assert_equal(actual, expected, message)
    assert(actual == expected,
        (message or "values differ") .. ": expected " .. tostring(expected)
            .. ", got " .. tostring(actual))
end

-- HTTPS origins through HTTP proxies use LuaSec, connect to the proxy, and
-- pass decoded credentials only to the tunnel descriptor.
reset({ { code = 200, headers = {} } })
request {
    url = "https://origin.example/path?q=1",
    proxy = "http://pr%2540xy:p%2521@proxy.example:3128",
    user = "origin",
    password = "secret%21",
    headers = { ["proxy-authorization"] = "caller-must-not-leak" }
}
assert_equal(#state.opens, 1, "automatic tunnel request count")
assert_equal(state.opens[1].host, "proxy.example", "raw destination host")
assert_equal(state.opens[1].port, "3128", "raw destination port")
assert_equal(https_state.calls, 1, "LuaSec creator selection")
local tunnel = https_state.params.proxy_tunnel
assert_equal(tunnel.authorization, "caller-must-not-leak", "explicit CONNECT authorization")
assert_equal(tunnel.host, "origin.example", "tunnel origin host")
assert_equal(tunnel.port, 443, "defaulted tunnel origin port")
assert_equal(tunnel.user, "pr%40xy", "proxy user decoded once")
assert_equal(tunnel.password, "p%21", "proxy password decoded once")
assert_equal(state.opens[1].uri, "/path?q=1", "origin-form request URI")
assert_equal(state.opens[1].headers["proxy-authorization"], nil,
    "proxy authorization isolated to CONNECT")
assert_equal(state.opens[1].headers.authorization, "Basic origin:secret!",
    "origin authorization preserved")

-- An HTTPS redirect gets a fresh tunnel descriptor for its new origin.
reset({
    { code = 302, headers = { location = "https://redirected.example:8443/new" } },
    { code = 200, headers = {} }
})
request {
    url = "https://origin.example/old",
    proxy = "http://proxy.example:8080",
    verify = "peer",
    cafile = "trusted.pem",
    hostflags = "no_wildcards"
}
assert_equal(#state.opens, 2, "redirect tunnel request count")
assert_equal(state.opens[1].host, "proxy.example", "first redirect raw host")
assert_equal(state.opens[2].host, "proxy.example", "second redirect raw host")
assert_equal(https_state.params.proxy_tunnel.host, "redirected.example",
    "redirect tunnel origin host")
assert_equal(tostring(https_state.params.proxy_tunnel.port), "8443",
    "redirect tunnel origin port")
assert_equal(state.opens[2].port, "8080", "redirect proxy dial port")
assert_equal(state.opens[2].uri, "/new", "redirect origin-form URI")
assert_equal(https_state.params.verify, "peer", "redirect TLS verification")
assert_equal(https_state.params.cafile, "trusted.pem", "redirect CA file")
assert_equal(https_state.params.hostflags, "no_wildcards", "redirect host flags")

-- Client identity on a tunneled request returns the original non-302 response.
local delivered_body
reset({ { code = 307, status = "Temporary Redirect", body = "benign body",
    headers = { location = "https://redirected.example/new" } } })
local identity_result, identity_code, identity_headers, identity_status =
    http.request {
        url = "https://origin.example/old",
        proxy = "http://proxy.example:8080",
        certificate = "identity.pem",
        sink = function(chunk) delivered_body = chunk end
    }
assert_equal(identity_result, 1, "identity redirect result")
assert_equal(identity_code, 307, "identity redirect status code")
assert_equal(identity_headers.location, "https://redirected.example/new",
    "identity redirect location")
assert_equal(identity_status, "Temporary Redirect", "identity redirect status")
assert_equal(#state.opens, 1, "identity redirect tunnel count")
assert_equal(delivered_body, "benign body", "identity redirect body delivery")
assert(state.opens[1].closed, "identity redirect connection closed")

-- A caller connector disables automatic classification and all shaping.
local custom_calls = 0
local custom_create = function()
    custom_calls = custom_calls + 1
    return { kind = "custom" }
end
reset({ { code = 200, headers = {} } })
request {
    url = "https://origin.example/custom",
    proxy = "http://user:pass@proxy.example:8080",
    create = custom_create
}
assert_equal(custom_calls, 1, "custom connector escape hatch")
assert_equal(https_state.calls, 0, "custom connector bypasses LuaSec")
assert_equal(state.opens[1].uri, "https://origin.example:443/custom",
    "custom connector preserves proxy URI form")
assert_equal(state.opens[1].headers["proxy-authorization"], "Basic user:pass",
    "custom connector preserves proxy authorization")

-- Direct and ordinary HTTP-proxy requests retain their existing shaping.
reset({ { code = 200, headers = {} } })
request { url = "http://origin.example/direct" }
assert_equal(state.opens[1].host, "origin.example", "direct destination host")
assert_equal(state.opens[1].uri, "/direct", "direct origin-form URI")

reset({ { code = 200, headers = {} } })
request {
    url = "http://origin.example/via-proxy",
    proxy = "http://proxy.example:3128"
}
assert_equal(state.opens[1].host, "proxy.example", "HTTP proxy destination host")
assert_equal(state.opens[1].uri, "http://origin.example:80/via-proxy",
    "HTTP proxy absolute-form URI")

-- Direct HTTPS does not create a proxy tunnel descriptor.
reset({ { code = 200, headers = {} } })
request { url = "https://origin.example/direct" }
assert_equal(https_state.calls, 1, "direct HTTPS creator selection")
assert_equal(https_state.params.proxy_tunnel, nil,
    "direct HTTPS unexpectedly created a proxy tunnel")

-- Unsupported TLS-to-proxy configurations fail instead of falling back.
reset({ { code = 200, headers = {} } })
local result, err = http.request {
    url = "https://origin.example/via-https-proxy",
    proxy = "https://proxy.example:3128"
}
assert_equal(result, nil, "HTTPS proxy unexpectedly succeeded")
assert_equal(err, "unsupported HTTPS proxy", "unsupported scheme error")
assert_equal(#state.opens, 0, "unsupported scheme opened a connection")

print("http proxy CONNECT classification tests: ok")
