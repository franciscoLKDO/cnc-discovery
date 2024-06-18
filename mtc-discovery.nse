local slaxml = require "slaxml"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"

description = [[
    Attemp to get mtconnect agent version and list devices/cnc machines linked to this agent
]]

---
--@usage
-- nmap --script mtc-discovery x.x.x.x -p 5000
--
--@output
-- 5000/tcp open  unknown
-- | mtc-discovery:
-- |   agent-version: 1.4.0.12
-- |   devices:
-- |
-- |       manufacturer: Mazak_Corporation
-- |       serialNumber: 304141
-- |_      name: MFMS10-MC2

-- TODO: Add events listing

author = "franciscoLKDO"

categories = { "discovery", "safe" }

-- Write callbacks for xml parser
local startElement = {
    -- Get mtconnect agent version from header tag
    Header = function(agent)
        agent.parser._call.attribute = function(name, attribute)
            if name == "version" then
                agent.version = attribute
            end
        end
    end,
    -- List devices in devices tag
    Devices = function(agent)
        agent.devices = {}
        agent.device = {}
    end,
    -- Get device name in device tag
    Device = function(agent)
        agent.parser._call.attribute = function(name, value)
            -- Assume the first attribute name is the device name,
            -- pass if set to avoid catching other nested tags attribute names
            if not agent.device.name and name == "name" then
                agent.device.name = value
            end
        end
    end,
    -- Get device manufacturer and serialNumber in device description tag
    Description = function(agent)
        agent.parser._call.attribute = function(name, value)
            if name == "manufacturer" or name == "serialNumber" then
                agent.device[name] = value
            end
        end
    end,
}

local clean_attribute = function(agent)
    agent.parser._call.attribute = nil
end

local closeElement = {
    -- Clean attribute function
    Header = clean_attribute,
    -- Clean attribute function
    Devices = clean_attribute,
    -- Clean attribute function
    Device = clean_attribute,
    -- Add device to list and clean
    Description = function(agent)
        table.insert(agent.devices, agent.device)
        agent.device = {}
        clean_attribute(agent)
    end,
}



local PATH = "/probe"
-- Maybe use a script-args for options
local options = {
    timeout = 10000,
    header = {
        Accept = "text/xml",
        ["User-Agent"] = "Mozilla/5.0"
    },
}

portrule = function(_, port)
    return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
    local agent = {
        version = "",
        devices = {}
    }
    local res = http.get(host, port, PATH, options)

    -- Quit if response status failed
    if res.status >= 400 then
        return
    end
    
    --Check if element callback exist and execute or pass
    local execute_callback = function(cb, name)
        return cb[name] and cb[name](agent) or nil
    end
    -- Assign callbacks to parser
    agent.parser = slaxml.parser:new({
        startElement = function(name)
            execute_callback(startElement, name)
        end,
        closeElement = function(name)
            execute_callback(closeElement, name)
        end,
    })
    -- Parse response body
    agent.parser:parseSAX(res.body)

    -- Generate result
    local output = stdnse.output_table()
    output["agent-version"] = agent.version or ""
    output.devices = agent.devices or {}
    return output
end
