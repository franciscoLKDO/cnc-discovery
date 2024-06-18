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
            if not agent.device.name and name == "name" then
                agent.device.name = value
            end
        end
    end,
    -- Get device manufacturer and serialNumber in device description tag
    Description = function(agent)
        agent.parser._call.attribute = function(name, value)
            if name == "manufacturer" then
                agent.device.manufacturer = value
            end
            if name == "serialNumber" then
                agent.device.serialNumber = value
            end
        end
    end,
}

local closeElement = {
    -- Clean attribute function
    Header = function(agent)
        agent.parser._call.attribute = nil
    end,
    -- Clean attribute function
    Devices = function(agent)
        agent.parser._call.attribute = nil
    end,
    -- Clean attribute function
    Device = function(agent)
        agent.parser._call.attribute = nil
    end,
    -- Add device to list and clean
    Description = function(agent)
        table.insert(agent.devices, agent.device)
        agent.device = {}
        agent.parser._call.attribute = nil
    end,
}


local output = stdnse.output_table()
local path = "/probe"

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
    local agent = {
        version = "",
        devices = {}
    }
    -- Maybe use a script-args for options
    local options = {
        timeout = 10000,
        header = {
            Accept = "text/xml",
            ["User-Agent"] = "Mozilla/5.0" 
        },
    }
    local res = http.get(host, port, path, options)
    
    -- Quit if response status failed
    if res.status > 400 then
        return 
    end
    -- Assign callbacks to parser
    agent.parser = slaxml.parser:new({
        startElement = function(name)
            return startElement[name] and startElement[name](agent) or nil
        end,
        closeElement = function(name)
            return startElement[name] and closeElement[name](agent) or nil
        end,
    })
    -- Parse response body
    agent.parser:parseSAX(res.body)

    -- Generate result
    output["agent-version"] = agent.version or ""
    output.devices = agent.devices or {}
    
    return output
end
