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
-- |    agent-version: 1.4.0.12
-- |    devices:
-- |       name:   MFMS10-MC2
-- |       serialNumber:   304141
-- |       manufacturer:   Mazak_Corporation
-- |       current:        127.0.0.1:8000/MFMS10-MC2/current
-- |       sample:         127.0.0.1:8000/MFMS10-MC2/sample

-- TODO: Add events listing

author = "franciscoLKDO"

categories = { "discovery", "safe" }

local CURRENT = "current"
local SAMPLE = "sample"
local PROBE = "probe"

local MANUFACTURER = "manufacturer"
local SERIALNUMBER = "serialNumber"
local DEVICE_NAME = "name"


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
            if not agent.device.name and name == DEVICE_NAME then
                agent.device.name = value
            end
        end
    end,
    -- Get device manufacturer and serialNumber in device description tag
    Description = function(agent)
        agent.parser._call.attribute = function(name, value)
            if name == MANUFACTURER or name == SERIALNUMBER then
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
        -- Assume /current and /sample are available
        for _, path in pairs({ CURRENT, SAMPLE }) do
            agent.device[path] = string.format("%s:%s/%s/%s", agent.ip, agent.port, agent.device.name, path)
        end
        table.insert(agent.devices, agent.device)
        agent.device = {}
        clean_attribute(agent)
    end,
}



-- Format nmap output for cli
local format_output = function(output)
    local output_str = string.format("\n   agent-version: %s\n", output.agent_version)

    local keys = { DEVICE_NAME, SERIALNUMBER, MANUFACTURER, CURRENT, SAMPLE }
    output_str = output_str .. "   devices:\n\t"
    for i, device in pairs(output.devices) do        
        for _, key in pairs(keys) do
            device[key] = device[key] or ""
            output_str = output_str .. key .. ": \t" .. device[key] .. "\n\t"
        end
        -- Add new line except for last device
        if i < #output.devices then
            output_str = output_str .. "\n\t"
        end
    end
    return output_str
end

portrule = function(_, port)
    return port.protocol == "tcp" and port.state == "open"
end

-- Maybe use a script-args for options
local options = {
    timeout = 10000,
    header = {
        Accept = "text/xml",
        ["User-Agent"] = "Mozilla/5.0"
    },
}

action = function(host, port)
    local res = http.get(host, port, "/" .. PROBE, options)

    -- Quit if response status failed
    if res.status >= 400 then
        return
    end

    local agent = {
        version = "",
        ip = host.ip,
        port = port.number,
        devices = {}
    }

    --Check if element callback exist and execute or pass
    local execute_callback = function(cb)
        return function(name)
            return cb[name] and cb[name](agent) or nil
        end
    end

    -- Assign callbacks to parser
    agent.parser = slaxml.parser:new({
        startElement = execute_callback(startElement),
        closeElement = execute_callback(closeElement)
    })
    -- Parse response body
    agent.parser:parseSAX(res.body)

    -- Generate result
    local output = stdnse.output_table()
    output.agent_version = agent.version or ""
    output.devices = agent.devices or {}
    return output, format_output(output)
end
