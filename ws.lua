require "strmproxy.utils.stringUtils"
require "strmproxy.utils.pureluapack"
local event=require "strmproxy.utils.event"
local logger=require "strmproxy.utils.compatibleLog"
local format = string.format
local bit = require "bit"
local ffi = require "ffi"

local byte = string.byte
local band = bit.band
local bor = bit.bor
local bxor = bit.bxor
local lshift = bit.lshift
local rshift = bit.rshift
local ffi_string = ffi.string


local _M = {}
_M._PROTOCOL ='ws'

local protocolPacket=require ("strmproxy.".. _M._PROTOCOL .. ".packets")

function _M.new(self, handshake_request)
  local o = setmetatable({},{__index=self})
  o.c2p_stage = "INIT"
  o.c2p_handshake_request = handshake_request
  o.p2s_stage = "INIT"

  o.HandshakeRequestEvent=event:newReturnEvent(o,"HandshakeRequestEvent")
	o.HandshakeResponseEvent=event:newReturnEvent(o,"HandshakeResponseEvent")
  o.FrameEvent=event:newReturnEvent(o,"FrameEvent")
  o.ctx={}

  local parser=require ("strmproxy.".. _M._PROTOCOL ..".parser"):new()
  
  o.C2PParser = parser.C2PParser
  o.C2PParser.events.TextEvent:addHandler(o, self.OnUploadEvent)
  o.C2PParser.events.BinaryEvent:addHandler(o, self.OnUploadEvent)
  o.C2PParser.events.CloseEvent:addHandler(o, self.OnUploadEvent)
  o.C2PParser.events.PingEvent:addHandler(o, self.OnUploadEvent)
  o.C2PParser.events.PongEvent:addHandler(o, self.OnUploadEvent)

  o.S2PParser = parser.S2PParser
  o.S2PParser.events.TextEvent:addHandler(o, self.OnDownloadEvent)
  o.S2PParser.events.BinaryEvent:addHandler(o, self.OnDownloadEvent)
  o.S2PParser.events.CloseEvent:addHandler(o, self.OnDownloadEvent)
  o.S2PParser.events.PingEvent:addHandler(o, self.OnDownloadEvent)
  o.S2PParser.events.PongEvent:addHandler(o, self.OnDownloadEvent)

  return o
end


local function parse_handshake(headers)
  local handshake = {}
  
  -- Split headers by newlines
  for line in headers:gmatch("[^\r\n]+") do
      local key, value = line:match("^(%S+):%s*(.+)$")
      if key and value then
          handshake[key] = value
      end
  end
  
  return handshake
end

local function readHandshakeRequest(self, sock)
  local req_line, err
  local headers = {}
  
  -- Read the HTTP request from the client
  req_line, err = sock:receive("*l")
  if err then return nil,nil,err end

  -- Read headers until an empty line is encountered
  while true do
    local line = sock:receive("*l")
    if line == "" then break end
    headers[#headers + 1] = line
  end

  -- Combine headers into a single string
  local headers_string = table.concat(headers, "\r\n")

  -- Parse the handshake headers
  local handshake = parse_handshake(headers_string)
    
  -- Check for required headers
  if handshake["Upgrade"] and handshake["Connection"]:lower():find("upgrade") then
    handshake["Host"] = self.channel.upstream.ip
    if self.channel.upstream.ssl then
      handshake["Host"]=handshake["Host"]..
        (self.channel.upstream.port ~= 443 and ":"..self.channel.upstream.port or "")
    else
      handshake["Host"]=handshake["Host"]..
        (self.channel.upstream.port ~= 80 and ":"..self.channel.upstream.port or "")
    end

    handshake["Sec-WebSocket-Extensions"] = nil

    headers_string = ""
    for key, value in pairs(handshake) do
      headers_string=headers_string..key..": "..value.."\r\n"
    end
  else
    -- Handle invalid handshake
    err ="HTTP/1.1 400 Bad Request\r\n"..headers_string
  end

  handshake["req_line"] = req_line
  local allBytes = req_line.."\r\n"..headers_string.."\r\n"

  return allBytes, handshake, err
end

local function readHandshakeResponse(self, sock)
  local resp_line, err
  local headers = {}

  -- Read the HTTP response from the server
  resp_line, err = sock:receive("*l")
  if err then return nil,nil,err end

  -- Read headers until an empty line is encountered
  while true do
    local line = sock:receive("*l")
    if line == "" then break end
    headers[#headers + 1] = line
  end

  -- Combine headers into a single string
  local headers_string = table.concat(headers, "\r\n")
  
  -- Parse the handshake headers
  local handshake = parse_handshake(headers_string)
  
  -- Check for required headers
  if handshake["Upgrade"] and handshake["Connection"]:lower():find("upgrade") then
  else
    -- Handle invalid handshake
    err ="HTTP/1.1 400 Bad Request\r\n"..headers_string
  end

  handshake["resp_line"] = resp_line
  local allBytes = resp_line.."\r\n"..headers_string.."\r\n\r\n"

  return allBytes, handshake, err
end

---------------parser event handlers----------------------
function _M:OnUploadEvent(source, packet)
  self.FrameEvent:trigger({packet=packet, up=true}, self.ctx)
end

function _M:OnDownloadEvent(source, packet)
  self.FrameEvent:trigger({packet=packet, up=false}, self.ctx)
end

---------------receive and parse packet----------------------
local function recv(self, readMethod, max_payload_len, force_masking, up)
  local allBytes

  local data, err = readMethod(self.channel, 2)
  if not data then
      return nil, "failed to receive the first 2 bytes: " .. err
  end

  allBytes = data

  local fst, snd = byte(data, 1, 2)
  local fin = band(fst, 0x80) ~= 0
  -- print("fin: ", fin)

  -- if band(fst, 0x70) ~= 0 then
  --     return nil, "bad RSV1, RSV2, or RSV3 bits"
  -- end

  local opcode = band(fst, 0x0f)
  -- print("opcode: ", tohex(opcode))

  if opcode >= 0x3 and opcode <= 0x7 then
      return nil, "reserved non-control frames"
  end

  if opcode >= 0xb and opcode <= 0xf then
      return nil, "reserved control frames"
  end

  local mask = band(snd, 0x80) ~= 0

  if force_masking and not mask then
    return nil, "frame unmasked"
  end

  local payload_len = band(snd, 0x7f)
  -- print("payload len: ", payload_len)

  if payload_len == 126 then
    local data, err = readMethod(self.channel, 2)
    if not data then
        return nil, "failed to receive the 2 byte payload length: "
                         .. (err or "unknown")
    end

    allBytes = allBytes..data

    payload_len = bor(lshift(byte(data, 1), 8), byte(data, 2))

  elseif payload_len == 127 then
    local data, err = readMethod(self.channel, 8)
    if not data then
        return nil, "failed to receive the 8 byte payload length: "
                         .. (err or "unknown")
    end

    allBytes = allBytes..data

    if byte(data, 1) ~= 0
       or byte(data, 2) ~= 0
       or byte(data, 3) ~= 0
       or byte(data, 4) ~= 0
    then
        return nil, "payload len too large"
    end

    local fifth = byte(data, 5)
    if band(fifth, 0x80) ~= 0 then
        return nil, "payload len too large"
    end

    payload_len = bor(lshift(fifth, 24),
                      lshift(byte(data, 6), 16),
                      lshift(byte(data, 7), 8),
                      byte(data, 8))
  end

  if band(opcode, 0x8) ~= 0 then
    -- being a control frame
    if payload_len > 125 then
        return nil, "too long payload for control frame"
    end

    if not fin then
        return nil, "fragmented control frame"
    end
  end

  -- print("payload len: ", payload_len, ", max payload len: ",
        -- max_payload_len)

  if payload_len > max_payload_len then
      return nil, "exceeding max payload len"
  end

  local rest
  if mask then
      rest = payload_len + 4
  else
      rest = payload_len
  end
  -- print("rest: ", rest)

  local data
  if rest > 0 then
      data, err = readMethod(self.channel, rest)
      if not data then
          return nil, "failed to read masking-len and payload: "
                           .. (err or "unknown")
      end

      allBytes = allBytes..data
  else
      data = ""
  end

  -- print("received rest")

  if opcode == 0x8 then
    -- being a close frame
    if payload_len > 0 then
        if payload_len < 2 then
            return nil, "close frame with a body must carry a 2-byte"
                             .. " status code"
        end
    end
  end

  local parser = up and self.C2PParser or self.S2PParser
  local packet, err = parser:parse(allBytes, nil, opcode, data)
  return packet, err
end

function _M.processUpRequest(self)

  if self.c2p_stage == "INIT" then

    local allBytes, handshake, err
    
    if self.c2p_handshake_request then
      allBytes = self.c2p_handshake_request
      handshake = parse_handshake(allBytes)
    else
      allBytes, handshake, err = readHandshakeRequest(self, self.channel.c2pSock)
      if err then
        logger.err("Websocket>: -- Failed to read handshake request: ", err)
        return nil,err
      end
    end
    logger.dbg("Websocket>: readHandshakeRequest()")
    self.c2p_stage = "HANDSHAKE"
    self.HandshakeRequestEvent:trigger(handshake, self.ctx)
    return allBytes

  else

    local packet, err = recv(self, self.channel.c2pRead, 65536, false, true)
    if err then return nil,err end
    return packet.allBytes

      -- TEST: we can block/replace data payload
      -- TODO: check if this is the correct way to do this
      -- local c2pPacket = self.C2PParser.parserList[packet.code].parser:new({
      --   fin=packet.fin,
      --   mask=packet.mask,
      --   payload=packet.payload ... "[777]"
      -- }):pack()
      -- self:sendUp(c2pPacket.allBytes)
      -- return

  end

end



function _M.processDownRequest(self)

  if self.p2s_stage == "INIT" then

    logger.dbg("Websocket>: readHandshakeResponse()")
    local allBytes, handshake, err = readHandshakeResponse(self, self.channel.p2sSock)
    if err then
      logger.err("Websocket>: -- Failed to read handshake response: ", err)
      return nil,err
    end
    self.p2s_stage = "OK"
    self.c2p_stage = "OK"
    self.HandshakeResponseEvent:trigger(handshake, self.ctx)
    return allBytes

  else
    
    local packet, err = recv(self, self.channel.p2sRead, 65536, false, false)
    if err then return nil,err end
    return packet.allBytes

      -- TEST: we can block/replace data payload
      -- TODO: check if this is the correct way to do this
      -- local s2pPacket = self.S2PParser.parserList[packet.code].parser:new({
      --   fin=packet.fin,
      --   mask=packet.mask,
      --   payload=packet.payload .. "[888]"
      -- }):pack()
      -- self:sendDown(s2pPacket.allBytes)
      -- return
  end
end


return _M