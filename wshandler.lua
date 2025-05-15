local logger = require "strmproxy.utils.compatibleLog"
local sockLogger = require "resty.logger.socket"
local format = string.format

local _M = {}
_M._PROTOCOL = "WS"

if not sockLogger.initted() then
  local ok, err = sockLogger.init {
      -- logger server address
      host        = '127.0.0.1',
      port        = 12080,
      flush_limit = 10,
      drop_limit  = 567800,
  }
  if not ok then
      logger.err("failed to initialize the logger: ", err)
  end
else
  logger.err("logger module already initialized")
end

local function wsLog(data)
  if sockLogger then
      local bytes, err = sockLogger.log(data)
      if err then
          logger.err("failed to log reply: ", err)
      end
  else
      logger.dbg( data)
  end
end

local function OnConnect(context, source, session)
  if session then
      local log = format("[".._M._PROTOCOL .. "] connected from %s:%s to %s:%s\r\n", session.clientIP, session.clientPort, session.srvIP, session.srvPort)
      wsLog(log)
  else
      logger.dbg("session is nil")
  end
end

local function OnHandshakeRequestEvent(context, source, headers)
  local log = format('['.._M._PROTOCOL .. "] Handshake Request: %s %s %s\r\n", 
    headers["req_line"], headers["Connection"], headers["Upgrade"])
  logger.dbg("[" .. _M._PROTOCOL .. " ] ", log)
  wsLog(log)
end

local function OnHandshakeResponseEvent(context, source, headers)
  local log = format('['.._M._PROTOCOL .. "] Handshake Response: %s %s %s\r\n",
  headers["resp_line"], headers["Connection"], headers["Upgrade"])
  logger.dbg("[" .. _M._PROTOCOL .. " ] ", log)
  wsLog(log)
end

local function OnFrameEvent(context, source, frame)
  local log
  local packet = frame.packet
  if frame.up then
    log = format('['.._M._PROTOCOL .. "] %s:%s sent \t\t[%s]   %s\r\n",
      source.ctx.clientIP, source.ctx.clientPort, 
      packet.opcode, packet.payload)
  else
    log = format('['.._M._PROTOCOL .. "] received from %s:%s \t[%s]   %s\r\n",
      source.ctx.srvIP, source.ctx.srvPort,
      packet.opcode, packet.payload)
  end

  logger.dbg("[" .. _M._PROTOCOL .. " ] ", log)
  wsLog(log)
end

_M.OnConnect = OnConnect
_M.OnHandshakeRequestEvent = OnHandshakeRequestEvent
_M.OnHandshakeResponseEvent = OnHandshakeResponseEvent
_M.OnFrameEvent = OnFrameEvent

return _M