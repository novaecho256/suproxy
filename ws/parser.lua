local bit = require "bit"

local P=require "strmproxy.ws.packets"
local parser=require("strmproxy.parser")

local byte = string.byte
local band = bit.band

local _M={}

-- only define the parsers that are needed to parse in the Websocket protocol
local conf={
  {key=P.PktType.Continuation, parserName="Continuation",    parser=P.Continuation,    eventName="ContinuationEvent"},
  {key=P.PktType.Text, parserName="Text",    parser=P.Text,    eventName="TextEvent"},
  {key=P.PktType.Binary, parserName="Binary",    parser=P.Binary,    eventName="BinaryEvent"},
  {key=P.PktType.Close, parserName="Close",    parser=P.Close,    eventName="CloseEvent"},
  {key=P.PktType.Ping, parserName="Ping",    parser=P.Ping,    eventName="PingEvent"},
  {key=P.PktType.Pong, parserName="Pong",    parser=P.Pong,    eventName="PongEvent"},
}

local KeyG=function(allBytes)
  return band(byte(allBytes, 1), 0x0f)
end

function _M:new()
  local o= setmetatable({},{__index=self})
  local C2PParser=parser:new()
  C2PParser.keyGenerator=keyG
  C2PParser:registerMulti(conf)
  C2PParser:registerDefaultParser(P.Base)
  o.C2PParser=C2PParser

  local S2PParser=parser:new()	
  S2PParser.keyGenerator=keyG
  S2PParser:registerMulti(conf)
  S2PParser:registerDefaultParser(P.Base)
  o.S2PParser=S2PParser
  return o
end

return _M