require "strmproxy.utils.stringUtils"
require "strmproxy.utils.pureluapack"
local tableUtils=require "strmproxy.utils.tableUtils"
local extends=tableUtils.extends
local orderTable=tableUtils.OrderedTable
local bit = require "bit"
local ffi = require "ffi"
local zlib = require("zlib")

local byte = string.byte
local char = string.char
local sub = string.sub
local band = bit.band
local bor = bit.bor
local bxor = bit.bxor
local lshift = bit.lshift
local rshift = bit.rshift
local rand = math.random
local ffi_new = ffi.new
local ffi_string = ffi.string

local _M={}

--Packet type defines, only the type that have been implemented are listed
_M.PktType={
  Continuation = 0x0,
  Text         = 0x1,
  Binary       = 0x2,
  Close        = 0x8,
  Ping         = 0x9,
  Pong         = 0xA,
}

local str_buf_size = 4096
local str_buf
local c_buf_type = ffi.typeof("char[?]")

local function get_string_buf(size)
  if size > str_buf_size then
      return ffi_new(c_buf_type, size)
  end
  if not str_buf then
      str_buf = ffi_new(c_buf_type, str_buf_size)
  end

  return str_buf
end

_M.Base = {
  parse = function(self, allBytes, pos, data)
    self.allBytes=allBytes
    self:parsePayload(allBytes, pos, data)
    return self
  end,

  parsePayload = function(self, allBytes, pos, data)
    local fst, snd = byte(allBytes, 1, 2)
    self.opcode = band(fst, 0x0f)
    self.fin = band(fst, 0x80) ~= 0
    self.mask = band(snd, 0x80) ~= 0
    
    if self.mask then
      local payload_len = #data - 4
      -- TODO string.buffer optimizations
      local bytes = get_string_buf(payload_len)
      for i = 1, payload_len do
          bytes[i - 1] = bxor(byte(data, 4 + i),
                              byte(data, (i - 1) % 4 + 1))
      end
      self.payload = ffi_string(bytes, payload_len)
    else
      self.payload = data
    end

    return self
  end,

  pack = function (self)
    self.allBytes = self:packPayload()
    return self
  end,

  packPayload = function (self)
    local fst
    if self.fin then
      fst = bor(0x80, self.code)
    else
      fst = self.code
    end

    local payload_len = #self.payload
    local snd, extra_len_bytes
    if payload_len <= 125 then
        snd = payload_len
        extra_len_bytes = ""

    elseif payload_len <= 65535 then
        snd = 126
        extra_len_bytes = char(band(rshift(payload_len, 8), 0xff),
                               band(payload_len, 0xff))

    else
        if band(payload_len, 0x7fffffff) < payload_len then
            return nil, "payload too big"
        end

        snd = 127
        -- XXX we only support 31-bit length here
        extra_len_bytes = char(0, 0, 0, 0, band(rshift(payload_len, 24), 0xff),
                               band(rshift(payload_len, 16), 0xff),
                               band(rshift(payload_len, 8), 0xff),
                               band(payload_len, 0xff))
    end

    local masking_key
    if self.mask then
        -- set the mask bit
        snd = bor(snd, 0x80)
        local key = rand(0xffffffff)
        masking_key = char(band(rshift(key, 24), 0xff),
                           band(rshift(key, 16), 0xff),
                           band(rshift(key, 8), 0xff),
                           band(key, 0xff))

        -- TODO string.buffer optimizations
        local bytes = get_string_buf(payload_len)
        for i = 1, payload_len do
            bytes[i - 1] = bxor(byte(self.payload, i),
                                byte(masking_key, (i - 1) % 4 + 1))
        end
        self.payload = ffi_string(bytes, payload_len)

    else
        masking_key = ""
    end

    return char(fst, snd) .. extra_len_bytes .. masking_key .. self.payload
  end,

  new=function(self,o) 
    local o=o or {}
    return orderTable.new(self,o)
  end
}

_M.Continuation={
  code=_M.PktType.Continuation,
}
extends(_M.Continuation,_M.Base)

_M.Text={
  code=_M.PktType.Text,
}
extends(_M.Text,_M.Base)

_M.Binary={
  code=_M.PktType.Binary,
}
extends(_M.Binary,_M.Base)

_M.Close={
  code=_M.PktType.Close,
}
extends(_M.Close,_M.Base)

_M.Ping={
  code=_M.PktType.Ping,
}
extends(_M.Ping,_M.Base)

_M.Pong={
  code=_M.PktType.Pong,
}
extends(_M.Pong,_M.Base)

return _M