local sub = string.sub
local byte = string.byte
local format = string.format
local tcp = ngx.socket.tcp
local setmetatable = setmetatable
local spawn = ngx.thread.spawn
local wait = ngx.thread.wait
local logger = require "strmproxy.utils.compatibleLog"
local ses = require "strmproxy.session.session"
local cjson = require "cjson"
local event = require "strmproxy.utils.event"
local balancer = require "strmproxy.balancer.balancer"

local _M = {}

_M._VERSION = '0.01'

function _M:new(upstreams, processor, options)
    local o = {}
    options = options or {}
    options.c2pConnTimeout = options.c2pConnTimeout or 10000
    options.c2pSendTimeout = options.c2pSendTimeout or 10000
    options.c2pReadTimeout = options.c2pReadTimeout or 3600000
    options.p2sConnTimeout = options.p2sConnTimeout or 10000
    options.p2sSendTimeout = options.p2sSendTimeout or 10000
    options.p2sReadTimeout = options.p2sReadTimeout or 3600000
    if ngx.var.sockettype == "udp" then
        options.udp = true
    end
    local c2pSock, err = ngx.req.socket(options.raw)
    if not c2pSock then
        return nil, err
    end
    if not options.udp then
        c2pSock:settimeouts(options.c2pConnTimeout, options.c2pSendTimeout, options.c2pReadTimeout)
    end
    local standalone = false
    if (not upstreams) then
        logger.err(format(">[new] no upstream specified, Proxy will run in standalone mode"))
        standalone = true
    end
    local p2sSock = nil
    if (not standalone) then
        if not options.udp then
            p2sSock, err = tcp()
        else
            p2sSock, err = ngx.socket.udp()
        end
        if not p2sSock then
            return nil, err
        end
        if not options.udp then
            p2sSock:settimeouts(options.p2sConnTimeout, options.p2sSendTimeout, options.p2sReadTimeout)
        end
    end
    --add default receive-then-forward processor
    if (not processor and not standalone) then
        processor = {}
        processor.processUpRequest = function(self)
            local data, err, partial = self.channel:c2pRead(1024 * 10)
            --real error happend or timeout
            if not data and not partial and err then return nil, err end
            if (data and not err) then
                return data
            else
                return partial
            end
        end
        processor.processDownRequest = function(self)
            local data, err, partial = self.channel:p2sRead(1024 * 10)
            --real error happend or timeout
            if not data and not partial and err then return nil, err end
            if (data and not err) then
                return data
            else
                return partial
            end
        end
    end
    --add default echo processor if proxy in standalone mode
    if (not processor and standalone) then
        logger.err(format(">[new] not processor and standalone"))
        processor = {}
        processor.processUpRequest = function(self)
            local data, err, partial = self.channel:c2pRead(1024 * 10)
            --real error happend or timeout
            if not data and not partial and err then return nil, err end
            local echodata = ""
            if (data and not err) then
                echodata = data
            else
                echodata = partial
            end
            logger.inf( echodata)
            local _, err = self.channel:c2pSend(echodata)
            logger.err( partial)
        end
    end

    local upForwarder = function(self, data)
        if data then return self.channel:p2sSend(data) end
    end

    local downForwarder = function(self, data)
        if data then return self.channel:c2pSend(data) end
    end

    --add default upforwarder
    processor.sendUp = processor.sendUp or upForwarder
    --add default downforwarder
    processor.sendDown = processor.sendDown or downForwarder

    processor.ctx = processor.ctx or {}

    local sessionInvalidHandler = function(self, session)
        logger.dbg(">[new] session closed")
        self:shutdown()
    end
    --set default session invalid handler
    processor.sessionInvalid = processor.sessionInvalid or sessionInvalidHandler
    --set AuthSuccessEvent handler
    if processor.AuthSuccessEvent then
        processor.AuthSuccessEvent:addHandler(o, function(self, source, username)
            if self.session and username then self.session.uid = username end
        end)
    end
    --update ctx info to session
    if processor.ContextUpdateEvent then
        processor.ContextUpdateEvent:addHandler(o, function(self, source, ctx)
            if ctx and self.session then
                self.session.ctx = ctx
            end
        end)
    end
    o.p2sSock = p2sSock
    o.c2pSock = c2pSock
    o.processor = processor
    o.balancer = upstreams.getBest and upstreams or balancer:new(upstreams)
    o.standalone = standalone
    o.OnConnectEvent = event:new(o, "OnConnectEvent")
    o.sessionMan = options.sessionMan or ses:newDoNothing()
    o.elapsed_start=0
    o.elapsed_end=0
    o.elapsed_time=0
    o.udp = options.udp or false
    setmetatable(o, { __index = self })
    processor.channel = o
    return o
end

local function _cleanup(self)
    logger.dbg(">[_cleanup] clean up executed")
    
    -- make sure buffers are clean
    if not self.udp then
        ngx.flush(true)
    end

    local p2sSock = self.p2sSock
    local c2pSock = self.c2pSock
    if p2sSock ~= nil then
        if p2sSock.shutdown then
            p2sSock:shutdown("send")
        end
        if p2sSock.close ~= nil then
            if not self.udp then
                local ok, err = p2sSock:setkeepalive()
                if not ok then
                    logger.err(format(">[_cleanup] Failed to p2sSock:setkeepalive()"))
                end
            end            
        end
    end
    
    if c2pSock ~= nil then
        if c2pSock.shutdown then
            c2pSock:shutdown("send")
        end
        if c2pSock.close ~= nil then
            local ok, err = c2pSock:close()
            if not ok then
                logger.err(format(">[_cleanup] Failed to c2pSock:close()"))
            end
        end
    end
end

local function _upl(self)
    -- proxy client request to server
    local upstream = self.upstream
    local buf, err, partial

    local session, err = ses:new(self.processor._PROTOCAL, self.sessionMan)
    if err then
        logger.err(format(">[_upl] start session fail: %s:%s, err:%s", upstream.ip, upstream.port, err))
        return
    end
    self.processor.ctx.clientIP   = ngx.var.remote_addr
    self.processor.ctx.clientPort = ngx.var.remote_port
    self.processor.ctx.srvIP      = upstream.ip
    self.processor.ctx.srvPort    = upstream.port
    self.processor.ctx.srvID      = upstream.id
    self.processor.ctx.srvGID     = upstream.gid
    self.processor.ctx.connTime   = ngx.time()
    session.ctx = self.processor.ctx
    self.session = session
    self.OnConnectEvent:trigger({
        clientIP   = session.ctx.clientIP,
        clientPort = session.ctx.clientPort,
        srvIP      = session.ctx.srvIP,
        srvPort    = session.ctx.srvPort
    })

    logger.inf(">[_upl] session processor type: ", self.session.stype)
    while true do
        --todo: sessionMan should notify session change
        if not self.session:valid(self.session) then
            self.processor:sessionInvalid(self.session)
        else
            self.session.uptime = ngx.time()
        end
        logger.inf(">[_upl] client --> proxy start process")
        buf, err, partial = self.processor:processUpRequest(self.standalone)
        if err then
            logger.err(format(">[_upl] processUpRequest fail: %s:%s, err:%s", upstream.ip, upstream.port, err))
            break
        end
        --if in standalone mode, don't forward
        if not self.standalone and buf then
            logger.inf(">_upl()<-sendUp() - self.channel.p2sSend")
            local _, err = self.processor:sendUp(buf)
            if err then
                logger.err(format(">[_upl] forward to upstream fail: %s:%s, err:%s", upstream.ip, upstream.port, err))
                break
            end
        end
    end
    self:shutdown(upstream)
end

local function _dwn(self)
    -- logger.inf(">[_dwn] session processor type: ", self.session.stype)
    local upstream = self.upstream
    -- proxy response to client
    local buf, err, partial
    while true do
        logger.inf(">[_dwn] server --> proxy start process")
        buf, err, partial = self.processor:processDownRequest(self.standalone)
        if err then
            logger.err(format(">[_dwn] processDownRequest fail: %s:%s, err:%s", upstream.ip, upstream.port, err))
            break
        end
        if buf then
            logger.inf(">_dwn()<-sendDown() - self.channel.c2pSend")
            local _, err = self.processor:sendDown(buf)
            if err then
                logger.err(format(">[_dwn] forward to downstream fail: %s:%s, err:%s", upstream.ip, upstream.port, err))
                break
            end
        end
    end
    self:shutdown(upstream)
end

function _M:c2pRead(length)
    -- print(debug.traceback())
    logger.inf(">[c2pPRead] c2pSock:receive (" .. (length == "*l" and length .. ", it means reading a line)" or length .. " bytes)"))
    local bytes, err, partial = self.c2pSock:receive(length)
    -- logger.dbgWithTitle("c2pRead",(bytes and bytes:hex32F() or ""))
    return bytes, err, partial
end

function _M:p2sRead(length)
    -- print(debug.traceback())
    logger.inf(">[p2sRead] p2sSock:receive (" .. length .. " bytes)")
    local bytes, err, partial = self.p2sSock:receive(length)
    -- logger.dbgWithTitle("p2sRead",(bytes and bytes:hex32F() or ""))
    return bytes, err, partial
end

function _M:c2pSend(bytes)
    -- print(debug.traceback())
    logger.inf(">[c2pSend] c2pSock:send")
    -- logger.dbgWithTitle("c2pSend:send",(bytes and bytes:hex32F() or ""))
    return self.c2pSock:send(bytes)
end

function _M:p2sSend(bytes)
    -- print(debug.traceback())
    logger.inf(">[p2sSend] p2sSock:send")
    -- logger.dbgWithTitle("p2sSend:send",(bytes and bytes:hex32F() or ""))
    return self.p2sSock:send(bytes)
end

function _M:run()
    logger.inf(format(">self.standalone: %s", tostring(self.standalone)))
    --this while is to ensure _cleanup will always be executed
    while true do
        local upstream
        if (not self.standalone) then
            while true do
                upstream = self.balancer:getBest()
                if not upstream then
                    logger.err(format(">[run] failed to get avaliable upstream"))
                    break
                end

                local max_attempts = 3
                local ok, err
                -- Retry up to 3 times
                for attempts = 0, max_attempts do
                    if not self.udp then
                        ok, err = self.p2sSock:connect(upstream.ip, upstream.port)
                    else
                        ok, err = self.p2sSock:setpeername(upstream.ip, upstream.port)
                    end
                    if not ok then
                        logger.err(format(">[run] failed to connect to proxy upstream: %s:%s, err:%s", upstream.ip, upstream.port, err))
                        self.balancer:blame(upstream)
                        if attempts < max_attempts then
                            ngx.sleep(1)
                        else
                            logger.err(format(">[run] Attempts exceeded, connection retry terminated"))
                            break
                        end
                    else
                      if upstream.ssl then
                        ok, err = self.p2sSock:sslhandshake(nil, upstream.ip, false)
                        if not ok then
                          logger.err(format(">[run] failed to ssl handshake: %s:%s, err:%s", upstream.ip, upstream.port, err))
                        end
                      end
                      break
                    end
                end
                if not ok then
                    logger.err(format(">[run] failed to connect to proxy upstream after %d attempts: %s:%s", max_attempts, upstream.ip, upstream.port))
                    break
                else
                    logger.inf(format(">[run] connected to proxy upstream: %s:%s", upstream.ip, upstream.port))
                    self.upstream = upstream
                    break
                end
            end
        end
        if not self.standalone and not self.upstream then
            logger.err(format(">[run] standalone: %s, upstream: %s:%s", self.standalone, upstream.ip, upstream.port))
            break
        end
        --_singThreadRun(self)
        logger.inf(">[run]::: SPAWN _upl() :::")
        local co_upl = spawn(_upl, self)
        if (not self.standalone) then
            logger.inf(">[run]::: SPAWN _dwn() :::")
            local co_dwn = spawn(_dwn, self)
            logger.inf(">[run]::: WAIT _dwn() :::")
            wait(co_dwn)
        end
        logger.inf(">[run]::: WAIT _upl() :::")
        wait(co_upl)
        break
    end
    _cleanup(self)
end

function _M:shutdown()
    if self.session then
        --self.processor:sessionInvalid(self.session)
        local err = self.session:kill(self.session)
        if err then
            logger.err(format(">[shutdown] kill session fail: %s:%s, err:%s", self.upstream.ip, self.upstream.port, err))
        end
    end
    _cleanup(self)
end

return _M
