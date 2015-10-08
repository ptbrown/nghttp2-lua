
local ffi = require"ffi"
local lib = require"libnghttp2"

local nghttp2 = {
    session = {},
    stream = {},
    hddeflate = {},
    hdinflate = {}
}

local session_ct, stream_ct, hddeflate_ct, hdinflate_ct

-- Converts the internal status to a string
local function error_success(error_code)
    if error_code ~= 0 then
        return false, ffi.string(lib.nghttp2_strerror(error_code)), tonumber(error_code)
    end
    return true
end

-- Converts a return that may be an error
local function error_result(result, convert)
    if result < 0 then
        return nil, ffi.string(lib.nghttp2_strerror(result)), tonumber(result)
    end
    return convert and convert(result) or result
end

--- Get the library version information.
--  Returns the version of the nghttp2 library and the protocol
--  string that it implements.
--  A minimum version number can be supplied and the function will
--  return `nil` if the current library is older than the version
--  you require.
--  @param  least_version   The minimum required version number.
--  @return Version as a number.
--  @return Version as a string.
--  @return Protocol version ID string.
function nghttp2.version(least_version)
    least_version = least_version or 0
    local info = lib.nghttp2_version(least_version)
    if info == nil then
        return nil
    end
    return info.version_num, ffi.string(info.version_str), ffi.string(info.proto_str)
end

--- Check if an error code is fatal.
--  @param  lib_error_code  Number of the error code.
--  @return True if it is a fatal error.
function nghttp2.is_fatal(lib_error_code)
    return 0 ~= lib.nghttp2_is_fatal(tonumber(lib_error_code))
end

--- Convert an error code to a string.
--  @param  error_code  The error code number.
--  @return String description of the error.
function nghttp2.strerror(error_code)
    return ffi.string(lib.nghttp2_strerror(tonumber(error_code)))
end

--- Verifies that a string is a valid HTTP header field name.
--  @param  name    The string to check.
--  @return True if the string can be used as a header name.
function nghttp2.check_header_name(name)
    assert(type(name) == 'string', "Argument must be a string")
    return 0 ~= lib.nghttp2_check_header_name(name, #name)
end

--- Verifies that a string is a valid HTTP header value.
--  @param  value   The string to check.
--  @return True if the string can be used as a header value.
function nghttp2.check_header_value(value)
    assert(type(name) == 'string', "Argument must be a string")
    return 0 ~= lib.nghttp2_check_header_value(value, #value)
end

-- Convert a setting name to the enum value
local function settings_key_id(name)
    if type(name) == 'number' then
        if name > 0 and name < lib.NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE then
            return name
        else
            return nil
        end
    end
    local enumname = "NGHTTP2_SETTINGS_" .. string.upper(name)
    return lib[enumname]
end

-- Takes a table of key/value settings and creates a C array
-- Unknown keys are ignored. Values that are not numbers will
-- cause the function to return `nil` so the caller can fail
-- gracefully.
local function create_settings(settings)
    local converted = {}
    local niv = 0
    for name, value in pairs(settings) do
        local id = settings_key_id(name)
        if id then
            if converted[id] == nil then
                niv = niv + 1
            end
            value = tonumber(value)
            if not value then
                return nil
            end
            converted[id] = tonumber(value)
        end
    end
    local iv = ffi.new("nghttp2_settings_entry[?]", niv)
    niv = 0
    for id, value in pairs(converted) do
        iv[niv].settings_id = id
        iv[niv].value = value
        niv = niv + 1
    end
    return iv, niv
end

--- Serialize values for the HTTP2-Settings header.
--  Settings are written in a table using keys. A key name is
--  the name from the `nghttp2_settings_id` enum converted to
--  lower-case and without the "NGHTTP2_SETTINGS_" prefix.
--  @param  settings The settings table.
--  @return Packed string.
function nghttp2.pack_settings_payload(settings)
    local iv, niv = create_settings(settings)
    if not iv then
        return nil, "Invalid values in settings table"
    end
    local buflen = 8 * niv
    local buf = ffi.new("uint8_t[?]", buflen)
    buflen = lib.nghttp2_pack_settings_payload(buf, buflen, iv, niv)
    if buflen < 0 then
        return nil, ffi.string(lib.nghttp2_strerror(buflen)), buflen
    end
    return ffi.string(buf, buflen)
end

local session_registry = setmetatable({}, { __mode = "kv" })
local data_source_registry = setmetatable({}, { __mode = "k" })

local function session_ref(session)
    session_registry[session._ptr] = session
    data_source_registry[session] = {}
end

local function session_unref(session)
    session_registry[session._ptr] = nil
    data_source_registry[session] = nil
end

local function data_source_ref(session, source)
    if not data_source_registry[session] then
        data_source_registry[session] = {}
    end
    local reg = data_source_registry[session]
    local ref = #reg + 1
    reg[ref] = source
    return ref
end

local function data_source_read(session, stream_id, buf, length, data_flags, source, user_data)
    session = session_registry[session]
    if not session then
        return lib.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE
    end
    source = data_source_registry[session][source.fd]
    if not source then
        return lib.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE
    end
    local data, flags, error_code = source(session, stream_id, length)
    ffi.copy(buf, data, #data)
    return #data
end

local function create_data_provider(session, source)
    local data_prd = ffi.new("nghttp2_data_provider[1]", { source_t })
    data_prd[0].source.fd = data_source_ref(session,source)
    data_prd[0].read_callback = data_source_read
    return data_prd
end

-- Make a C callbacks structure using the functions in a table.
-- Will fail if a callback is defined but is not a function.
-- Ignores keys that are not callbacks.
-- FIXME this is wrong, define a single set of library callbacks
-- and dispatch to the actual functions using references. FFI only
-- allows a limited number of callbacks and creating them is expensive.
local function create_callbacks(opts)
    local cb = ffi.new"nghttp2_session_callbacks*[1]"
    local error_code = lib.nghttp2_session_callbacks_new(cb)
    if error_code ~= 0 then
        return nil, error_code
    end
    ffi.gc(cb[0], lib.nghttp2_session_callbacks_del)
    if opts.send then
        if type(opts.send) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_send_callback(cb, opts.send)
    end
    if opts.recv then
        if type(opts.recv) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_recv_callback(cb, opts.recv)
    end
    if opts.on_frame_recv then
        if type(opts.on_frame_recv) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_on_frame_recv_callback(cb, opts.on_frame_recv)
    end
    if opts.on_invalid_frame_recv then
        if type(opts.on_invalid_frame_recv) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(cb, opts.on_invalid_frame_recv)
    end
    if opts.data_chunk_recv then
        if type(opts.data_chunk_recv) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_data_chunk_recv_callback(cb, opts.data_chunk_recv)
    end
    if opts.before_frame_send then
        if type(opts.before_frame_send) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_before_frame_send_callback(cb, opts.before_frame_send)
    end
    if opts.on_frame_send then
        if type(opts.on_frame_send) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_on_frame_send_callback(cb, opts.on_frame_send)
    end
    if opts.on_frame_not_send then
        if type(opts.on_frame_not_send) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_on_frame_not_send_callback(cb, opts.on_frame_not_send)
    end
    if opts.on_stream_close then
        if type(opts.on_stream_close) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_on_stream_close_callback(cb, opts.on_stream_close)
    end
    if opts.on_begin_headers then
        if type(opts.on_begin_headers) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_on_begin_headers_callback(cb, opts.on_begin_headers)
    end
    if opts.on_header then
        if type(opts.on_header) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_on_header_callback(cb, opts.on_header)
    end
    if opts.select_padding then
        if type(opts.select_padding) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_sellect_padding_callback(cb, opts.select_padding)
    end
    if opts.data_source_read_length then
        if type(opts.data_source_read_length) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_data_source_read_length_callback(cb, opts.data_source_read_length)
    end
    if opts.on_begin_frame then
        if type(opts.on_begin_frame) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_on_begin_frame_callback(cb, opts.on_begin_frame)
    end
    if opts.send_data then
        if type(opts.send_data) ~= 'function' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_session_callbacks_set_send_data_callback(cb, opts.send_data)
    end
    return cb
end

local function create_http2_flags(opts)
    local flags = 0
    if opts then
        for _,opt in ipairs(opts) do
            if type(opt) == 'number' then
                flags = flags + opt
            else
                opt = "NGHTTP2_FLAG_" + string.upper(opt)
                if lib[opt] then
                    flags = flags + header_flags[opt]
                end
            end
        end
    end
    return flags
end

local function create_header_flags(opt, ...)
    local flags = 0
    if opt then
        if type(opt) == 'number' then
            flags = flags + opt
        else
            opt = "NGHTTP2_NV_FLAG_" + string.upper(opt)
            if lib[opt] then
                flags = flags + header_flags[opt]
            end
        end
        return flags + create_header_flags(...)
    end
    return flags
end

local function create_header_def(nv, name, value, ...)
    if type(name) ~= 'string' or type(value) ~= 'string' then
        return false
    end
    nv.name = ffi.cast("uint8_t*", name)
    nv.namelen = #name
    nv.value = ffi.cast("uint8_t*", value)
    nv.valuelen = #value
    nv.flags = create_header_flags(...)
    return true
end

local function create_header_table(nv)
    local header = {
        ffi.string(nv.name, nv.namelen),
        ffi.string(nv.value, nv.valuelen)
    }
    if bit.band(nv.flags, lib.NGHTTP2_NV_FLAG_NO_INDEX) ~= 0 then
        header[3] = "no_index"
    end
    return header
end

-- Headers are an array of {name,value,flags...}
-- The only defined flag so far is "sensitive"
local function create_headers(headers)
    local nvlen = #headers
    local nva = ffi.new("nghttp2_nv[?]", nvlen)
    for n = 1,nvlen do
        if not create_header_def(nva[n-1], unpack(headers[n])) then
            return nil
        end
    end
    return nva, nvlen
end

-- Makes a C options structure from table keys.
local function create_options(options)
    local opt = ffi.new"nghttp2_option*[1]"
    local error_code = lib.nghttp2_option_new(opt)
    if error_code ~= 0 then
        return nil, error_code
    end
    ffi.gc(opt[0], lib.nghttp2_option_del)
    if options.no_auto_window_update ~= nil then
        if type(options.no_auto_window_update) ~= 'boolean' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_option_set_no_auto_window_update(opt, options.no_auto_window_update)
    end
    if options.peer_max_concurrent_streams ~= nil then
        local value = tonumber(options.peer_max_concurrent_streams)
        if not value then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_option_set_peer_max_concurrent_streams(opt, value)
    end
    if options.no_recv_client_magic ~= nil then
        if type(options.no_recv_client_magic) ~= 'boolean' then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_option_set_no_recv_client_magic(opt, options.no_recv_client_magic)
    end
    if options.no_http_messaging ~= nil then
        if type(options.no_http_messaging) ~= nil then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_option_set_no_http_messaging(opt, options.no_http_messaging)
    end
    if options.max_reserved_remote_streams ~= nil then
        local value = tonumber(options.max_reserved_remote_streams)
        if not value then
            return nil, lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        lib.nghttp2_option_set_max_reserved_remote_streams(opt, value)
    end
    return opt
end

-- Make a C priority structure from a number or table.
local function create_priority(priority)
    local pri_spec = ffi.new"nghttp2_priority[1]"
    if type(priority) == 'number' then
        pri_spec[0].stream_id = priority
        pri_spec[0].weight = lib.NGHTTP2_DEFAULT_WEIGHT
    else
        if not priority[1] then
            return nil
        end
        pri_spec[0].stream_id = priority[1]
        local weight = tonumber(priority[2])
        if weight then
            pri_spec[0].weight = weight
        end
        if priority[3] then
            pri_spec[0].exclusive = 1
        end
    end
    return pri_spec
end

--- Create a client session.
--  @return Session object.
function nghttp2.session.client(options)
    local error_code, ope, cb
    opt, error_code = create_options(options)
    if not opt then
        return nil, "could not create session", error_code
    end
    cb, error_code = create_callbacks(options)
    if not cb then
        return nil, "could not create session", error_code
    end
    local session = session_ct()
    error_code = lib.nghttp2_session_client_new2(ffi.cast("nghttp2_session**",session), cb, nil, opt)
    if error_code ~= 0 then
        return nil, "could not create session", error_code
    end
    return session
end

--- Create a server session.
--  @return Session object.
function nghttp2.session.server(options)
    local error_code, ope, cb
    opt, error_code = create_options(options)
    if not opt then
        return nil, "could not create session", error_code
    end
    cb, error_code = create_callbacks(options)
    if not cb then
        return nil, "could not create session", error_code
    end
    local session = session_ct()
    error_code = lib.nghttp2_session_server_new2(ffi.cast("nghttp2_session**",session), cb, opt)
    if error_code ~= 0 then
        return nil, "could not create session", error_code
    end
    return session
end

--- Close a session.
--  Implicitly called when a session object is garbage collected.
function nghttp2.session:del()
    if self._ptr ~= nil then
        lib.nghttp2_session_del(self._ptr)
        self._ptr = nil
    end
end

--- Send any pending outgoing data.
--  Calls the `send` callback with the data that will be sent.
--  @return True if the data was sent.
function nghttp2.session:send()
    local error_code = lib.nghttp2_session_send(self._ptr)
    return error_success(error_code)
end

--- Get any pending outgoing data.
--  Returns the data to be sent instead of calling the `send` callback.
--  @return A block of data as a string.
function nghttp2.session:mem_send()
    local data = ffi.new"utf8_t*[1]"
    local length = lib.nghttp2_session_mem_send(self._ptr, data)
    if length < 0 then
        return nil, ffi.string(lib.nghttp2_strerror(length)), tonumber(length)
    end
    return ffi.string(data, length)
end

--- Fetch incoming data.
--  Calls the `recv` callback until all pending data is received.
--  @return True if the data was received.
function nghttp2.session:recv()
    local error_code = lib.nghttp2_session_recv(self._ptr)
    return error_success(error_code)
end

--- Reads incoming data.
--  Accepts a string of input data instead of calling the `recv` callback.
--  @return The number of bytes that were read from the string.
function nghttp2.session:mem_recv(data)
    local length = lib.nghttp2_session_mem_recv(self._ptr, data, #data)
    if length < 0 then
        return nil, ffi.string(lib.nghttp2_strerror(length)), tonumber(length)
    end
    return ffi.string(data, length)
end

--- Puts back previously deferred data into the outgoing stream.
--  @return True if the function succeeds.
function nghttp2.session:resume_data(stream_id)
    local error_code = lib.nghttp2_session_resume_data(self._ptr, stream_id)
    return error_success(error_code)
end

--- Check if a session is in a read state.
--  @return True if the session is ready to receive data.
function nghttp2.session:want_read()
    local error_code = lib.nghttp2_session_want_read(self._ptr, stream_id)
    return error_success(error_code)
end

--- Check if a session is in a write state.
--  @return True if the session is ready to send data.
function nghttp2.session:want_write()
    local error_code = lib.nghttp2_session_want_write(self._ptr, stream_id)
    return error_success(error_code)
end

--[[ DISABLED
--- Get stream user data.
--  @return A value associated with a stream.
function nghttp2.session:get_stream_user_data(stream_id)
end

--- Set stream user data.
--  @param  stream_id   The ID number of the stream.
--  @param  value       A value to associate with the stream.
--  @return True if the function succeeds.
function nghttp2.session:set_stream_user_data(stream_id, value)
end
]]

--- Get the size of the outbound queue.
--  @return Number of frames.
function nghttp2.session:get_outbound_queue_size()
    local size = lib.nghttp2_session_get_outbound_queue_size(self._ptr)
    return error_result(size, tonumber)
end

--- Get the effective amount of data received.
--  @return Size of data in bytes.
function nghttp2.session:get_effective_recv_data_length()
    local size = lib.nghttp2_session_get_effective_recv_data_length(self._ptr)
    return error_result(size, tonumber)
end

--- Get the local window size.
--  @return Size of window in bytes.
function nghttp2.session:get_effective_local_window_size()
    local size = lib.nghttp2_session_get_stream_effective_local_window_size(self._ptr)
    return error_result(size, tonumber)
end

--- Get the remote window size.
--  @return Size of window in bytes.
function nghttp2.session:get_remote_window_size()
    local size = lib.nghttp2_session_get_remote_window_size(self._ptr)
    return error_result(size, tonumber)
end

--- Get the effective amount of data received by a stream.
--  @return Size of data in bytes.
function nghttp2.session:get_stream_effective_recv_data_length(stream_id)
    local size = lib.nghttp2_session_get_stream_effective_recv_data_length(self._ptr, stream_id)
    return error_result(size, tonumber)
end

--- Get the local window size for a stream.
--  @return Size of window in bytes.
function nghttp2.session:get_stream_effective_local_window_size(stream_id)
    local size = lib.nghttp2_session_get_stream_effective_local_window_size(self._ptr, stream_id)
    return error_result(size, tonumber)
end

--- Get the remote window size for a stream.
--  @return Size of window in bytes.
function nghttp2.session:get_stream_remote_window_size(stream_id)
    local size = lib.nghttp2_session_get_stream_remote_window_size(self._ptr, stream_id)
    return error_result(size, tonumber)
end

--- Check if a stream was closed by the local peer.
--  @return True if the stream is half closed. False is not. Nil if the stream is invalid.
function nghttp2.session:get_stream_local_close(stream_id)
    local is_close = lib.nghttp2_session_get_stream_local_close(self._ptr, stream_id)
    if is_close < 0 then
        return nil, ffi.string(lib.nghttp2_strerror(error_code)), tonumber(error_code)
    end
    return is_close ~= 0
end

--- Check if a stream was closed by the remote peer.
--  @return True if the stream is half closed. False is not. Nil if the stream is invalid.
function nghttp2.session:get_stream_remote_close(stream_id)
    local is_close = lib.nghttp2_session_get_stream_remote_close(self._ptr, stream_id)
    if is_close < 0 then
        return nil, ffi.string(lib.nghttp2_strerror(error_code)), tonumber(error_code)
    end
    return is_close ~= 0
end

--- Close some or all of the streams in a session.
--  @param  last_stream_id  Lowest stream number that will be terminated. (optional)
--  @param  error_code      Status code of the GOAWAY frame.
--  @return True if the function succeeds.
function nghttp2.session:terminate_session(last_stream_id, error_code)
    if error_code == nil then
        error_code, last_stream_id = last_stream_id
    end
    if not error_code then
        return false, "Invalid argument", lib.NGHTTP2_ERR_INVALID_ARGUMENT
    end
    if stream_id == nil then
        error_code = lib.nghttp2_session_terminate_session(self._ptr, error_code)
    else
        error_code = lib.nghttp2_session_terminate_session2(self._ptr, last_stream_id, error_code)
    end
    return error_success(error_code)
end

--- Send messages indicating the connection is about to be closed.
--  @return True if the function succeeds.
function nghttp2.session:submit_shutdown_notice()
end

--- Return the value of a settings option sent by the remote peer.
--  @param  id  The option key or ID number.
--  @return The value of the option.
function nghttp2.session:get_remote_settings(id)
    id = settings_key_id(id)
    if not id then
        return nil, "Invalid argument", lib.NGHTTP2_ERR_INVALID_ARGUMENT
    end
    local value = lib.nghttp2_session_get_remote_settings(self._ptr, id)
    return error_result(value, tonumber)
end

--- Change the next stream ID number.
--  @param stream_id    Number of the next stream.
--  @return True if the function succeeds.
function nghttp2.session:set_next_stream_id(stream_id)
    local error_code = lib.nghttp2_session_set_next_stream_id(self._ptr, stream_id)
    return error_success(error_code)
end

--- Return the next outgoing stream ID.
--  @return The stream ID number or `nil` if there are no more IDs.
function nghttp2.session:get_next_stream_id()
    local stream_id = lib.nghttp2_session_get_next_stream_id(self._ptr)
    if stream_id == 0x80000000 then
        return nil
    end
    return stream_id
end

--- Return the last stream ID that has processed input.
--  @return The stream ID number.
function nghttp2.session:get_last_proc_stream_id()
    return lib.nghttp2_get_last_proc_stream_id(self._ptr)
end

--- Tell the session how many bytes have been processed.
--  @param stream_id    The stream ID the bytes were read from.
--  @param size         Number of bytes.
--  @return True if the function succeeds.
function nghttp2.session:consume(stream_id, size)
    local error_code = lib.nghttp2_session_consume(self._ptr, stream_id, size)
    return error_success(error_code)
end

--- Tell the session how many bytes have been processed at the connection level.
--  @param size Number of bytes.
--  @return True if the function succeeds.
function nghttp2.session:consume_connection(size)
    local error_code = lib.nghttp2_session_consume_connection(self._ptr, size)
    return error_success(error_code)
end

--- Tell the session how many bytes have been processed at the stream level.
--  @param stream_id    The stream ID the bytes were read from.
--  @param size         Number of bytes.
--  @return True if the function succeeds.
function nghttp2.session:consume_stream(stream_id, size)
    local error_code = lib.nghttp2_session_consume_stream(self._ptr, stream_id, size)
    return error_success(error_code)
end

--- Perform a HTTP upgrade.
--  @param settings_payload Decoded string from the HTTP2-Settings header.
--  @return True if the function succeeds.
function nghttp2.session:upgrade(settings_payload)
    assert(type(settings_payload) == 'string', "argument must be a string")
    local error_code = lib.nghttp2_session_upgrade(self._ptr, settings_payload, #settings_payload, nil)
    return error_success(error_code)
end

function nghttp2.session:submit_request(headers, source, priority)
    local nva,nvlen = create_headers(headers)
    local data_prd = create_data_provider(self, source)
    priority = create_priority(priority)
    local stream_id = lib.nghttp2_submit_request(self._ptr, priority, nva, nvlen, data_prd, nil)
    return error_result(stream_id)
end

function nghttp2.session:submit_response(stream_id, headers, source)
    local nva,nvlen = create_headers(headers)
    local data_prd = create_data_provider(self, source)
    local error_code = lib.nghttp2_submit_response(self._ptr, stream_id, nva, nvlen, data_prd)
    return error_success(error_code)
end

function nghttp2.session:submit_headers(stream_id, headers, priority, flags)
    local nva,nvlen = create_headers(headers)
    priority = create_priority(priority)
    flags = create_http2_flags(flags)
    local error_code = lib.nghttp2_submit_headers(self._ptr, flags, stream_id, priority, nva, nvlen, nil)
    return error_success(error_code)
end

function nghttp2.session:submit_trailer(stream_id, headers)
    local nva,nvlen = create_headers(headers)
    local error_code = lib.nghttp2_submit_trailer(self._ptr, stream_id, nva, nvlen)
    return error_success(error_code)
end

function nghttp2.session:submit_data(stream_id, source, flags)
    local data_prd = create_data_provider(self, source)
    flags = create_http2_flags(flags)
    local error_code = lib.nghttp2_submit_data(self._ptr, flags, stream_id, data_prd)
    return error_success(error_code)
end

function nghttp2.session:submit_priority(stream_id, priority, flags)
    priority = create_priority(priority)
    flags = create_http2_flags(flags)
    local error_code = lib.nghttp2_submit_priority(self._ptr, flags, stream_id, priority)
    return error_success(error_code)
end

function nghttp2.session:submit_rst_stream(stream_id, error_code, flags)
    flags = create_http2_flags(flags)
    local error_code = lib.nghttp2_submit_rst_stream(self._ptr, flags, stream_id, error_code)
    return error_success(error_code)
end

function nghttp2.session:submit_settings(settings, flags)
    local iv,niv = create_settings(settings)
    flags = create_http2_flags(flags)
    local error_code = lib.nghttp2_submit_settings(self._ptr, flags, iv, niv)
    return error_success(error_code)
end

function nghttp2.session:submit_push_promise(stream_id, headers, flags)
    local nva,nvlen = create_headers(headers)
    flags = create_http2_flags(flags)
    stream_id = lib.nghttp2_submit_headers(self._ptr, flags, stream_id, nva, nvlen, nil)
    return error_result(stream_id)
end

function nghttp2.session:submit_ping(data, flags)
    data = data or ""
    if type(data) ~= 'string' then
        return false, "Invalid argument", lib.NGHTTP2_ERR_INVALID_ARGUMENT
    end
    local opaque_data = ffi.new("uint8_t[8]")
    ffi.copy(opaque_data, data, math.min(8,#data))
    flags = create_http2_flags(flags)
    local error_code = lib.nghttp2_submit_ping(self._ptr, flags, opaque_data)
    return error_success(error_code)
end

function nghttp2.session:submit_goaway(error_code, last_stream_id, flags, data)
    local datalen = 0
    if data ~= nil then
        if type(data) ~= 'string' then
            return false, "Invalid argument", lib.NGHTTP2_ERR_INVALID_ARGUMENT
        end
        datalen = #data
    end
    error_code = lib.nghttp2_submit_goaway(self._ptr, flags or 0, last_stream_id, error_code, data, datalen)
    return error_success(error_code)
end

function nghttp2.session:submit_window_update(stream_id, size_increment, flags)
    flags = create_http2_flags(flags)
    local error_code = lib.nghttp2_submit_window_update(self._ptr, flags, stream_id, size_increment)
    return error_success(error_code)
end

function nghttp2.session:get_root_stream()
    local stream = lib.nghttp2_session_get_root_stream(self._ptr)
    if stream == nil then
        return nil, "stream not found"
    end
    return stream
end

function nghttp2.session:find_stream(stream_id)
    local stream = lib.nghttp2_session_find_stream(self._ptr, stream_id)
    if stream == nil then
        return nil, "stream not found"
    end
    return stream
end

function nghttp2.stream:stream_id()
    return lib.nghttp2_stream_get_stream_id(self._ptr)
end

local stream_proto_state = {
    [lib.NGHTTP2_STREAM_STATE_IDLE] = "idle",
    [lib.NGHTTP2_STREAM_STATE_OPEN] = "open",
    [lib.NGHTTP2_STREAM_STATE_RESERVED_LOCAL] = "reserved-local",
    [lib.NGHTTP2_STREAM_STATE_RESERVED_REMOTE] = "reserved-remote",
    [lib.NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL] = "half-closed-local",
    [lib.NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE] = "half-closed-remote",
    [lib.NGHTTP2_STREAM_STATE_CLOSED] = "closed"
}
function nghttp2.stream:state()
    local proto_state = lib.nghttp2_stream_get_state(self._ptr)
    return stream_proto_state[proto_state] or proto_state
end

function nghttp2.stream:parent()
    local stream = lib.nghttp2_stream_get_parent(self._ptr)
    if stream == nil then
        return nil, "stream not found"
    end
    return stream
end

function nghttp2.stream:next_sibling()
    local stream = lib.nghttp2_stream_get_next_sibling(self._ptr)
    if stream == nil then
        return nil, "stream not found"
    end
    return stream
end

function nghttp2.stream:previous_sibling()
    local stream = lib.nghttp2_stream_get_previous_sibling(self._ptr)
    if stream == nil then
        return nil, "stream not found"
    end
    return stream
end

function nghttp2.stream:first_child()
    local stream = lib.nghttp2_stream_get_first_child(self._ptr)
    if stream == nil then
        return nil, "stream not found"
    end
    return stream
end

function nghttp2.stream:weight()
    return tonumber(lib.nghttp2_stream_get_weight(self._ptr))
end

function nghttp2.stream:sum_dependency_weight()
    return tonumber(lib.nghttp2_stream_get_sum_dependency_weight(self._ptr))
end


function nghttp2.hddeflate.new(max_size)
    max_size = max_size or lib.NGHTTP2_DEFAULT_HEADER_TABLE_SIZE
    deflater = hddeflate_ct()
    local error_code = lib.nghttp2_hd_deflate_new(ffi.cast("nghttp2_hd_deflater**",deflater), max_size)
    if error_code ~= 0 then
        return nil, ffi.string(lib.nghttp2_strerror(error_code)), tonumber(error_code)
    end
    return deflater
end

function nghttp2.hddeflate:del()
    if self._ptr ~= nil then
        lib.nghttp2_hd_deflate_del(self._ptr)
        self._ptr = nil
    end
end

function nghttp2.hddeflate:change_table_size(size)
    local error_code = lib.nghttp2_hd_deflate_change_table_size(self._ptr, size)
    return error_success(error_code)
end

function nghttp2.hddeflate:deflate_bound(headers)
    local nva, nvlen = create_headers(headers)
    if not nva then
        return nil, "Invalid argument", lib.NGHTTP2_ERR_INVALID_ARGUMENT
    end
    local size = lib.nghttp2_hd_deflate_bound(self._ptr, nva, nvlen)
    return error_result(size, tonumber)
end

-- TODO nghttp2 documentation is ambiguous whether this returns a size or error code.
function nghttp2.hddeflate:deflate(headers)
    local nva, nvlen = create_headers(headers)
    if not nva then
        return nil, "Invalid argument", lib.NGHTTP2_ERR_INVALID_ARGUMENT
    end
    local buflen = lib.nghttp2_hd_deflate_bound(self._ptr, nva, nvlen)
    if buflen < 0 then
        return error_result(buflen)
    end
    local buf = ffi.new("uint8_t[?]", buflen)
    buflen = lib.nghttp2_hd_deflate_hd(self._ptr, buf, buflen, nva, nvlen)
    if buflen < 0 then
        return error_result(buflen)
    end
    return ffi.string(buf, buflen)
end

function nghttp2.hdinflate.new()
    inflater = hdinflate_ct()
    local error_code = lib.nghttp2_hd_inflate_new(ffi.cast("nghttp2_hd_inflater**",inflater))
    if error_code ~= 0 then
        return nil, ffi.string(lib.nghttp2_strerror(error_code)), tonumber(error_code)
    end
    return inflater
end

function nghttp2.hdinflate:del()
    if self._ptr ~= nil then
        lib.nghttp2_hd_inflate_del(self._ptr)
        self._ptr = nil
    end
end

function nghttp2.hdinflate:change_table_size(size)
    local error_code = lib.nghttp2_hd_deflate_change_table_size(self._ptr, size)
    return error_success(error_code)
end

--- Decompress packed headers
--  If the inflater reaches the end of a header block, it will return
--  `true` and the caller should call `end_headers` before reusing this
--  object.
--  @return A table of {name,value} pairs.
--  @return True if all headers were unpacked.
function nghttp2.hdinflate:inflate(buf, final, headers)
    headers = headers or {}
    local nv = ffi.new"nghttp2_nv[1]"
    local flags = ffi.new"int[1]"
    final = final and 1 or 0
    if type(buf) ~= 'string' then
        return nil, "Invalid argument", lib.NGHTTP2_ERR_INVALID_ARGUMENT
    end
    inlen = #buf
    inbuf = ffi.new("uint8_t*", ffi.cast("uint8_t*", buf))
    repeat
        local nbytes = lib.nghttp2_hd_inflate_hd(self._ptr, nv, flags, inbuf, inlen, final)
        if nbytes < 0 then
            error_result(nbytes)
        end
        inbuf = inbuf + nbytes
        inlen = math.max(tonumber(inlen - nbytes), 0) -- really, LuaJIT?
        if bit.band(tonumber(flags[0]), lib.NGHTTP2_HD_INFLATE_EMIT) ~= 0 then
            headers[#headers+1] = create_header_table(nv[0])
        elseif inlen == 0 then
            return headers, false
        end
    until bit.band(tonumber(flags[0]), lib.NGHTTP2_HD_INFLATE_FINAL) ~= 0
    return headers, true
end

function nghttp2.hdinflate:end_headers()
    local error_code = lib.nghttp2_hd_inflate_end_headers(self._ptr)
    return error_success(error_code)
end


ffi.cdef[[
    typedef struct {
        nghttp2_session *_ptr;
    } nghttp2_session_ct;

    typedef struct {
        nghttp2_stream *_ptr;
    } nghttp2_stream_ct;

    typedef struct {
        nghttp2_hd_deflater *_ptr;
    } nghttp2_hd_deflater_ct;

    typedef struct {
        nghttp2_hd_inflater *_ptr;
    } nghttp2_hd_inflater_ct;
]]

session_ct = ffi.metatype("nghttp2_session_ct", {
    __gc = nghttp2.session.del,
    __index = nghttp2.session
})

stream_ct = ffi.metatype("nghttp2_stream_ct", {
    __index = nghttp2.stream
})

hddeflate_ct = ffi.metatype("nghttp2_hd_deflater_ct", {
    __gc = nghttp2.hddeflate.del,
    __index = nghttp2.hddeflate
})

hdinflate_ct = ffi.metatype("nghttp2_hd_inflater_ct", {
    __gc = nghttp2.hdinflate.del,
    __index = nghttp2.hdinflate
})


return nghttp2
