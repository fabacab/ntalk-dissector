-- This is a simple Wireshark/`tshark` plugin written in Lua. It is
-- a protocol dissector for the equally simple protocol used by the
-- original `talk(1)` program and its server counterpart, `talkd(8)`.
--
-- I have attempted to comment my code as thoroughly as I understand
-- it, including using LDoc conventions. See
--
--     https://stevedonovan.github.io/ldoc/
--
-- for details on LDoc and usage.
--
-- @script talk
-- @license GPL-3.0-or-later

-- Choose some sensible defaults.
local default_settings = {
    port = 518
}

-- Create a Proto object, but don't register it yet.
local talk = Proto("talk", "Talk Protocol")

-- Define protocol message types. These are used in the upcoming
-- ProtoField for `talk.type`.
local talk_message_types = {
    [0] = "LEAVE_INVITE",
    [1] = "LOOK_UP",
    [2] = "DELETE",
    [3] = "ANNOUNCE"
}

-- Create protocol fields, which map to structs defined in `talkd.h`.
local pf_protocol_version = ProtoField.uint8('talk.version', "Protocol version")
local pf_request_type     = ProtoField.uint8('talk.request_type', "Request type", base.DEC, talk_message_types)
local pf_reply_type       = ProtoField.uint8('talk.reply_type', "Response type", base.DEC, talk_message_types)
local pf_pad              = ProtoField.uint8('talk.pad', "Pad")
local pf_message_id_num   = ProtoField.uint32('talk.id', "Message ID number")
-- TODO:
-- The addresses here are actually `struct osockaddr`, which `talkd.h` defines as follows:
-- /*
--  * 4.3 compat sockaddr
--  */
-- #include <_types.h>
-- struct osockaddr {
--     __uint16_t      sa_family;      /* address family */
--     char            sa_data[14];    /* up to 14 bytes of direct address */
-- };
--
-- However, 14 bytes is a lot more than an IPv4 address needs. It's
-- less than IPv6 address needs, though. So I'm not sure where the 2
-- bytes for the address family should be considered.
local pf_address_port     = ProtoField.uint16('talk.addr_port', "Client port") -- TODO: Not always "client" port.
local pf_address          = ProtoField.ipv4('talk.addr', "Client address")
local pf_ctl_address_port = ProtoField.uint16('talk.ctl_addr_port', "Server port") -- TODO: Not always "Server." Depends on isRequest()?
local pf_ctl_address      = ProtoField.ipv4('talk.ctl_addr', "Server address")
local pf_caller_pid       = ProtoField.int32('talk.pid', "Process ID")
local pf_caller_name      = ProtoField.string('talk.caller_name', "Caller's name", base.ASCII, "Account name of the calling user")
local pf_callee_name      = ProtoField.string('talk.callee_name', "Callee's name", base.ASCII, "Account name of the called user")
local pf_callee_tty_name  = ProtoField.string('talk.callee_tty_name', "Callee's TTY name")

-- The Talk protocol has a client-server architecture. Messages sent
-- from the client to server are called `CTL_MSG`s, while messages
-- sent from the server to the client are called `CTL_RESPONSE`s.
local ctl_msg = {
    pf_protocol_version,
    pf_request_type,
    pf_reply_type,
    pf_pad,
    pf_message_id_num,
    pf_address_port,
    pf_address,
    pf_ctl_address_port,
    pf_ctl_address,
    pf_caller_pid,
    pf_caller_name,
    pf_callee_name,
    pf_callee_tty_name
}
local ctl_response = {
    pf_protocol_version,
    pf_request_type,
    pf_reply_type,
    pf_pad,
    pf_message_id_num,
    pf_address_port,
    pf_address
}

-- Register the above fields as a new Protocol to analyze.
-- TODO: Programmatically create this table so as to avoid forgetting
--       to register a given field.
talk.fields = ctl_msg -- Talk CTL_MSG has all possible protocol fields.

-- Now that we've registered some fields for the `talk` Proto object,
-- create some analysis fields to view data that has been dissected.
local f_protocol_version = Field.new('talk.version')
local f_request_type     = Field.new('talk.request_type')
local f_reply_type       = Field.new('talk.reply_type')
local f_pad              = Field.new('talk.pad')
local f_message_id_num   = Field.new('talk.id')
local f_address_port     = Field.new('talk.addr')
local f_address          = Field.new('talk.addr')
local f_ctl_address_port = Field.new('talk.ctl_addr_port')
local f_ctl_address      = Field.new('talk.ctl_addr')
local f_caller_pid       = Field.new('talk.pid')
local f_caller_name      = Field.new('talk.caller_name')
local f_callee_name      = Field.new('talk.callee_name')
local f_callee_tty_name  = Field.new('talk.callee_tty_name')

--- Helper to determine whether the packet is a request or reply.
--
-- Requests to the server are called `CTL_MSG`s, while responses from
-- the server to the client are called `CTL_RESPONSE`s.
--
-- @param pktinfo A Pinfo object representing the given packet.
--
-- @return boolean
local function isRequest(pktinfo)
    return pktinfo.dst_port == default_settings['port']
end

--- The actual dissector for the Talk protocol.
--
-- The callback function that Wireshark calls when disssecting a
-- given packet matching the Talk protocol's UDP port.
--
-- @param tvbuf The `Tvb` object for the packet.
-- @param pktinfo The `Pinfo` object representing the packet info.
-- @param root The `TreeItem` object representing the root of the tree view.
talk.dissector = function (tvbuf, pktinfo, root)

    -- Display protocol name in Packet List pane's Protocol column.
    pktinfo.cols.protocol:set("Talk")

    -- Get this packet's length.
    --local pktlen = tvbuf:reported_length_remaining()
    local pktlen = tvbuf:reported_length_remaining()

    -- Since Talk does not encapsulate any other protocol, the entire
    -- packet is part of the Talk protocol, so its whole range should
    -- be added to the Packet Details pane as the Talk protocol.
    local tree = root:add(talk, tvbuf:range(0, pktlen))

    -- TODO: Make sure the packet seems sensible. I.e., not malformed
    --       in some way. Should also add some hints for the analyst,
    --       probably in the form of Wireshark "expert info" fields.

    -- Parse the bytes in the packet buffer and add its information
    -- to the Packet Details pane as an expandable tree view.
    tree:add(pf_protocol_version, tvbuf:range(0, 1))
    tree:add(pf_request_type, tvbuf:range(1, 1))

    -- Only responses from the server have a reply type (answer code).
    if not isRequest(pktinfo) then
        tree:add(pf_reply_type, tvbuf:range(2, 1))
    end

    tree:add(pf_pad, tvbuf:range(3, 1))
    tree:add(pf_message_id_num, tvbuf:range(4, 4))

    tree:add(pf_address_port, tvbuf:range(10, 2))
    tree:add(pf_address, tvbuf:range(12, 4))

    if isRequest(pktinfo) then
        tree:add(pf_ctl_address_port, tvbuf:range(26, 2))
        tree:add(pf_ctl_address, tvbuf:range(28, 4))
        tree:add(pf_caller_pid, tvbuf:range(40, 4))
        -- 12 bytes is the default size of the name string buffers
        -- in `talkd.h`, used for both the caller and callee's names.
        tree:add(pf_caller_name, tvbuf:range(44, 12))
        tree:add(pf_callee_name, tvbuf:range(56, 12))
        -- The TTY name is given a buffer 16 bytes long in `talkd.h`.
        tree:add(pf_callee_tty_name, tvbuf:range(68, 16))
    end

    -- TODO: Still need to dissect the ctl_addr field.

end

-- Invoke our dissector for a specific UDP port.
DissectorTable.get("udp.port"):add(default_settings.port, talk)
