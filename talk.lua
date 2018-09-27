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
local pf_message_type     = ProtoField.uint8('talk.type', "Message type", base.DEC, talk_message_types)
local pf_answer_code      = ProtoField.uint8('talk.answer', "Answer code")
local pf_pad              = ProtoField.uint8('talk.pad', "Pad")
local pf_message_id_num   = ProtoField.uint32('talk.id', "Message ID number")
-- TODO: What is an "osockaddr"??? This should be the "addr" field
-- TODO: Similarly, the next thing in the struct is the "ctl_addr" field?
local pf_caller_pid       = ProtoField.int32('talk.pid', "Process ID")
local pf_caller_name      = ProtoField.string('talk.caller_name', "Caller's name", base.ASCII, "Account name of the calling user")
local pf_callee_name      = ProtoField.string('talk.callee_name', "Callee's name", base.ASCII, "Account name of the called user")
local pf_callee_tty_name  = ProtoField.string('talk.callee_tty_name', "Callee's TTY name")

-- Register the above fields as a new Protocol to analyze.
-- TODO: Programmatically create this table so as to avoid forgetting
--       to register a given field.
talk.fields = {
    pf_protocol_version,
    pf_message_type,
    pf_answer_code,
    pf_pad,
    pf_message_id_num,
    -- TODO:
    -- * Missing the "addr" field
    -- * Missing the "ctl_addr" field
    pf_caller_pid,
    pf_caller_name,
    pf_callee_name,
    pf_callee_tty_name
}

-- Now that we've registered some fields for the `talk` Proto object,
-- create some analysis fields to view data that has been dissected.
local f_protocol_version = Field.new('talk.version')
local f_message_type     = Field.new('talk.type')
local f_answer_code      = Field.new('talk.answer')
local f_pad              = Field.new('talk.pad')
local f_message_id_num   = Field.new('talk.id')
-- TODO: The osockaddr struct's "addr" field.
-- TODO: The osockaddr struct's "ctl_addr" field.
local f_caller_pid       = Field.new('talk.pid')
local f_caller_name      = Field.new('talk.caller_name')
local f_callee_name      = Field.new('talk.callee_name')
local f_callee_tty_name      = Field.new('talk.callee_tty_name')

--- The actual dissector for the Talk protocol.
--
-- The callback function that Wireshark calls when disssecting a
-- given packet matching the Talk protocol's UDP port.
--
-- @param tvbuf The `Tvb` object for the packet.
-- @param pktinfo The `Pinfo` object representing the packet info.
-- @param root The `TreeItem` object representing the root of the tree view.
--
-- @todo Currently only dissects the client->server messages. Replies
--       from server->client are shorter and thus still cause errors.
talk.dissector = function (tvbuf, pktinfo, root)
    pktinfo.cols.protocol:set("Talk")

    -- Get this packet's length.
    local pktlen = tvbuf:reported_length_remaining()

    -- Since Talk does not encapsulate any other protocol, the entire
    -- packet is part of the Talk protocol, so its whole range should
    -- be added to the Packet Details pane.
    local tree = root:add(talk, tvbuf:range(0, pktlen))

    -- TODO: Make sure the packet seems sensible. I.e., not malformed
    --       in some way. Should also add some hints for the analyst,
    --       probably in the form of Wireshark "expert info" fields.

    -- Parse the bytes in the packet buffer and add its information
    -- to the Packet Details pane as an expandable tree view.
    tree:add(pf_protocol_version, tvbuf:range(0, 1))
    tree:add(pf_message_type, tvbuf:range(1, 1))
    tree:add(pf_answer_code, tvbuf:range(2, 1))
    tree:add(pf_pad, tvbuf:range(3, 1))
    tree:add(pf_message_id_num, tvbuf:range(4, 4))

    -- TODO: Still need to dissect the addr and ctl_addr fields.

    tree:add(pf_caller_pid, tvbuf:range(40, 4))

    -- 12 bytes is the default size of the name string buffers
    -- in `talkd.h`, used for both the caller and callee's names.
    tree:add(pf_caller_name, tvbuf:range(44, 12))
    tree:add(pf_callee_name, tvbuf:range(56, 12))

    -- The TTY name is given a buffer 16 bytes long in `talkd.h`.
    tree:add(pf_callee_tty_name, tvbuf:range(68, 16))
end

-- Invoke our dissector for a specific UDP port.
DissectorTable.get("udp.port"):add(default_settings.port, talk)
