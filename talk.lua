-- File: talk.lua
--
-- This is a simple Wireshark/`tshark` plugin written in Lua. It is
-- a protocol dissector for the equally simple protocol used by the
-- original `talk(1)` program and its server counterpart, `talkd(8)`.

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

-- Create the actual dissector for our protocol.
function talk.dissector(tbuf, pktinfo, root)
end

-- Invoke our dissector for a specific UDP port.
DissectorTable.get("udp.port"):add(default_settings.port, talk)
