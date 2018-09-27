# Wireshark and `tshark` Talk protocol dissector

This is a simple [Wireshark protocol dissector](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterDissection.html) for the equally-simple protocol used by the old BSD UNIX [`talk(1)`](https://manpage.me/index.cgi?q=talk) program and its counterpart, the [`talkd(8)`](https://manpage.me/index.cgi?q=talkd) server. This same protocol is used by the `ntalk(1)` and `ytalk(1)` programs, as well, since they both rely on the same `talkd` server.

## Installation

First, [check your version of Wireshark for Lua support](https://wiki.wireshark.org/Lua#Getting_Started). Without this, you won't be able to run this code. Otherwise, the installation procedure is as simple as:

1. Copy (or symlink) the [`talk.lua`](talk.lua) script into your [personal or global Wireshark plugins folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).
1. Restart Wireshark, or reload your Lua plugins (available from the Wireshark menu as `Analyze → Reload Lua Plugins`).
1. Open any of the provided sample packet capture files in Wireshark.

## Why? No one uses `talk` anymore.

Exactly. As far as I can tell, that means no one has written a Wireshark dissector for it. That fact, coupled with the simplicity of the protocol, make writing one a great little project for me. :)
