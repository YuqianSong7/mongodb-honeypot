#!/usr/bin/env python3

 ###############################################################################
 # mongodb-honeypot-monitor - Monitoring software for MongoDB honeypots        #
 # Copyright (C) 2021  Simone Cimarelli <aquilairreale@ymail.com>              #
 #                                                                             #
 # This program is free software: you can redistribute it and/or modify        #
 # it under the terms of the GNU Affero General Public License as published by #
 # the Free Software Foundation, either version 3 of the License, or           #
 # (at your option) any later version.                                         #
 #                                                                             #
 # This program is distributed in the hope that it will be useful,             #
 # but WITHOUT ANY WARRANTY; without even the implied warranty of              #
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
 # GNU Affero General Public License for more details.                         #
 #                                                                             #
 # You should have received a copy of the GNU Affero General Public License    #
 # along with this program.  If not, see <https://www.gnu.org/licenses/>.      #
 ###############################################################################


from enum import IntEnum
from socket import socket, AF_INET, SOCK_STREAM
from selectors import DefaultSelector, EVENT_READ
from socketserver import BaseRequestHandler, ThreadingTCPServer
from xstruct import struct, sizeof, byteorder, Little, UInt8, Int32, UInt32, Int64, Bytes, CString, BSON, Array, CustomMember

from args import parser


class OpCodes(IntEnum):
    OP_REPLY        = 1
    OP_UPDATE       = 2001
    OP_INSERT       = 2002
    OP_QUERY        = 2004
    OP_GET_MORE     = 2005
    OP_DELETE       = 2006
    OP_KILL_CURSORS = 2007
    OP_COMPRESSED   = 2012
    OP_MSG          = 2013


class FlagBits(IntEnum):
    CHECKSUM_PRESENT = 1 << 0
    MORE_TO_COME     = 1 << 1
    EXHAUST_ALLOWED  = 1 << 16


globals().update(OpCodes.__members__)
globals().update(FlagBits.__members__)


def op_code_name(op_code):
    return next(
            k for k, v
            in OpCodes.__members__.items()
            if v == op_code)


@struct(endianess=Little)
class MsgHeader:
    message_length: Int32
    request_id:     Int32
    response_to:    Int32
    op_code:        Int32


@struct(endianess=Little)
class QueryMsg:
    header: MsgHeader

    flags:                Int32
    full_collection_name: CString
    number_to_skip:       Int32
    number_to_return:     Int32

    query:                  BSON
    return_fields_selector: BSON = {}


@struct(endianess=Little)
class ReplyMsg:
    header: MsgHeader

    response_flags:  Int32
    cursor_id:       Int64
    starting_from:   Int32
    number_returned: Int32
    documents:       Array(BSON, "number_returned")


@struct(endianess=Little)
class MsgMsgHeader:
    header: MsgHeader
    flag_bits: UInt32


@struct(endianess=Little)
class BodySection:
    kind: UInt8
    body: BSON


class MsgSection(CustomMember):
    def unpack(self, obj, buf, endianess=Little):
        kind = buf[0]
        length = int.from_bytes(buf[1:5], byteorder[endianess], signed=False)
        if kind == 0:
            section = BodySection.unpack(buf)
        else:
            raise NotImplementedError(f"Unimplemented section kind {kind!r}")
        return section, buf[sizeof(section):]


@struct(endianess=Little)
class MsgMsg:
    header: MsgHeader
    flag_bits: UInt32
    sections: Array(MsgSection)


def unpack_msgmsg(buf):
    header = MsgMsgHeader.unpack(buf)
    if header.flag_bits & CHECKSUM_PRESENT:
        buf = buf[:-4]
    return MsgMsg.unpack(buf)


msg_unpackers = {
    OP_QUERY: QueryMsg.unpack,
    OP_REPLY: ReplyMsg.unpack,
    OP_MSG: unpack_msgmsg
}


def unpack_msg(buf):
    header = MsgHeader.unpack(buf)
    try:
        unpacker = msg_unpackers[header.op_code]
    except KeyError as e:
        raise NotImplementedError(f"Unimplemented op_code {op_code_name(header.op_code)}") from e
    return unpacker(buf)


def recv_msg(sock):
    header_size = sizeof(MsgHeader)
    buf = sock.recv(header_size)
    if not buf:
        return buf
    header = MsgHeader.unpack(buf)
    buf += sock.recv(header.message_length-header_size)
    return buf


def proxy(peer_sock, mongo_sock):
    with DefaultSelector() as selector:
        selector.register(peer_sock, EVENT_READ, mongo_sock)
        selector.register(mongo_sock, EVENT_READ, peer_sock)
        for events in iter(selector.select, None):
            for (sock, _, _, peer), _ in events:
                buf = recv_msg(sock)
                if not buf:
                    return
                msg = unpack_msg(buf)
                print(msg)
                peer.send(buf)


class MongoHandler(BaseRequestHandler):
    def __init__(self, mongo_host):
        self.mongo_host = mongo_host

    def __call__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def handle(self):
        with socket(AF_INET, SOCK_STREAM) as mongo_sock:
            try:
                mongo_sock.connect(self.mongo_host)
            except ConnectionRefusedError:
                print("Upstream connection refused: is Mongo up?")
                return

            peer_sock = self.request
            peer_addr, peer_port = peer_sock.getpeername()
            print(f"Incoming connection from {peer_addr}:{peer_port}")

            proxy(peer_sock, mongo_sock)


if __name__ == "__main__":
    args = parser.parse_args()
    try:
        with ThreadingTCPServer(args.host, MongoHandler(args.mongo_host)) as server:
            server.serve_forever()
    except KeyboardInterrupt:
        print("Interrupted")
