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
from socketserver import BaseRequestHandler, ThreadingTCPServer
from xstruct import struct, sizeof, Little, Int32, CString, BSON

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


globals().update(OpCodes.__members__)


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


def recv_msg(sock):
    header_size = sizeof(MsgHeader)
    buf = sock.recv(header_size)
    if not buf:
        return None
    header = MsgHeader.unpack(buf)

    return header, buf+sock.recv(header.message_length-header_size)


def recv_all(sock):
    while (ret := recv_msg(sock)) is not None:
        yield ret


msg_classes = {
    OP_QUERY: QueryMsg
    #OP_MSG: MsgMsg
}


def decode_msg(buf):
    header = MsgHeader.unpack(buf)
    try:
        msg_cls = msg_classes[header.op_code]
    except KeyError:
        return None
    return msg_cls.unpack(buf)


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

            for header, buf in recv_all(self.request):
                msg = decode_msg(buf)
                peer_addr, peer_port = self.request.getpeername()
                print(f"Forwarding {op_code_name(header.op_code)} from {peer_addr}:{peer_port}")
                if msg is not None:
                    print(msg)
                mongo_sock.send(buf)
                _, reply = recv_msg(mongo_sock)
                self.request.send(reply)


if __name__ == "__main__":
    args = parser.parse_args()
    try:
        with ThreadingTCPServer(args.host, MongoHandler(args.mongo_host)) as server:
            server.serve_forever()
    except KeyboardInterrupt:
        print("Interrupted")
