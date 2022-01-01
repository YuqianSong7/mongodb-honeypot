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


import sys
from time import time
from enum import IntEnum
from socket import socket, AF_INET, SOCK_STREAM
from selectors import DefaultSelector, EVENT_READ
from socketserver import BaseRequestHandler, TCPServer, ThreadingMixIn
from threading import Thread, Lock, Event
from functools import wraps
from xstruct import struct, sizeof, byteorder, Little, UInt8, Int32, UInt32, Int64, Bytes, CString, BSON, Array, CustomMember

import colorama
from colorama import Fore

from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError

from args import parser


output_lock = Lock()
_print = print
@wraps(_print)
def print(*args, **kwargs):
    with output_lock:
        _print(*args, **kwargs)


class ExecTimer:
    def __init__(self):
        self.time = 0

    def __enter__(self):
        self.time = time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.time = time() - self.time


class OpCode(IntEnum):
    OP_REPLY        = 1
    OP_UPDATE       = 2001
    OP_INSERT       = 2002
    OP_QUERY        = 2004
    OP_GET_MORE     = 2005
    OP_DELETE       = 2006
    OP_KILL_CURSORS = 2007
    OP_COMPRESSED   = 2012
    OP_MSG          = 2013


class FlagBit(IntEnum):
    CHECKSUM_PRESENT = 1 << 0
    MORE_TO_COME     = 1 << 1
    EXHAUST_ALLOWED  = 1 << 16


globals().update(OpCode.__members__)
globals().update(FlagBit.__members__)


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
class ReplyMsg:
    header: MsgHeader

    response_flags:  Int32
    cursor_id:       Int64
    starting_from:   Int32
    number_returned: Int32
    documents:       Array(BSON, "number_returned")


@struct(endianess=Little)
class UpdateMsg:
    header: MsgHeader

    zero:                 Int32
    full_collection_name: CString
    flags:                Int32
    selector:             BSON
    update:               BSON


@struct(endianess=Little)
class InsertMsg:
    header: MsgHeader

    flags:                Int32
    full_collection_name: CString
    documents:            Array(BSON)


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
class GetMoreMsg:
    header: MsgHeader

    zero:                 Int32
    full_collection_name: CString
    number_to_return:     Int32
    cursor_id:            Int64


@struct(endianess=Little)
class DeleteMsg:
    header: MsgHeader

    zero:                 Int32
    full_collection_name: CString
    flags:                Int32
    selector:             BSON


@struct(endianess=Little)
class KillCursorsMsg:
    header: MsgHeader

    zero:                 Int32
    number_of_cursor_ids: Int32
    cursor_ids:           Array(Int64, "number_of_cursor_ids")


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
    OP_REPLY: ReplyMsg.unpack,
    OP_UPDATE: UpdateMsg.unpack,
    OP_INSERT: InsertMsg.unpack,
    OP_QUERY: QueryMsg.unpack,
    OP_GET_MORE: GetMoreMsg.unpack,
    OP_DELETE: DeleteMsg.unpack,
    OP_KILL_CURSORS: KillCursorsMsg.unpack,
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


shutdown_event = Event()


def proxy(peer_sock, mongo_sock):
    peer_addr, peer_port = peer_sock.getpeername()
    print(f"Incoming connection from {peer_addr}:{peer_port}")

    with DefaultSelector() as selector:
        selector.register(peer_sock, EVENT_READ, (mongo_sock, Fore.GREEN))
        selector.register(mongo_sock, EVENT_READ, (peer_sock, Fore.RED))
        while True:
            selector_events = selector.select(timeout=1)
            if shutdown_event.is_set():
                return
            for (sock, _, _, (peer, color)), _ in selector_events:
                exit_condition = None
                try:
                    buf = recv_msg(sock)
                except ConnectionResetError:
                    if sock is peer_sock:
                        exit_condition = "reset by peer"
                    else:
                        exit_condition = "reset by upstream Mongo for peer"
                else:
                    if not buf:
                        if sock is peer_sock:
                            exit_condition = "closed by peer"
                        else:
                            exit_condition = "closed by upstream Mongo for peer"
                if exit_condition:
                    print(f"Connection {exit_condition} {peer_addr}:{peer_port}")
                    return
                msg = unpack_msg(buf)
                print(f"{color}{msg}")
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

            proxy(self.request, mongo_sock)


class ProxyServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True

    def server_close(self):
        shutdown_event.set()
        super().server_close()


def is_mongo_up(mongo_host):
    try:
        MongoClient(*mongo_host, serverSelectionTimeoutMS=3000).server_info()
    except ServerSelectionTimeoutError:
        return False
    else:
        return True


def check_mongo(mongo_host, check_interval):
    was_up = True
    elapsed = ExecTimer()
    while not shutdown_event.wait(max(check_interval-elapsed.time, 0)):
        with elapsed:
            is_up = is_mongo_up(mongo_host)
            if is_up != was_up:
                if is_up:
                    print("Mongo is back up")
                else:
                    print("Mongo went down")
                was_up = is_up


if __name__ == "__main__":
    colorama.init(autoreset=True)
    args = parser.parse_args()
    if not is_mongo_up(args.mongo_host):
        mongo_addr, mongo_port = args.mongo_host
        print("Could not connect to Mongo at {mongo_addr}:{mongo_port}")
        sys.exit(1)
    try:
        Thread(target=check_mongo, args=(args.mongo_host, args.check_interval), daemon=False).start()
        with ProxyServer(args.host, MongoHandler(args.mongo_host)) as server:
            server.serve_forever()
    except KeyboardInterrupt:
        print("Interrupted")
    finally:
        shutdown_event.set()
