#!/usr/bin/env python3

from enum import IntEnum
from socketserver import BaseRequestHandler, TCPServer
from xstruct import struct, sizeof, Little, Int32, CString, BSON


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


class MongoHandler(BaseRequestHandler):
    def handle(self):
        msg = self.recv_msg()
        print(msg)

    def recv_msg(self):
        header_size = sizeof(MsgHeader)
        buf = self.request.recv(header_size)
        header = MsgHeader(buf)

        buf += self.request.recv(header.message_length-header_size)
        if header.op_code == OP_QUERY:
            return QueryMsg(buf)

        raise NotImplementedError


if __name__ == "__main__":
    try:
        with TCPServer(("localhost", 27017), MongoHandler) as server:
            server.serve_forever()
    except KeyboardInterrupt:
        print("Interrupted")
