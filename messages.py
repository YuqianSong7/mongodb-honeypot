
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


import zlib
import snappy
import zstd

from enum import IntEnum
from xstruct import struct, sizeof, byteorder, Little, UInt8, Int32, UInt32, Int64, Bytes, CString, BSON, Array, CustomMember


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


class MsgMsgSectionKind(IntEnum):
    BODY              = 0
    DOCUMENT_SEQUENCE = 1


class FlagBit(IntEnum):
    CHECKSUM_PRESENT = 1 << 0
    MORE_TO_COME     = 1 << 1
    EXHAUST_ALLOWED  = 1 << 16


class CompressorId(IntEnum):
    NOOP   = 0
    SNAPPY = 1
    ZLIB   = 2
    ZSTD   = 3


globals().update(OpCode.__members__)
globals().update(MsgMsgSectionKind.__members__)
globals().update(FlagBit.__members__)
globals().update(CompressorId.__members__)


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
    body: BSON


@struct(endianess=Little)
class DocumentSequenceSection:
    size: Int32
    document_sequence_identifier: CString
    documents: Array(BSON)


section_unpackers = {
    BODY: BodySection.unpack,
    DOCUMENT_SEQUENCE: DocumentSequenceSection.unpack
}


class MsgSection(CustomMember):
    def unpack(self, obj, buf, endianess=Little):
        kind = buf[0]
        length = int.from_bytes(buf[1:5], byteorder[endianess], signed=False)
        buf, rest = buf[1:1+length], buf[1+length:]
        try:
            unpacker = section_unpackers[kind]
        except KeyError as e:
            raise RuntimeError(f"Invalid section kind {kind!r}") from e
        return unpacker(buf), rest


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


@struct(endianess=Little)
class CompressedMsg:
    header: MsgHeader

    original_opcode:    Int32
    uncompressed_size:  Int32
    compressor_id:      UInt8
    compressed_message: Bytes


decompressors = {
    NOOP: lambda x: x,
    SNAPPY: snappy.uncompress,
    ZLIB: zlib.decompress,
    ZSTD: zstd.ZSTD_uncompress
}


def unpack_compressed(buf):
    msg = CompressedMsg.unpack(buf)
    data = decompressors[msg.compressor_id](msg.compressed_message)
    header = MsgHeader(
            message_length=4+msg.uncompressed_size,
            request_id=msg.header.request_id,
            response_to=msg.header.response_to,
            op_code=msg.original_opcode)
    return unpack_msg(header.pack()+data)


msg_unpackers = {
    OP_REPLY: ReplyMsg.unpack,
    OP_UPDATE: UpdateMsg.unpack,
    OP_INSERT: InsertMsg.unpack,
    OP_QUERY: QueryMsg.unpack,
    OP_GET_MORE: GetMoreMsg.unpack,
    OP_DELETE: DeleteMsg.unpack,
    OP_KILL_CURSORS: KillCursorsMsg.unpack,
    OP_COMPRESSED: unpack_compressed,
    OP_MSG: unpack_msgmsg
}


def unpack_msg(buf):
    header = MsgHeader.unpack(buf)
    try:
        unpacker = msg_unpackers[header.op_code]
    except KeyError as e:
        raise RuntimeError(f"Invalid opcode") from e
    return unpacker(buf)
