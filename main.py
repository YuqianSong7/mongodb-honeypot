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
import atexit
from time import time, sleep
from socket import socket, AF_INET, SOCK_STREAM
from selectors import DefaultSelector, EVENT_READ
from socketserver import BaseRequestHandler, TCPServer, ThreadingMixIn
from threading import Thread, Lock, Event
from functools import wraps

from docker.errors import DockerException, NotFound

from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError

from xstruct import sizeof

import output
import logger
from args import parser
from messages import MsgHeader, unpack_msg, OP_MSG, BodySection
from containers import MongoContainer


class ExecTimer:
    def __init__(self):
        self.time = 0

    def __enter__(self):
        self.time = time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.time = time() - self.time


def recv_msg(sock):
    header_size = sizeof(MsgHeader)
    header_buf = sock.recv(header_size)
    if len(header_buf) < header_size:
        raise EOFError
    header = MsgHeader.unpack(header_buf)
    buf = bytearray(header.message_length)
    buf[:header_size] = header_buf
    i = header_size
    while i < header.message_length:
        read = sock.recv_into(memoryview(buf)[i:])
        if read == 0:
            raise EOFError
        i += read
    return bytes(buf)


def analyze_find(db, collection, filter_, peer_addr, peer_port):
    match filter_:
        case {"$where": query}:
            output.warning(f"$where: {query!r}")
            logger.log("suspicious_activity", "$where", client=peer_addr, port=peer_port, query=query)
        case _:
            for field, pred in filter_.items():
                if not field.startswith("$"):
                    match pred:
                        case {"$regex": regex}:
                            output.warning(f"$regex: {regex!r}")
                            logger.log("suspicious_activity", "$regex", client=peer_addr, port=peer_port, regex=regex)


def analyze_msg_msg_body_section(body, peer_addr, peer_port):
    match body:
        case {"find": collection, "$db": db, "filter": filter_, **rest}:
            analyze_find(db, collection, filter_, peer_addr, peer_port)


def analyze(msg, direction, peer_addr, peer_port):
    if msg.header.op_code == OP_MSG:
        logger.log(
                direction,
                "msgmsg",
                client=peer_addr,
                port=peer_port,
                request_id=msg.header.request_id,
                response_to=msg.header.response_to,
                sections=msg.sections)
        if direction == "request":
            for section in msg.sections:
                if isinstance(section, BodySection):
                    analyze_msg_msg_body_section(section.body, peer_addr, peer_port)


shutdown_event = Event()


def proxy(peer_sock, mongo_sock, verbose):
    peer_addr, peer_port = peer_sock.getpeername()
    output.info(f"Incoming connection from {peer_addr}:{peer_port}")
    logger.log("connection", "established", client=peer_addr, port=peer_port)

    with DefaultSelector() as selector:
        selector.register(peer_sock, EVENT_READ, mongo_sock)
        selector.register(mongo_sock, EVENT_READ, peer_sock)

        while True:
            selector_events = selector.select(timeout=1)

            if shutdown_event.is_set():
                return

            for (sock, _, _, peer), _ in selector_events:
                try:
                    buf = recv_msg(sock)

                except ConnectionResetError:
                    if sock is peer_sock:
                        output.warning(f"Connection reset by peer {peer_addr}:{peer_port}")
                        logger.log("connection", "reset by peer", client=peer_addr, port=peer_port)
                    else:
                        output.warning(f"Connection reset by upstream server for peer {peer_addr}:{peer_port}")
                        logger.log("connection", "reset by upstream server", client=peer_addr, port=peer_port)
                    return

                except EOFError:
                    if sock is peer_sock:
                        output.info(f"Connection closed by peer {peer_addr}:{peer_port}")
                        logger.log("connection", "closed by peer", client=peer_addr, port=peer_port)
                    else:
                        output.info(f"Connection closed by upstream server for peer {peer_addr}:{peer_port}")
                        logger.log("connection", "closed by upstream server", client=peer_addr, port=peer_port)
                    return

                msg = unpack_msg(buf)

                if verbose:
                    if sock is peer_sock:
                        output.primary(msg)
                    else:
                        output.secondary(msg)

                analyze(msg, "request" if sock is peer_sock else "response", peer_addr, peer_port)

                peer.send(buf)


class MongoHandler(BaseRequestHandler):
    def __init__(self, mongo, verbose):
        self.mongo = mongo
        self.verbose = verbose

    def __call__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def handle(self):
        with socket(AF_INET, SOCK_STREAM) as mongo_sock:
            try:
                mongo_sock.connect(("127.0.0.1", self.mongo.port))
            except ConnectionRefusedError:
                output.warning("Upstream connection refused: is Mongo up?")
                return

            proxy(self.request, mongo_sock, self.verbose)


class ProxyServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True

    def server_close(self):
        shutdown_event.set()
        super().server_close()


def is_mongo_up(mongo_addr, mongo_port, timeout=3):
    try:
        MongoClient(mongo_addr, mongo_port, serverSelectionTimeoutMS=int(timeout*1000)).server_info()
    except ServerSelectionTimeoutError:
        return False
    else:
        return True


def check_mongo(mongo, check_interval):
    was_up = True
    elapsed = ExecTimer()
    while not shutdown_event.wait(max(check_interval-elapsed.time, 0)):
        with elapsed:
            if not is_mongo_up("127.0.0.1", mongo.port):
                output.warning("Mongo is unresponsive. Restarting...")
                logger.log("mongo", "down")
                mongo.restart()
                output.success("Mongo restarted")
                logger.log("mongo", "restarted")


def main():
    output.init()
    args = parser.parse_args()
    logger.init(args.log_file)

    output.info("Starting mongo...")
    with MongoContainer() as mongo:
        for _ in range(3):
            sleep(.5)
            if is_mongo_up("127.0.0.1", mongo.port):
                break
        else:
            output.error(f"Could not connect to Mongo at 127.0.0.1:{mongo.port}")
            sys.exit(1)
        output.info("Mongo started")
        output.success("Ready")
        logger.log("system", "startup")
        atexit.register(lambda: logger.log("system", "shutdown"))
        try:
            Thread(target=check_mongo, args=(mongo, args.check_interval), daemon=False).start()
            with ProxyServer(args.host, MongoHandler(mongo, args.verbose)) as server:
                server.serve_forever()
        finally:
            shutdown_event.set()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        sys.exit(1)
    except (ServerSelectionTimeoutError, NotFound):
        output.error("Mongo seems not to be working\nCheck the output of `docker run -ti --rm mongo:latest'")
        sys.exit(3)
    except DockerException:
        output.error("Docker error (is docker up?)")
        sys.exit(2)
