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
from time import time, sleep
from socket import socket, AF_INET, SOCK_STREAM
from selectors import DefaultSelector, EVENT_READ
from socketserver import BaseRequestHandler, TCPServer, ThreadingMixIn
from threading import Thread, Lock, Event
from functools import wraps

import colorama
from colorama import Fore

from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError

from args import parser
from xstruct import sizeof
from messages import MsgHeader, unpack_msg
from containers import MongoContainer


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
                except EOFError:
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
    def __init__(self, mongo):
        self.mongo = mongo

    def __call__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def handle(self):
        with socket(AF_INET, SOCK_STREAM) as mongo_sock:
            try:
                mongo_sock.connect(("127.0.0.1", self.mongo.port))
            except ConnectionRefusedError:
                print("Upstream connection refused: is Mongo up?")
                return

            proxy(self.request, mongo_sock)


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
                print("Mongo is unresponsive. Restarting...")
                mongo.restart()
                print("Mongo restarted")


def main():
    colorama.init(autoreset=True)
    args = parser.parse_args()

    print("Starting mongo...")
    with MongoContainer() as mongo:
        for _ in range(3):
            sleep(.5)
            if is_mongo_up("127.0.0.1", mongo.port):
                break
        else:
            print(f"Could not connect to Mongo at 127.0.0.1:{mongo.port}")
            sys.exit(1)
        print("Mongo started")
        try:
            Thread(target=check_mongo, args=(mongo, args.check_interval), daemon=False).start()
            with ProxyServer(args.host, MongoHandler(mongo)) as server:
                server.serve_forever()
        finally:
            shutdown_event.set()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted")
        sys.exit(1)
