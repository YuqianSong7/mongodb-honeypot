
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


from argparse import ArgumentParser


default_host = "localhost", 27017
default_mongo_host = "localhost", 27016


def parse_host(default_address, default_port):
    def parse(s):
        address, sep, port = s.partition(":")
        return address or default_address, int(port or default_port)
    return parse


parser = ArgumentParser(description="Configure mongodb-honeypot-monitor")
parser.add_argument("-H", "--host", default=default_host, type=parse_host(*default_host), help="ADDRESS:PORT to bind the monitor to")
parser.add_argument("-m", "--mongo-host", default=default_mongo_host, type=parse_host(*default_mongo_host), help="ADDRESS:PORT of the running mongodb instance")
parser.add_argument("-t", "--check-interval", default=5., type=float, help="Every how many seconds to check for mongodb being up")


if __name__ == "__main__":
    print(parser.parse_args())
