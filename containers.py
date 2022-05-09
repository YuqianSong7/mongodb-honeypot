
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
import gzip
import json
import subprocess

from time import sleep
from contextlib import suppress

import docker
from docker.errors import NotFound, ImageNotFound

from pymongo import MongoClient

import output


client = docker.from_env()


def ensure_image_exists(name):
    with suppress(ImageNotFound):
        client.images.get(name)
        return
    subprocess.run(["docker", "pull", name], stdout=sys.stderr.buffer)
    client.images.get(name)


def ensure_container_running(container):
    container.reload()
    while container.status != "running":
        sleep(.5)
        container.reload()


class MongoContainer:
    def __init__(self, image="mongo:latest", dataset="primer-dataset.json.gz"):
        self.image = image
        self.dataset = dataset
        self._start()

    def _start(self):
        output.info("Looking for container image...")
        ensure_image_exists(self.image)
        self.container = client.containers.run(
                self.image, detach=True, remove=True,
                ports={"27017/tcp": ("127.0.0.1", None)})
        output.info("Waiting for container to start...")
        ensure_container_running(self.container)
        self.port = int(self.container.ports["27017/tcp"][0]["HostPort"])
        mongo_client = MongoClient("127.0.0.1", self.port)
        output.info("Loading dataset...")
        with gzip.open(self.dataset) as f:
            mongo_client.db.restaurants.insert_many(map(json.loads, f))

    def restart(self):
        with suppress(NotFound):
            self.container.kill()
        self._start()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.container.kill()
