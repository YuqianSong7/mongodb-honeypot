
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


import atexit
import json

from datetime import datetime
from threading import Lock


log_lock = Lock()
log_file = None


@atexit.register
def cleanup():
    if log_file is not None:
        log_file.close()


def init(log_path):
    global log_file
    log_file = open(log_path, "a")


def log(entry_type, event, **data):
    if log_file is None:
        raise RuntimeError("logger.log was called before initialization")

    entry = {
        "timestamp": f"{datetime.utcnow().isoformat()}Z",
        "type": entry_type,
        "event": event,
        **data
    }

    with log_lock:
        json.dump(entry, log_file)
        print(file=log_file, flush=True)
