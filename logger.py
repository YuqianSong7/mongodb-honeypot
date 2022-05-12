
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


import os
import re
import atexit
import json
import gzip
import shutil

from pathlib import Path
from datetime import datetime
from threading import Lock, Thread

from bson import Binary
from messages import BodySection, DocumentSequenceSection



log_lock = Lock()
log_file = None
threshold = None


@atexit.register
def cleanup():
    if log_file is not None:
        log_file.close()


def init(log_path, log_rotation_threshold=100*1024*1024):
    global log_file, threshold
    log_file = open(log_path, "a")
    threshold = log_rotation_threshold


def convert_bson(obj):
    if isinstance(obj, Binary):
        return {"$bson": "binary", "value": obj.hex()}
    elif isinstance(obj, BodySection):
        return {"$mongo": "msgmsg_body", "body": obj.body}
    elif isinstance(obj, DocumentSequenceSection):
        return {
            "$mongo": "msgmsg_document_sequence",
            "body": obj.body,
            "document_sequence_identifier": obj.document_sequence_identifier,
            "documents": obj.documents
        }


def rotate_log():
    global log_file
    log_path = Path(log_file.name).resolve()
    log_re = re.compile(rf"{re.escape(log_path.name)}\.(\d+)\.gz")
    n = 0
    for file in log_path.parent.iterdir():
        if m := log_re.match(file.name):
            n = max(n, int(m.group(1))+1)
    log_file.close()
    with open(log_path, "rb") as log_file:
        with gzip.open(f"{log_path}.{n:03}.gz", "wb") as gzipped_log:
            shutil.copyfileobj(log_file, gzipped_log)
    log_file = open(log_path, "w")


def log_entry(entry):
    if os.fstat(log_file.fileno()).st_size > threshold:
        rotate_log()
    json.dump(entry, log_file, default=convert_bson)
    print(file=log_file, flush=True)


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
        t = Thread(target=log_entry, args=(entry,))
        t.start()
        t.join()
