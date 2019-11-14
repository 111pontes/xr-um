#!/usr/bin/env python3
#
# Copyright 2019 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Validate peer interface operation.

usage: validate_peer_interface.py [-h] [-v] node name

positional arguments:
  node           node streaming interface status
  name           interface name

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  print debugging messages
"""

import kafka
import json
import time
import argparse
import logging


KAFKA_TOPIC = 'pipeline'
KAFKA_BOOTSTRAP_SERVER = 'localhost:9092'
STATE_UP = "im-state-up"
TIMEOUT = 30


def validate_peer_interface(kafka_consumer, node, name,
                            state=STATE_UP,
                            timeout=TIMEOUT):
    """Validate interface state."""
    telemetry_encoding_path = "Cisco-IOS-XR-pfi-im-cmd-oper:interfaces/interface-briefs/interface-brief"
    start_time = time.time()
    for kafka_msg in kafka_consumer:
        msg = json.loads(kafka_msg.value.decode('utf-8'))
        if (msg["Telemetry"]["node_id_str"] == node and
                msg["Telemetry"]["encoding_path"] == telemetry_encoding_path
                and "Rows" in msg):
            for row in msg["Rows"]:
                # return true if intf in expected oper/admin state
                if ("interface-name" in row["Keys"] and
                        row["Keys"]["interface-name"] == name and
                        "state" in row["Content"] and
                        "line-state" in row["Content"] and
                        row["Content"]["state"] == state and
                        row["Content"]["line-state"] == state
                        ):
                    return True

        if time.time() - start_time > timeout:
            break

    return False


if __name__ == "__main__":
    """Execute main program."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging messages",
                        action="store_true")
    parser.add_argument("node",
                        help="node router streaming interface status")
    parser.add_argument("name",
                        help="interface name")
    args = parser.parse_args()

    # log debug messages if verbose argument specified
    if args.verbose:
        logger = logging.getLogger("kafka")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(("%(asctime)s - %(name)s - "
                                      "%(levelname)s - %(message)s"))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # create kafka consumer to pipeline topic
    kafka_consumer = kafka.KafkaConsumer(KAFKA_TOPIC,
                                         bootstrap_servers=KAFKA_BOOTSTRAP_SERVER,
                                         consumer_timeout_ms=TIMEOUT*1000)

    print(validate_peer_interface(kafka_consumer, args.node, args.name))

    exit()
# End of script
