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
Validate BGP peer operation.

usage: validate_bgp_peer.py [-h] [-v] node peer_address

positional arguments:
  node           node streaming interface status
  peer_address   peer address

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
SESSION_STATE_ESTABLISHED = "bgp-st-active"
DEFAULT_INSTANCE = "default"
TIMEOUT = 60


def validate_bgp_peer(kafka_consumer, node, peer_address,
                      session_state=SESSION_STATE_ESTABLISHED,
                      instance_name=DEFAULT_INSTANCE,
                      timeout=TIMEOUT):
    """Validate BGP session state."""
    telemetry_encoding_path = "Cisco-IOS-XR-ipv4-bgp-oper:bgp/instances/instance/instance-active/default-vrf/neighbors/neighbor"
    start_time = time.time()
    for kafka_msg in kafka_consumer:
        msg = json.loads(kafka_msg.value.decode('utf-8'))
        if (msg["Telemetry"]["node_id_str"] == node and
                msg["Telemetry"]["encoding_path"] == telemetry_encoding_path
                and "Rows" in msg):
            for row in msg["Rows"]:
                # return true if BGP session in expected state
                if ("instance-name" in row["Keys"] and
                        "neighbor-address" in row["Keys"] and
                        row["Keys"]["instance-name"] == instance_name and
                        row["Keys"]["neighbor-address"] == peer_address and
                        "connection-state" in row["Content"] and
                        row["Content"]["connection-state"] == session_state
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
    parser.add_argument("peer_address",
                        help="peer address")
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

    print(validate_bgp_peer(kafka_consumer, args.node, args.peer_address))

    exit()
# End of script
