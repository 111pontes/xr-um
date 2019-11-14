#!/usr/bin/env python3
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
Deploy peer configuration.

usage: deploy_peer.py [-h] [-v] FILE

positional arguments:
  peer_config_file_name    peer configuration file (JSON)

optional arguments:
  -h, --help               show this help message and exit
  -v, --verbose            print debugging messages
"""

import kafka
import sys
import json
import datetime
import argparse
import logging

from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_um_interface_cfg as xr_um_interface_cfg
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_um_router_bgp_cfg as xr_um_router_bgp_cfg

from config_peer_interface import config_peer_interface
from validate_peer_interface import validate_peer_interface
from config_bgp_peer import config_bgp_peer
from validate_bgp_peer import validate_bgp_peer

KAFKA_TOPIC = 'pipeline'
KAFKA_BOOTSTRAP_SERVER = "localhost:9092"
KAFKA_TIMEOUT = 30

VALIDATE_TIMEOUT = 60

USERNAME = PASSWORD = "admin"
PLEN = 70  # output padding length
PCHAR = '.'  # output padding character

sys.dont_write_bytecode = True


def load_peer_config_file(peer_config_file_name):
    """Load peer configuration file (JSON)"""
    with open(peer_config_file_name) as peer_config_file:
        config = json.load(peer_config_file)

    return config


def init_connections(address):
    """Initialize all connections"""
    # create kafka consumer to pipeline topic
    kafka_consumer = kafka.KafkaConsumer(KAFKA_TOPIC,
                                         bootstrap_servers=KAFKA_BOOTSTRAP_SERVER,
                                         consumer_timeout_ms=KAFKA_TIMEOUT*1000)

    # connect to LER
    provider = NetconfServiceProvider(address=address,
                                      username=USERNAME,
                                      password=PASSWORD)

    # create CRUD service
    crud = CRUDService()

    return kafka_consumer, provider, crud


def format_validate_msg(status):
    """Format validation message in color"""
    OK = '\033[92m OK \033[0m'
    FAIL = '\033[91mFAIL\033[0m'
    if status:
        return OK
    else:
        return FAIL


def deploy_peer_interface(kafka_consumer, provider, crud, asbr, peer):
    """Configure and validate peer interface"""
    # interface configuration
    interfaces = xr_um_interface_cfg.Interfaces()
    config_peer_interface(interfaces,
                          name=peer["interface"]["name"],
                          description=peer["interface"]["description"],
                          address=peer["interface"]["address"],
                          netmask=peer["interface"]["netmask"])

    # create configuration on NETCONF device
    crud.create(provider, interfaces)

    return validate_peer_interface(kafka_consumer,
                                   asbr["name"],
                                   peer["interface"]["name"],
                                   timeout=VALIDATE_TIMEOUT)


def deploy_bgp_peer(kafka_consumer, provider, crud, asbr, peer):
    """Configure and validate BGP peer"""
    # BGP peer configuration
    router = xr_um_router_bgp_cfg.Router()
    config_bgp_peer(router,
                    local_as=asbr["as"],
                    neighbor_address=peer["address"],
                    remote_as=peer["as"],
                    neighbor_group=peer["group"])

    # create configuration on NETCONF device
    crud.create(provider, router)

    return validate_bgp_peer(kafka_consumer,
                             asbr["name"],
                             peer["address"],
                             timeout=VALIDATE_TIMEOUT)


if __name__ == "__main__":
    """Execute main program."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging messages",
                        action="store_true")
    parser.add_argument("peer_config_file_name",
                        help="peer configuration file (JSON)")
    args = parser.parse_args()

    # log debug messages if verbose argument specified
    if args.verbose:
        logger = logging.getLogger("ydk")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(("%(asctime)s - %(name)s - "
                                      "%(levelname)s - %(message)s"))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    print("{}: Loading peer config ".format(datetime.datetime.now().time()).ljust(PLEN, PCHAR),
          end='', flush=True)
    config = load_peer_config_file(args.peer_config_file_name)
    print(" [{}]".format(format_validate_msg(True)))

    print("{}: Initializing Kafka and NETCONF connections ".format(datetime.datetime.now().time()).ljust(PLEN, PCHAR),
          end='', flush=True)
    kafka_consumer, provider, crud = init_connections(config["asbr"]["address"])
    print(" [{}]".format(format_validate_msg(True)))

    # deploy peers
    for peer in config["peers"]:
        print("{}: Configure peer interface {} ".format(datetime.datetime.now().time(),
                                                        peer["interface"]["name"]).ljust(PLEN, PCHAR),
              end='', flush=True)
        peer_interface_status = deploy_peer_interface(kafka_consumer, provider, crud,
                                                      config["asbr"],
                                                      peer)
        print(" [{}]".format(format_validate_msg(peer_interface_status)))

        # deploy BGP peer if peer interface deployed successfully
        if peer_interface_status:
            print("{}: Configure BGP peer {} ".format(datetime.datetime.now().time(),
                                                      peer["address"]).ljust(PLEN, PCHAR),
                  end='', flush=True)
            bgp_peer_status = deploy_bgp_peer(kafka_consumer, provider, crud,
                                              config["asbr"],
                                              peer)
            print(" [{}]".format(format_validate_msg(bgp_peer_status)))

    sys.exit()
# End of script
