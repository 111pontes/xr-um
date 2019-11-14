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
Withdraw peer configuration.

usage: withdraw_peers.py [-h] [-v] FILE

positional arguments:
  peer_config_file_name    peer configuration file (JSON)

optional arguments:
  -h, --help               show this help message and exit
  -v, --verbose            print debugging messages
"""

import sys
import json
import datetime
import argparse
import logging

from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_um_interface_cfg as xr_um_interface_cfg
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_um_router_bgp_cfg as xr_um_router_bgp_cfg

from remove_peer_interface import peer_interface_remove_filter
from remove_bgp_peer import bgp_peer_remove_filter


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
    # connect to LER
    provider = NetconfServiceProvider(address=address,
                                      username=USERNAME,
                                      password=PASSWORD)

    # create CRUD service
    crud = CRUDService()

    return provider, crud


def format_validate_msg(status):
    """Format validation message in color"""
    OK = '\033[92m OK \033[0m'
    FAIL = '\033[91mFAIL\033[0m'
    if status:
        return OK
    else:
        return FAIL


def withdraw_peer_interface(provider, crud, peer):
    """Withdraw peer interface configuration"""
    # interface configuration filter
    interfaces = xr_um_interface_cfg.Interfaces()
    peer_interface_remove_filter(interfaces, 
                                 name=peer["interface"]["name"])

    # update configuration on NETCONF device
    crud.update(provider, interfaces)


def withdraw_bgp_peer(provider, crud, asbr, peer):
    """Withdraw BGP peer configuration"""
    # BGP configuration filter
    router = xr_um_router_bgp_cfg.Router()
    bgp_peer_remove_filter(router, 
                           local_as=asbr["as"],
                           peer_address=peer["address"])

    # update configuration on NETCONF device
    crud.update(provider, router)


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

    print("{}: Initializing NETCONF connection ".format(datetime.datetime.now().time()).ljust(PLEN, PCHAR),
          end='', flush=True)
    provider, crud = init_connections(config["asbr"]["address"])
    print(" [{}]".format(format_validate_msg(True)))

    # remove peers
    for peer in config["peers"]:
        print("{}: Remove peer interface {} ".format(datetime.datetime.now().time(),
                                                     peer["interface"]["name"]).ljust(PLEN, PCHAR),
              end='', flush=True)
        withdraw_peer_interface(provider, crud, peer)
        print(" [{}]".format(format_validate_msg(True)))

        print("{}: Remove BGP peer {} ".format(datetime.datetime.now().time(),
                                                      peer["address"]).ljust(PLEN, PCHAR),
              end='', flush=True)
        withdraw_bgp_peer(provider, crud, config["asbr"], peer)
        print(" [{}]".format(format_validate_msg(True)))

    sys.exit()
# End of script
