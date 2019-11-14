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
#

"""
Remove configuration for BGP peer.

usage: remove_bgp_peer.py [-h] [-v] local_as peer_address device

positional arguments:
  local_as       local autonomous system
  peer_address   peer address
  device         NETCONF device (ssh://user:password@host:port)

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  print debugging messages
"""

import argparse
import urllib.parse
import logging

from ydk.services import CRUDService
from ydk.providers import NetconfServiceProvider
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_um_router_bgp_cfg as xr_um_router_bgp_cfg
from ydk.filters import YFilter


def bgp_peer_remove_filter(router, local_as, peer_address):
    "Define filter to remove BGP peer"
    as_ = router.bgp.As()
    as_.as_number = local_as

    neighbor = as_.neighbors.Neighbor()
    neighbor.neighbor_address = peer_address
    neighbor.yfilter = YFilter.remove

    as_.neighbors.neighbor.append(neighbor)
    router.bgp.as_.append(as_)


if __name__ == "__main__":
    """Execute main program."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", 
                        help="print debugging messages",
                        action="store_true")
    parser.add_argument("local_as",
                        help="local autonomous system")
    parser.add_argument("peer_address",
                        help="peer address")
    parser.add_argument("device",
                        help="NETCONF device (ssh://user:password@host:port)")
    args = parser.parse_args()
    device = urllib.parse.urlparse(args.device)

    # log debug messages if verbose argument specified
    if args.verbose:
        logger = logging.getLogger("ydk")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(("%(asctime)s - %(name)s - "
                                      "%(levelname)s - %(message)s"))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # create NETCONF provider
    provider = NetconfServiceProvider(address=device.hostname,
                                      port=device.port,
                                      username=device.username,
                                      password=device.password,
                                      protocol=device.scheme)
    # create CRUD service
    crud = CRUDService()

    # BGP configuration filter
    router = xr_um_router_bgp_cfg.Router()
    bgp_peer_remove_filter(router, args.local_as, args.peer_address)

    # update configuration on NETCONF device
    crud.update(provider, router)

    exit()
# End of script
