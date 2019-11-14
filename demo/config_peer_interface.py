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
Create configuration for peer interface.

usage: config_peer_interface.py [-h] [-v] name description address netmask device

positional arguments:
  name           interface name
  description    interfaces description
  address        interface address
  netmask        interface network mask
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
from ydk.models.cisco_ios_xr import Cisco_IOS_XR_um_interface_cfg as xr_um_interface_cfg
from ydk.filters import YFilter


def config_peer_interface(interfaces, name, description, address, netmask):
    """Add config data to interfaces object."""
    # configure interface
    interface = interfaces.Interface()
    interface.interface_name = name
    interface.description = description

    # configure ip address
    address_ = interface.ipv4.addresses.Address()
    address_.address = address
    address_.netmask = netmask

    # unshut interface
    interface.shutdown = interface.Shutdown()
    interface.shutdown.yfilter = YFilter.remove

    interface.ipv4.addresses.address = address_
    interfaces.interface.append(interface) 


if __name__ == "__main__":
    """Execute main program."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", 
                        help="print debugging messages",
                        action="store_true")
    parser.add_argument("name",
                        help="interface name")
    parser.add_argument("description",
                        help="interfaces description")
    parser.add_argument("address",
                        help="interface address")
    parser.add_argument("netmask",
                        help="interface network mask")
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

    # interface configuration
    interfaces = xr_um_interface_cfg.Interfaces()
    config_peer_interface(interfaces, args.name, args.description, args.address, args.netmask)

    # create configuration on NETCONF device
    crud.create(provider, interfaces)

    exit()
# End of script
