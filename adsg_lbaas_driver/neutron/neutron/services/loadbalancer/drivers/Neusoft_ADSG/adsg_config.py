# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015,  Neusoft ADSG .
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging
import os
import sys

from neutron.services.loadbalancer.drivers.Neusoft_ADSG import adsg_exceptions

config_dir = "/etc/neutron/services/loadbalancer/Neusoft_ADSG"


LOG = logging.getLogger(__name__)


class ADSGConfig(object):

    def __init__(self):
        config_path = os.path.join(config_dir, "config.py")
        real_sys_path = sys.path
        sys.path = [config_dir]
        try_ini = False
        try:
            import config
            self.config = config
            self.devices = {}
            for k, v in self.config.devices.items():
                if v['status']:
                    self.devices[k] = v
                else:
                    LOG.debug("status is False, skipping dev: %s", v)
        except ImportError:
            try_ini = True
        finally:
            sys.path = real_sys_path
        if try_ini:
            LOG.error("ADSGDriver: missing config file at: %s", config_path)
            raise adsg_exceptions.ADSGDeviceException()
        LOG.debug("ADSGConfig, devices=%s", self.devices)

