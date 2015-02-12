# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015,  Neusoft ADSG.
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

import sys

from neutron.common import exceptions
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class ADSGBaseException(exceptions.NeutronException):
    def __init__(self, **kwargs):
        LOG.debug("ADSGBaseException", exc_info=sys.exc_info())
        super(ADSGBaseException, self).__init__(**kwargs)


class ADSGDeviceException(ADSGBaseException):
    message = _('An unknown exception occurred in ADSGLBaaS provider.')


class ADSGDeviceNoSession(ADSGBaseException):
    message = _('Unable to get session id from appliance')


class ADSGDeviceNoDevices(ADSGBaseException):
    message = _('No configured and active devices')


class ADSGDeviceVersionMismatch(ADSGBaseException):
    message = _("ADSGClient: driver requires ADSG version 1.3.12+")


class UnsupportedFeatureAppCookie(ADSGBaseException):
    message = _(
        'This version of the driver does not support this'
        ' feature in this release.')


class VipCreateError(ADSGBaseException):
    message = _(
        'VIP %(vip)s could not be created.')


class VipUpdateError(ADSGBaseException):
    message = _(
        'VIP %(vip)s could not be Updated.')
class VipGetError(ADSGBaseException):
    message = _(
        'VIP %(vip)s could not be GET.')



class VipDeleteError(ADSGBaseException):
    message = _(
        'VIP %(vip)s could not be Deleted.')


class SgCreateError(ADSGBaseException):
    message = _(
        'ServiceGroup %(sg)s could not be created.')

class SgGetError(ADSGBaseException):
    message = _(
        'ServiceGroup %(sg)s could not be Get.')


class SgUpdateError(ADSGBaseException):
    message = _(
        'ServiceGroup %(sg)s could not be Updated.')


class SgDeleteError(ADSGBaseException):
    message = _(
        'ServiceGroup %(sg)s could not be Deleted.')


class MemberCreateError(ADSGBaseException):
    message = _(
        'Member %(member)s could not be created.')


class MemberUpdateError(ADSGBaseException):
    message = _(
        'Member %(member)s could not be Updated.')

class MemberEmptyError(ADSGBaseException):
    message = _(
        'Member Empty.')

class MemberDeleteError(ADSGBaseException):
    message = _(
        'Member %(member)s could not be Deleted.')


class HealthMonitorCreateError(ADSGBaseException):
    message = _(
        'HealthMonitor %(hm)s could not be created.')


class HealthMonitorUpdateError(ADSGBaseException):
    message = _(
        'HealthMonitor %(hm)s could not be Updated.')


class HealthMonitorDeleteError(ADSGBaseException):
    message = _(
        'HealthMonitor %(hm)s could not be Deleted.')

class TemplateError(ADSGBaseException):
    message = _(
        'Template %(template)s could not be created.')


class TemplateCreateError(ADSGBaseException):
    message = _(
        'Template %(template)s could not be created.')


class TemplateUpdateError(ADSGBaseException):
    message = _(
        'Template %(template)s could not be Updated.')


class TemplateDeleteError(ADSGBaseException):
    message = _(
        'Template %(template)s could not be Deleted.')


class SearchError(ADSGBaseException):
    message = _(
        'Search Error: %(term)s')


class ADSGNoDevices(ADSGBaseException):
    message = _(
        'Search Error: %(term)s')
