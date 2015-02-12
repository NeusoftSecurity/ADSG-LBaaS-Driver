# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015, Neusoft ADSG.
#
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

from neutron.db import l3_db
from neutron.db.loadbalancer import loadbalancer_db as lb_db
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.loadbalancer.drivers.Neusoft_ADSG import (
     adsg_exceptions as adsg_ex
)
from neutron.services.loadbalancer.drivers.Neusoft_ADSG import adsg_config
from neutron.services.loadbalancer.drivers.Neusoft_ADSG import adsg_client
from neutron import manager
VERSION = "0.1.1"
LOG = logging.getLogger(__name__)


# TODO - not inheriting; causes issues with Havana
# from neutron.services.loadbalancer.drivers import abstract_driver
# class AdsgDriver(abstract_driver.LoadBalancerAbstractDriver):
class AdsgDriver(object):

    def __init__(self, plugin):
        LOG.info("ADSGDriver: init version=%s", VERSION)
        self.plugin = plugin
        self.config = adsg_config.ADSGConfig()
        self._verify_appliances()


    def _verify_appliances(self):
        LOG.info("ADSGDriver: verifying appliances")

        if len(self.config.devices) == 0:
            LOG.error(_("ADSGDriver: no configured appliances"))

        for k, v in self.config.devices.items():
            try:
                adsg_client.ADSGClient(self.config, dev_info=v,
                                      version_check=True)
            except Exception:
                LOG.error(_("ADSGDriver: unable to connect to configured"
                            "appliance, name=%s"), v['username'])

    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _device_context(self, tenant_id=""):
        return adsg_client.ADSGClient(self.config, tenant_id=tenant_id)

    def _active(self, context, model, vid):
        self.plugin.update_status(context, model, vid, constants.ACTIVE)

    def _failed(self, context, model, vid):
        self.plugin.update_status(context, model, vid, constants.ERROR)

    def _setup_vip_args(self, vip):
        s_pers = None
        c_pers = None
        app_cookie = None
        pname = "openstackcookie"
        if ('session_persistence' in vip and
                vip['session_persistence'] is not None):
            LOG.warn("creating persistence template")
            #HTTP_COOKIE name for openstackcookie
            if vip['session_persistence']['type'] == "HTTP_COOKIE":
                c_pers = pname
            #sourceip
            elif vip['session_persistence']['type'] == "SOURCE_IP":
                s_pers="IpHash"
            #appcookie
            elif vip['session_persistence']['type'] == "APP_COOKIE":
                app_cookie=vip['session_persistence']['cookie_name']
        LOG.warn("pname=%s"%c_pers)
        status = "Enabled"
        if vip['admin_state_up'] is False:
            status = "Disabled"
        LOG.warn("_setup_vip_args = %s, %s, %d", s_pers, c_pers, status)
        return s_pers, c_pers,app_cookie, status
      
    def create_vip(self, context, vip):

        adsg = self._device_context(tenant_id=vip['tenant_id'])
        s_pers, c_pers,app_cookie,status = self._setup_vip_args(vip)
        # for 4 loadbalance
        pbObj=context.session.query(lb_db.Pool).filter_by(id=vip['pool_id']).first()
        protocol=pbObj["protocol"]
        LOG.warn("protocol=%s"%protocol)
        LOG.warn("vip obj=%s"%vip)
        LOG.warn("c_pers=%s"%c_pers)
        LOG.warn("app_cookie=%s"%app_cookie)
        subnet_id=pbObj["subnet_id"]
        LOG.warn("subnet_id=%s"%pbObj["subnet_id"])
        subnet = manager.NeutronManager.get_plugin().get_subnet(context, subnet_id)
        LOG.warn("cidr=%s"%subnet["cidr"])
        try:
            adsg.virtual_server_create(vip['id'], vip['address'],
                              vip['protocol'], vip['protocol_port'],
                                      vip['pool_id'],
                                      s_pers, c_pers,app_cookie, status,subnet["cidr"])
            self._active(context, lb_db.Vip, vip['id'])

        except Exception,e:
            self._failed(context, lb_db.Vip, vip['id'])
            LOG.error(_("create_vip ERROR:%s"),e)
            self.plugin._delete_db_vip(context, vip['id'])
            raise adsg_ex.VipCreateError(vip=vip['id'])

    def update_vip(self, context, old_vip, vip):
        adsg = self._device_context(tenant_id=vip['tenant_id'])
        s_pers, c_pers, app_cookie,status = self._setup_vip_args(vip)
        LOG.warn("vip obj=%s"%vip)
        LOG.warn("c_pers=%s"%c_pers)
        LOG.warn("app_cookie=%s"%app_cookie)
        try:
            LOG.warn("context=%s"%context)
            adsg.virtual_server_update(vip['id'], vip['protocol'],
                                    vip['pool_id'],
                                    s_pers, c_pers,app_cookie, status)
            self._active(context, lb_db.Vip, vip['id'])

        except Exception, e:
            self._failed(context, lb_db.Vip, vip['id'])
            LOG.error(_("update_vip ERROR:%s"),e)
            raise e
    def ddelete_vip(self, context, vip):
       self.plugin._delete_db_vip(context, vip['id'])
    def delete_vip(self, context, vip):
        adsg = self._device_context(tenant_id=vip['tenant_id'])
        LOG.warn("vipdelete obj=%s"%vip)        

        try:
            adsg.virtual_server_delete(vip['id'], vip['pool_id'],vip['protocol'])
            LOG.warn("--test delete vip---")
            self.plugin._delete_db_vip(context, vip['id'])
        except Exception,e:
            self._failed(context, lb_db.Vip, vip['id'])
            LOG.error(_("delete_vip ERROR:%s"),e)
            raise adsg_ex.VipDeleteError(vip=vip['id'])
    def create_pool(self, context, pool):

        adsg = self._device_context(tenant_id=pool['tenant_id'])
        try:
            if pool['lb_method'] == "ROUND_ROBIN":
                    lb_method = "RoundRobin"
            elif pool['lb_method'] == "LEAST_CONNECTIONS":
                    lb_method = "LeastConnections"
            elif pool['lb_method'] == "SOURCE_IP":
                    lb_method = "IpHash" 
            else:
                #by default
                lb_method = "LeastConnections"           
            adsg.service_group_create(pool['id'], lb_method,pool['protocol'])
            self._active(context, lb_db.Pool, pool['id'])
        except Exception,e:
            self._failed(context, lb_db.Pool, pool['id'])
            LOG.error(_("create_pool ERROR:%s"),e)
            self.plugin._delete_db_pool(context, pool['id'])
            raise adsg_ex.SgCreateError(sg=pool['id'])


    def update_pool(self, context, old_pool, pool):
        adsg = self._device_context(tenant_id=pool['tenant_id'])
        try:
            if pool['lb_method'] == "ROUND_ROBIN":
                lb_method = "RoundRobin"
            elif pool['lb_method'] == "LEAST_CONNECTIONS":
                lb_method = "LeastConnections"
            elif pool['lb_method'] == "SOURCE_IP":
                    lb_method = "IpHash"
            else:
                #by default
                lb_method = "LeastConnections"
            adsg.service_group_update(pool['id'], lb_method,pool['protocol'])
            self._active(context, lb_db.Pool, pool['id'])
        except Exception,e:
            self._failed(context, lb_db.Pool, pool['id'])
            LOG.error(_("update_pool ERROR:%s"),e)
            raise adsg_ex.SgUpdateError(sg=pool['id'])
    
    def ddelete_pool(self, context, pool):
        self.plugin._delete_db_pool(context, pool['id'])
    def delete_pool(self, context, pool):
        LOG.warn('delete_pool context=%s, pool=%s' % (context, pool))
        adsg = self._device_context(tenant_id=pool['tenant_id'])
        removed_adsg=False
        try:
            LOG.warn("try to delete service group adsg")
            adsg.service_group_delete(pool['id'],pool["protocol"])
            removed_adsg = True
            self.plugin._delete_db_pool(context, pool['id'])
        except Exception,e:
            if removed_adsg:
                LOG.error(_("SG was REMOVED from ADSG "
                                           "entity but cloud not be removed "
                                          "from OS DB:%s"),e)
                raise e
            else:
                LOG.error(_("SG was not REMOVED from an "
                                           "ADSG entity please contact your "
                                           "admin."),e)
                raise e

    def stats(self, context, pool_id):
        pool_qry = context._session.query(lb_db.Pool).filter_by(id=pool_id)
        vip_id = pool_qry.vip_id
        #adsg = self._device_context(tenant_id=pool_qry.tenant_id)
        #not implements now
        s = {
                "bytes_in": 0,
                "bytes_out": 0,
                "active_connections": 0,
                "total_connections": 0
            }
        return s

    def _get_member_ip(self, context, member, ADSG):
        ip_address = member['address']
        if ADSG.device_info['use_float']:
            fip_qry = context.session.query(l3_db.FloatingIP)
            if (fip_qry.filter_by(fixed_ip_address=ip_address).count() > 0):
                float_address = fip_qry.filter_by(
                    fixed_ip_address=ip_address).first()
                ip_address = str(float_address.floating_ip_address)
        return ip_address

    def _get_member_server_name(self, member, ip_address):
        tenant_label = member['tenant_id'][:5]
        addr_label = str(ip_address).replace(".", "_", 4)
        server_name = "_%s_%s_neutron" % (tenant_label, addr_label)
        return server_name

    def create_member(self, context, member):
        adsg = self._device_context(tenant_id=member['tenant_id'])
        pbObj=context.session.query(lb_db.Pool).filter_by(id=member['pool_id']).first()
        protocol=pbObj["protocol"]
        LOG.warn("protocol=%s"%protocol)


        ip_address = self._get_member_ip(context, member, adsg)
        server_name = self._get_member_server_name(member, ip_address)

        try:
            status = "Enabled"
            if member["admin_state_up"] is False:
                status = "Disabled"

            adsg.member_create(member['pool_id'], ip_address,
                              member['protocol_port'], status,protocol)
            self._active(context, lb_db.Member, member["id"])
        except Exception,e:
            self._failed(context, lb_db.Member, member["id"])
            LOG.error(_("create_member ERROR:%s"),e)
            self.plugin._delete_db_member(context, member['id'])
            raise adsg_ex.MemberCreateError(member=server_name)

    def update_member(self, context, old_member, member):
        adsg = self._device_context(tenant_id=member['tenant_id'])

        pbObj=context.session.query(lb_db.Pool).filter_by(id=member['pool_id']).first()
        protocol=pbObj["protocol"]
        LOG.warn("protocol=%s"%protocol)
        LOG.warn("member=%s"%member)
        ip_address = self._get_member_ip(context, member, adsg)
        server_name = self._get_member_server_name(member, ip_address)

        try:
            status = "Enabled"
            if member["admin_state_up"] is False:
                status = "Disabled"
            adsg.member_update(old_member["pool_id"],member["pool_id"],ip_address,member['protocol_port'],protocol,status)
            self._active(context, lb_db.Member, member["id"])
        except Exception,e:
            self._failed(context, lb_db.Member, member["id"])
            LOG.error(_("update_member ERROR:%s"),e)
            raise adsg_ex.MemberUpdateError(member=server_name)
    def ddelete_member(self, context, member):
        self.plugin._delete_db_member(context, member['id'])
    def delete_member(self, context, member):
        adsg = self._device_context(tenant_id=member['tenant_id'])
        # for 4 loadbalance
        pbObj=context.session.query(lb_db.Pool).filter_by(id=member['pool_id']).first()
        protocol=pbObj["protocol"]
        LOG.warn("protocol=%s"%protocol)
        LOG.warn("member=%s"%member)
        ip_address = self._get_member_ip(context, member, adsg)
        server_name = self._get_member_server_name(member, ip_address)
        LOG.warn("server_name=%s"%server_name)
        try:


            adsg.member_delete(member['pool_id'], ip_address,
                                  member['protocol_port'],protocol)

            self.plugin._delete_db_member(context, member['id'])
        except Exception:
            self._failed(context, lb_db.Member, member["id"])
            raise adsg_ex.MemberDeleteError(member=member["id"])

    def update_health_monitor(self, context, old_health_monitor,
                                   health_monitor, pool_id):
        adsg = self._device_context(tenant_id=health_monitor['tenant_id'])
        hm_name = health_monitor['id'][0:28]
        # for 4 loadbalance
        pbObj=context.session.query(lb_db.Pool).filter_by(id=pool_id).first()
        protocol=pbObj["protocol"]
        LOG.warn("protocol=%s"%protocol)
        try:
            adsg.health_monitor_update(health_monitor['type'],
                                      pool_id,
                                      health_monitor['delay'],
                                      health_monitor['timeout'],
                                      health_monitor['max_retries'],
                                      hm_name,protocol,health_monitor.get('http_method'),
                                      health_monitor.get('url_path'),
                                      health_monitor.get('expected_codes'))

            self.plugin.update_pool_health_monitor(context,
                                                   health_monitor["id"],
                                                   pool_id,
                                                   constants.ACTIVE)

        except Exception,e:
            LOG.error(_("update_health_monitor ERROR:%s"),e)
            
            raise adsg_ex.HealthMonitorUpdateError(hm=hm_name)

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        adsg = self._device_context(tenant_id=health_monitor['tenant_id'])
        hm_name = health_monitor['id'][0:28]
                # for 4 loadbalance
        pbObj=context.session.query(lb_db.Pool).filter_by(id=pool_id).first()
        protocol=pbObj["protocol"]

        try:

            LOG.warn("health_monitor=%s"%health_monitor)
            adsg.health_monitor_create(health_monitor['type'],
                                      pool_id,
                                      health_monitor['delay'],
                                      health_monitor['timeout'],
                                      health_monitor['max_retries'],
                                      hm_name,protocol,health_monitor.get('http_method'),
                                      health_monitor.get('url_path'),
                                      health_monitor.get('expected_codes'))
            self.plugin.update_pool_health_monitor(context,
                                                   health_monitor["id"],
                                                   pool_id,
                                                   constants.ACTIVE)
        except Exception,e:
            self.plugin.update_pool_health_monitor(context,
                                                    health_monitor["id"],
                                                    pool_id,
                                                    constants.ERROR)
            self.plugin._delete_db_pool_health_monitor(context,
                                                        health_monitor['id'],
                                                        pool_id)
            LOG.error(_("create_pool_health_monitor ERROR:%s"),e)
            raise adsg_ex.HealthMonitorUpdateError(hm=hm_name)
    def ddelete_pool_health_monitor(self, context, health_monitor, pool_id):
        self.plugin._delete_db_pool_health_monitor(context,
                                                       health_monitor['id'],
                                                       pool_id)
    def delete_pool_health_monitor(self, context, health_monitor, pool_id):
        adsg = self._device_context(tenant_id=health_monitor['tenant_id'])
        pbObj=context.session.query(lb_db.Pool).filter_by(id=pool_id).first()
        protocol=pbObj["protocol"]
        try:
            adsg.health_monitor_delete(pool_id,protocol)

            self.plugin._delete_db_pool_health_monitor(context,
                                                       health_monitor['id'],
                                                       pool_id)
        except Exception,e:
            self.plugin.update_pool_health_monitor(context,
                                                   health_monitor["id"],
                                                   pool_id,
                                                   constants.ERROR)
            LOG.error(_("delete_pool_health_monitor ERROR:%s"),e)
