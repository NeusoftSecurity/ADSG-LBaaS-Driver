
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

import hashlib
import httplib
import json
import re
import socket
import ssl
import traceback
import copy
import types
import netaddr

from neutron.openstack.common import log as logging
from neutron.services.loadbalancer.drivers.Neusoft_ADSG import (
    adsg_exceptions as adsg_ex)

from neutron.services.loadbalancer.drivers.Neusoft_ADSG import (
    request_struct_adsg
)


# Neutron logs
LOG = logging.getLogger(__name__)

def force_tlsv1_connect(self):
    sock = socket.create_connection((self.host, self.port), self.timeout)
    if self._tunnel_host:
        self.sock = sock
        self._tunnel()
    self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                ssl_version=ssl.PROTOCOL_TLSv1)

class ADSGClient(object):

     def __init__(self, config,tenant_id="", dev_info=None,
                 version_check=False):
        self.config = config
        self.tenant_id = tenant_id
        self.device_info = dev_info or self.select_device(tenant_id=tenant_id)
        self.set_base_url()
        LOG.debug ("ADSGClient init: connecting %s", self.base_url)
        self.force_tlsv1 = False
        self.session_id = None
        self.get_session_id()
        if self.session_id is None:
            message = ("ADSGClient: unable to get session_id from ax")
            LOG.debug (message)

        if version_check:
            self.check_version()
        LOG.debug ("ADSGClient init: connected, session_id=%s", self.session_id)
        self.funcSet={
           "HTTP_POOL_CREATE":self.L7_service_group_create,
           "HTTP_POOL_UPDATE":self.L7_service_group_update,
           "HTTP_POOL_DELETE":self.L7_service_group_delete,
           "HTTP_VIP_CREATE":self.L7_virtual_server_create,
           "HTTP_VIP_UPDATE":self.L7_virtual_server_update,
           "HTTP_VIP_DELETE":self.L7_virtual_server_delete,
           "HTTP_MEMBER_CREATE":self.L7_member_create,
           "HTTP_MEMBER_UPDATE":self.L7_member_update,
           "HTTP_MEMBER_DELETE":self.L7_member_delete,
           "HTTP_HM_CREATE":self.L7_health_monitor_set,
           "HTTP_HM_UPDATE":self.L7_health_monitor_set,
           "HTTP_HM_DELETE":self.L7_health_monitor_set,
           
           "HTTPS_POOL_CREATE":self.L7_service_group_create,
           "HTTPS_POOL_UPDATE":self.L7_service_group_update,
           "HTTPS_POOL_DELETE":self.L7_service_group_delete,
           "HTTPS_VIP_CREATE":self.L7_virtual_server_create,
           "HTTPS_VIP_UPDATE":self.L7_virtual_server_update,
           "HTTPS_VIP_DELETE":self.L7_virtual_server_delete,
           "HTTPS_MEMBER_CREATE":self.L7_member_create,
           "HTTPS_MEMBER_UPDATE":self.L7_member_update,
           "HTTPS_MEMBER_DELETE":self.L7_member_delete,
           "HTTPS_HM_CREATE":self.L7_health_monitor_set,
           "HTTPS_HM_UPDATE":self.L7_health_monitor_set,
           "HTTPS_HM_DELETE":self.L7_health_monitor_set,

           "TCP_POOL_CREATE":self.L4_service_group_create,
           "TCP_POOL_UPDATE":self.L4_service_group_update,
           "TCP_POOL_DELETE":self.L4_service_group_delete,
           "TCP_VIP_CREATE":self.L4_virtual_server_create,
           "TCP_VIP_UPDATE":self.L4_virtual_server_update,
           "TCP_VIP_DELETE":self.L4_virtual_server_delete,
           "TCP_MEMBER_CREATE":self.L4_member_create,
           "TCP_MEMBER_UPDATE":self.L4_member_update,
           "TCP_MEMBER_DELETE":self.L4_member_delete,
           "TCP_HM_CREATE":self.L4_health_monitor_set,
           "TCP_HM_UPDATE":self.L4_health_monitor_set,
           "TCP_HM_DELETE":self.L4_health_monitor_set,

        }

        self.l4algset={"RoundRobin":"rr","LeastConnections":"lc","IpHash":"sh"}

     def set_base_url(self):
        self.protocol = "https"
        port="10000"
        if "port" in self.device_info:
            port=self.device_info["port"]
        self.host = self.device_info["host"]
        self.port = int(port)
        self.localips=self.device_info["localips"]
        if "protocol" in self.device_info:
            self.protocol = self.device_info['protocol']

        self.base_url = "%s://%s:%d" % (self.protocol, self.host, self.port)

     def send(self, method="", url="", body={},
             close_session_after_request=True,header={}):
        if self.session_id is None:
            self.get_session_id()

        if url.find('%') >= 0 and self.session_id is not None:
            url = url % self.session_id
        LOG.warn ("send: body = %s"%body)
        header["Cookie"]='JSESSIONID=%s'%self.session_id

        r = self.axapi_http(method, url, body, header=header)

        if close_session_after_request:
            LOG.debug ("about to close session after req")
            self.close_session()
            LOG.debug ("session closed")

        return r

     def get_cookie(self, method , api_url, params={}):
         if self.protocol == 'https':
            http = httplib.HTTPSConnection(self.host, self.port)
            http.connect = lambda: force_tlsv1_connect(http)
         else:
            http = httplib.HTTPConnection(self.host, self.port)

         headers = {
            "Content-Type":"application/json"
         }

         LOG.debug ("axapi_http: start")
         LOG.debug ("axapi_http: url = %s", api_url)
         LOG.debug ("axapi_http: params = %s", params)

         if params:
            payload = json.dumps(params)
         else:
            payload = None

         http.request(method, api_url, payload, headers)

         res=http.getresponse()

         cookie = res.getheaders()

         LOG.debug  ("cookie:%s",cookie)
         cookieToJson = json.dumps(cookie)
         LOG.debug  ("cookieToJson:%s",cookieToJson)
         return json.loads(cookieToJson)

     def close_session(self):

         url = ("/Administration/rest/adsg/auth/logout")
         headers = {"Accept":"application/json"}
         headers["Cookie"]='JSESSIONID=%s'%self.session_id
         results = self.axapi_http("GET",url,header=headers)
         errorCode = int(results["data"]["errorCode"])
         if(errorCode == 0):
             self.session_id = None
             LOG.debug  ("close session success")

         else:
             LOG.debug ("close session failed.")
     def inspect_response(self, response, func=None):
         LOG.debug ("inspect_response: %s"%response)
         if "data" in response:
             if "errorCode" in response["data"] and response["data"]["errorCode"] == "0":
                 return True

         return False



     def axapi_http(self, method, api_url, body={},header={}):

         LOG.warn ("axapi_http: params body= %s"%body)
         if self.protocol == 'https':
            http = httplib.HTTPSConnection(self.host, self.port)
            http.connect = lambda: force_tlsv1_connect(http)
         else:
            http = httplib.HTTPConnection(self.host, self.port)

         LOG.warn("axapi_http: method = %s"%method)
         LOG.warn("axapi_http: url = %s"%api_url)
         LOG.warn("axapi_http: header = %s"%header)
         if body:
            payload = json.dumps(body)

         else:
            payload = None
         LOG.warn ("axapi_http: payload = %s"% payload)
         http.request(method, api_url, payload,header)

         res = http.getresponse()

         data = res.read()

         LOG.warn("axapi_http:axapi return data = %s", data)

         return json.loads(data)


     def get_session_id(self):

        auth_url ="/Administration/rest/adsg/auth/login"
        params = {
            "name":self.device_info["username"],
            "password":self.device_info["password"],
            "language":"zh_CN"
        }

        try:
            r = self.get_cookie("POST", auth_url, params)
            LOG.debug("reponse datar %s" , r)
            for x in r:
                if "set-cookie" in x and len(x) > 1:
                    for item in x:

                        index = str(item).find("JSESSIONID")
                        if index >= 0 :
                            arr = item.split(";")
                            for js in arr:

                                if str(js).find("JSESSIONID") >= 0:
                                    self.session_id = js.split("=")[1]

        except Exception as e:
            tlsv1_error = "SSL23_GET_SERVER_HELLO:tlsv1 alert protocol version"
            if self.force_tlsv1 is False and str(e).find(tlsv1_error) >= 0:
                # workaround ssl version
                self.force_tlsv1 = True
                self.get_session_id()
            else:
                LOG.error("get_session_id failed: %s", e)
                LOG.error(traceback.format_exc())
                self.session_id = None

     def check_version(self):

        info_url = ("/Administration/rest/adsg/monitor/sys/getSystemInfo?accountId=1")
        headers = {
            "Accept":"application/json",
         }
        headers["Cookie"]='JSESSIONID=%s'%self.session_id
        LOG.debug("headers:",headers)

        r = self.axapi_http("GET", info_url , header=headers)

        if int(r["data"]["errorCode"]) == 0 :
            version=r["data"]["rawResourceList"]["SystemInformation"]["Version"]
            LOG.debug("version:",version)
            major = int(version["Major"])
            minor = int(version["Minor"])

            m = re.match("^(\d+)", version["Patch"])
            dot = 0
            if m is not None:
                dot = int(m.group(1))
            LOG.debug("major=%s,minor=%s,patch=%s",major,minor,dot)
            if major < 1 or minor < 3 or dot < 12:
                LOG.debug("AdsgClient: driver requires ADSG version 1.3.12+")



     def L7_service_group_create(self, name, lb_method,protocol):
        pool_create_req = (request_struct_adsg.service_group_json_obj.call
                           .create.toDict().items())

        pool_ds = (request_struct_adsg.service_group_json_obj.ds.toDict())
        pool_ds['data']['resourceList']['Pool'][0]["protocol"] = protocol
        pool_ds['data']['resourceList']['Pool'][0]["name"] = name
        pool_ds['data']['resourceList']['Pool'][0]["loadBalancingAlgorithm"] = lb_method

        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",

         }
        r = self.send(
                      method=pool_create_req[0][0],
                      url=pool_create_req[0][1],
                      body=pool_ds,header=headers)
        if self.inspect_response(r) is not True:
           LOG.error ("create service_group failed.poolname=%s"%name)
           raise adsg_ex.SgCreateError(sg=name)
        else:
           LOG.info ("create service_group success.poolname=%s"%name)

     def L4_service_group_create(self, name, lb_method,protocol):
        pool_create_req = (request_struct_adsg.service_L4_group_json_obj.call
                           .create.toDict().items())

        pool_ds = (request_struct_adsg.service_L4_group_json_obj.ds.toDict())
        pool_ds['data']['resourceList']['L4Pool'][0]["protocol"] = protocol
        pool_ds['data']['resourceList']['L4Pool'][0]["name"] = name
        pool_ds['data']['resourceList']['L4Pool'][0]["loadBalanceAlgorithm"] = self.l4algset[lb_method]

        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",

         }
        r = self.send(
                      method=pool_create_req[0][0],
                      url=pool_create_req[0][1],
                      body=pool_ds,header=headers)
        if self.inspect_response(r) is not True:
           LOG.error ("create service_group failed.poolname=%s"%name)
           raise adsg_ex.SgCreateError(sg=name)
        else:
           LOG.info ("create service_group success.poolname=%s"%name)

     def service_group_create(self, name, lb_method,protocol):
         key=protocol+"_POOL_CREATE"
         self.funcSet[key](name,lb_method,protocol)




     def service_group_get(self, name):
        pool_search_req = (request_struct_adsg.service_group_json_obj.call
                           .search.toDict().items())
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        requestBody={

        "data": {
           "accountId":"1"
               },
            "oldValues": None
          }
        r = self.send(
                         method=pool_search_req[0][0],
                         url=pool_search_req[0][1],
                         body=requestBody,header=headers)
        if self.inspect_response(r) is not True:
            LOG.error ("service_group_get from adsg failure poolname=%s"%name)
            raise adsg_ex.SgGetError(sg=name)
        LOG.warn("resourceList=%s"%r['data']['resourceList'])
        if  r['data']['resourceList'] is None:
            return None
        var=r['data']['resourceList']['Pool']
        vtype=type(var)

        LOG.warn("vlist type:%s"%vtype)
        poolinfo=None
        if vtype is types.ListType:
            for item in var:
                LOG.warn("item:%s"%item)
                if item["name"] == name:
                    poolinfo=copy.deepcopy(item)
                    return poolinfo
        if vtype is types.DictType:
            if var["name"] == name:
                 poolinfo = copy.deepcopy(var)
                 return poolinfo
        LOG.warn("get poolinfo=%s"%poolinfo)
        return None

     def service_l4_group_get(self, name):
        pool_search_req = (request_struct_adsg.service_L4_group_json_obj.call
                           .search.toDict().items())
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        requestBody={

        "data": {
           "accountId":"1"
               },
            "oldValues": None
          }
        r = self.send(
                         method=pool_search_req[0][0],
                         url=pool_search_req[0][1],
                         body=requestBody,header=headers)

        if self.inspect_response(r) is not True:
            LOG.error ("service_l4_group_get from adsg failure poolname=%s"%name)
            raise adsg_ex.SgGetError(sg=name)
        if  r['data']['resourceList'] is None:
            return None
        var=r['data']['resourceList']['L4Pool']
        vtype=type(var)
        LOG.warn("vlist type:%s"%vtype)
        poolinfo=None
        if vtype is types.ListType:
            for item in var:
                LOG.warn("item:%s"%item)
                if item["name"] == name:
                    poolinfo=copy.deepcopy(item)
                    return poolinfo
        if vtype is types.DictType:
            if var["name"] == name:
                 poolinfo = copy.deepcopy(var)
                 return poolinfo
        LOG.warn("get poolinfo=%s"%poolinfo)
        return None

     def L7_service_group_update(self, name, lb_method=""):
        pool_update_req = (request_struct_adsg.service_group_json_obj.call
                           .update.toDict().items())

        pool = self.service_group_get(name)
        if pool is None:
            LOG.error("get pools failure.poolname=%s"%name)
            raise adsg_ex.SgGetError(sg=name)
        pool["name"] = name
        pool["loadBalancingAlgorithm"] = lb_method
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",

         }
        headers["Cookie"]='JSESSIONID=%s'%self.session_id
        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{
                "Pool":[{}]}}
        }

        requestBody["data"]["resourceList"]["Pool"][0] = copy.deepcopy(pool)
        LOG.debug("requestBody:%s"% requestBody["data"])
        r = self.send(
                      method=pool_update_req[0][0],
                      url=pool_update_req[0][1],
                      body=requestBody,header=headers)

        if self.inspect_response(r) is not True:
            LOG.error ("update pool failure name=%s"%name)
            raise adsg_ex.SgUpdateError(sg=name)
        else:
            LOG.info ("update pool success name=%s"%name)

     def L4_service_group_update(self, name, lb_method=""):
        pool_update_req = (request_struct_adsg.service_L4_group_json_obj.call
                           .update.toDict().items())

        pool = self.service_l4_group_get(name)
        if pool is None:
            LOG.error("get pools failure.poolname=%s"%name)
            raise adsg_ex.SgGetError(sg=name)
        pool["name"] = name
        pool["loadBalancingAlgorithm"] = self.l4algset[lb_method]
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",

         }
        headers["Cookie"]='JSESSIONID=%s'%self.session_id
        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{
                "L4Pool":[{}]}}
        }

        requestBody["data"]["resourceList"]["L4Pool"][0] = copy.deepcopy(pool)
        LOG.debug("requestBody:%s"% requestBody["data"])
        r = self.send(
                      method=pool_update_req[0][0],
                      url=pool_update_req[0][1],
                      body=requestBody,header=headers)

        if self.inspect_response(r) is not True:
            LOG.error ("update pool failure name=%s"%name)
            raise adsg_ex.SgUpdateError(sg=name)
        else:
            LOG.info ("update pool success name=%s"%name)

     def service_group_update(self, name, lb_method="",protocol=""):

         key=protocol+"_POOL_UPDATE"
         self.funcSet[key](name,lb_method)

     def L7_service_group_delete(self, name):
        pool_delete_req = (request_struct_adsg.service_group_json_obj.call
                           .delete.toDict().items())
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        pool=self.service_group_get(name)
        if pool is None:
            LOG.warn("pool=%s"%name+ "is not exist in adsg!")
            return
        ObjectId = pool["objectId"]
        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "deletionList":"Pool,%s"%ObjectId ,
            "resourceList":{}
                },
                  "oldValues": None
                }
        r = self.send(
                      method=pool_delete_req[0][0],
                      url=pool_delete_req[0][1],
                      body=requestBody,header=headers)

        if self.inspect_response(r) is not True:
            LOG.error ("delete pool failure,pool name=%s"%name)
            raise adsg_ex.SgDeleteError(sg="sg delete failure")
        else:
            LOG.info("delete pool success,pool name=%s"%name)

     def L4_service_group_delete(self, name):
        pool_delete_req = (request_struct_adsg.service_L4_group_json_obj.call
                           .delete.toDict().items())
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        pool=self.service_l4_group_get(name)
        if pool is None:
            LOG.warn("pool=%s"%name+ "is not exist in adsg!")
            return
        ObjectId = pool["objectId"]
        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "deletionList":"L4Pool,%s"%ObjectId ,
            "resourceList":{}
                },
                  "oldValues": None
                }
        r = self.send(
                      method=pool_delete_req[0][0],
                      url=pool_delete_req[0][1],
                      body=requestBody,header=headers)

        if self.inspect_response(r) is not True:
            LOG.error ("delete pool failure,pool name=%s"%name)
            raise adsg_ex.SgDeleteError(sg="sg delete failure")
        else:
            LOG.info("delete pool success,pool name=%s"%name)

     def service_group_delete(self, name,protocol):
         key=protocol+"_POOL_DELETE"
         self.funcSet[key](name)


     def L7_member_create(self, name, server_name, port, status="Enabled"):

        member_create_req = (request_struct_adsg.service_group_member_obj
                             .call.create.toDict().items())

        pool = self.service_group_get(name)
        if pool is None:
            LOG.error("get pools failure.poolname=%s"%name)
            raise adsg_ex.SgGetError(sg=name)

        server={}
        server["accountId"] = 1
        #need dnsname or ip
        server["name"] = server_name
        server["port"] = port
        server["portStatus"] = status
        server["serverType"]= "Static"
        server["portStatus"]= "Enabled"
        server["pool"] = pool["XMLID"]

        pool["servers"]=[]
        pool["servers"].append(server)

        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{
                "Pool":[{}]}}
        }

        requestBody["data"]["resourceList"]["Pool"][0] = copy.deepcopy(pool)
        r = self.send(
                      method=member_create_req[0][0],
                      url=member_create_req[0][1],
                      body=requestBody,header=headers)

        if self.inspect_response(r) is not True:
            LOG.error("MemberCreateError member=%s"%server_name)
            raise adsg_ex.MemberCreateError(member=server_name)
        else:
            LOG.info("MemberCreate success member=%s"%server_name)


     def L4_member_create(self, name, server_name, port, status="Enabled"):
        member_create_req = (request_struct_adsg.service_L4_group_member_obj
                             .call.create.toDict().items())

        pool = self.service_l4_group_get(name)
        if pool is None:
            LOG.error("get pools failure.poolname=%s"%name)
            raise adsg_ex.SgGetError(sg=name)

        server={}
        server["accountId"] = 1
        server["name"] = server_name
        server["port"] = port
        server["weight"] = 1
        server["pool"] = pool["XMLID"]
        server["mode"] = "DSNAT"
        server["XMLID"]= "1"
        server["status"]="Enabled"
        pool["servers"]=[]
        pool["servers"].append(server)

        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{
                "L4Pool":[{}]}}
        }

        requestBody["data"]["resourceList"]["L4Pool"][0] = copy.deepcopy(pool)
        r = self.send(
                      method=member_create_req[0][0],
                      url=member_create_req[0][1],
                      body=requestBody,header=headers)

        if self.inspect_response(r) is not True:
            LOG.error("MemberCreateError member=%s"%server_name)
            raise adsg_ex.MemberCreateError(member=server_name)
        else:
            LOG.info("MemberCreate success member=%s"%server_name)

     def member_create(self, name, server_name, port, status="Enabled",protocol=""):

         key=protocol+"_MEMBER_CREATE"
         self.funcSet[key](name, server_name, port, status="Enabled")



     def L7_member_update(self, old_pool_name, new_pool_name, server_name, port, status):
       
         member_update_req = (request_struct_adsg.service_group_member_obj
                             .call.update.toDict().items())
         headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

         old_pool = self.service_group_get(old_pool_name)
         if old_pool is None:
             LOG.error("get old_pool failure.old_pool=%s"%old_pool_name)
             raise adsg_ex.MemberUpdateError(member=server_name)
         LOG.warn("pool:%s"%old_pool)

         servers=old_pool["servers"]
         if len(servers) == 0:
             LOG.error ("servers in pool is empty,can not delete server form pool")
             raise adsg_ex.MemberUpdateError(member=server_name)
         LOG.warn("servers:%s"%servers)
         objectId=None
         vtype=type(servers)
         if vtype is types.ListType:
             for s in servers:
                 if s["name"] == server_name and s["port"] == str(port):
                     objectId=s["objectId"]
                     break

         if vtype is types.DictType:
            if servers["name"]== server_name and servers["port"] == str(port):
                 objectId=servers["objectId"]
         if objectId is None:
            LOG.error("server name is not in old_pool")

         to_pool = self.service_group_get(new_pool_name)
         if to_pool is None:
             LOG.error("get to_pool failure.")
             raise adsg_ex.MemberUpdateError(member=server_name)
         LOG.warn("pool:%s"%to_pool)

         newserver={}
         newserver["accountId"] = 1
         newserver["name"] = server_name
         newserver["port"] = port
         newserver["status"] = status
         newserver["serverType"]="Static"
         newserver["portStatus"]="Enabled"
         newserver["pool"] = to_pool["XMLID"]
         to_pool["servers"]=[]
         to_pool["servers"].append(newserver)

         requestBody={
         "dataSource":"commitData",
         "operationType": "update",
         "data": {
             "accountId":"1",
             "resourceList":{"Pool":[{}]}
                 },
                   "oldValues": None
                 }
         requestBody["data"]["resourceList"]["Pool"][0] = copy.deepcopy(to_pool)
         if objectId is not None:
             requestBody["data"]["deletionList"] ="Server,%s"%objectId

         r = self.send(
                      method=member_update_req[0][0],
                      url=member_update_req[0][1],
                      body=requestBody,header=headers)

         if self.inspect_response(r, func='delete') is not True:
            LOG.error("L7_member_update failure")
            raise adsg_ex.MemberUpdateError(member=server_name)
         
     def L4_member_update(self, old_pool_name,new_pool_name,server_name, port, status):
         member_update_req = (request_struct_adsg.service_L4_group_member_obj
                             .call.update.toDict().items())
         headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

         old_pool = self.service_l4_group_get(old_pool_name)
         if old_pool is None:
             LOG.error("get old_pool failure.old_pool=%s"%old_pool_name)
             raise adsg_ex.MemberUpdateError(member=server_name)
         LOG.warn("pool:%s"%old_pool)

         servers=old_pool["servers"]
         if len(servers) == 0:
             LOG.error ("servers in pool is empty,can not delete server form pool")
             raise adsg_ex.MemberUpdateError(member=server_name)
         LOG.warn("servers:%s"%servers)
         objectId=None
         vtype=type(servers)
         if vtype is types.ListType:
             for s in servers:
                 if s["name"] == server_name and s["port"] == str(port):
                     objectId=s["objectId"]
                     break

         if vtype is types.DictType:
            if servers["name"]== server_name and servers["port"] == str(port):
                 objectId=servers["objectId"]
         if objectId is None:
            LOG.error("server name is not in old_pool")

         to_pool = self.service_l4_group_get(new_pool_name)
         if to_pool is None:
             LOG.error("get to_pool failure.")
             raise adsg_ex.MemberUpdateError(member=server_name)
         LOG.warn("pool:%s"%to_pool)
         newserver={}
         newserver["accountId"] = 1
         newserver["name"] = server_name
         newserver["port"] = port
         newserver["weight"] = 1
         newserver["pool"] = to_pool["XMLID"]
         newserver["mode"] = "DSNAT"
         to_pool["servers"]=[]
         to_pool["servers"].append(newserver)

         requestBody={
         "dataSource":"commitData",
         "operationType": "update",
         "data": {
             "accountId":"1",
             "resourceList":{"L4Pool":[{}]}
                 },
                   "oldValues": None
                 }
         requestBody["data"]["resourceList"]["L4Pool"][0] = copy.deepcopy(to_pool)
         if objectId is not None:
             requestBody["data"]["deletionList"] ="L4Server,%s"%objectId
         r = self.send(
                      method=member_update_req[0][0],
                      url=member_update_req[0][1],
                      body=requestBody,header=headers)

         if self.inspect_response(r, func='delete') is not True:
            LOG.error("L4_member_update failure")
            raise adsg_ex.MemberUpdateError(member=server_name)

    
     def member_update(self,old_pool_name,new_pool_name, server_name, port,protocol, status=""):

         key=protocol+"_MEMBER_UPDATE"
         self.funcSet[key](old_pool_name,new_pool_name, server_name, port, status)
         
     # def get_member_info(self, name, server_name, server_port):
     #    pool = self.service_group_get(name)
     #    if pool is None:
     #        return False
     #    if "servers" not in pool:
     #        return False
     #    servers=pool["servers"]
     #    if len(servers) == 0:
     #        LOG.error ("servers in pool is empty,can not delete server form pool")
     #        return False
     #    for s in servers:
     #        if s["name"] == server_name and s["port"] == str(server_port):
     #            return True
     #    return False


     def L7_member_delete(self, name, server_name, server_port):


        member_delete_req = (request_struct_adsg.service_group_member_obj
                             .call.delete.toDict().items())
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        pool = self.service_group_get(name)
        if pool is None:
            LOG.error("get pools failure.poolname=%s"%name)
            return

        if "servers" not in pool:
            LOG.error("servers not in pool=%s"%name)
            return
        servers=pool["servers"]
        if len(servers) == 0:
            LOG.warn("servers in pool=%s"%name+"is empty,can not delete server form pool")
            return
        objectId=None
        for s in servers:
            if s["name"] == server_name and s["port"] == str(server_port):
                objectId=s["objectId"]
                break
                
        if objectId is None:
             LOG.warn("server=%s "+ server_name+ " pool=%s"%name+"is not in pool")
             return

        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{}
                },
                  "oldValues": None
                }
        if objectId is not None:
             requestBody["data"]["deletionList"] ="Server,%s"%objectId
        r = self.send(
                      method=member_delete_req[0][0],
                      url=member_delete_req[0][1],
                      body=requestBody,header=headers)

        if self.inspect_response(r, func='delete') is not True:
           LOG.error("MemberDeleteError member=%s"%server_name)
           raise adsg_ex.MemberDeleteError(member=name)

     def L4_member_delete(self, name, server_name, server_port):

        member_delete_req = (request_struct_adsg.service_L4_group_member_obj
                             .call.delete.toDict().items())
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        pool = self.service_l4_group_get(name)
        if pool is None:
            LOG.error("get pools failure.poolname=%s"%name)
            return

        if "servers" not in pool:
            LOG.error("servers not in pool=%s"%name)
            return
        servers=pool["servers"]
        if len(servers) == 0:
            LOG.warn("servers in pool=%s"%name+"is empty,can not delete server form pool")
            return
        objectId=None
        for s in servers:
            if s["name"] == server_name and s["port"] == str(server_port):
                objectId=s["objectId"]
                break

        if objectId is None:
             LOG.warn("server=%s "+ server_name+ " pool=%s"%name+"is not in pool")
             return

        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",

            "resourceList":{}
                },
                  "oldValues": None
                }
        if objectId is not None:
             requestBody["data"]["deletionList"] ="L4Server,%s"%objectId
        r = self.send(
                      method=member_delete_req[0][0],
                      url=member_delete_req[0][1],
                      body=requestBody,header=headers)

        if self.inspect_response(r, func='delete') is not True:
           LOG.error("MemberDeleteError member=%s"%server_name)
           raise adsg_ex.MemberDeleteError(member=name)

     def member_delete(self, pool_id, server_name, server_port,protocol):
         key=protocol+"_MEMBER_DELETE"
         self.funcSet[key](pool_id, server_name,server_port)

     def vserver_get(self,name):
        "get the vserver in adsg"
        vserver_search_req = (request_struct_adsg.virtual_server_object.call
                           .search.toDict().items())
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        requestBody={

        "data": {
           "accountId":"1"
               },
            "oldValues": None
          }
        r = self.send(
                         method=vserver_search_req[0][0],
                         url=vserver_search_req[0][1],
                         body=requestBody,header=headers)
        if self.inspect_response(r) is not True:
            LOG.error ("vserver_L7_get from adsg failure vservername=%s"%name)
            raise adsg_ex.VipGetError(vip=name)

        LOG.warn ("ritem:%s"%r)
        if r['data']['resourceList'] is None or "VServer" not in r['data']['resourceList']:
            return None
        var=r['data']['resourceList']['VServer']
        vtype=type(var)
        LOG.debug ("vlist type:%s"%vtype)
        if vtype is types.ListType:
            for item in var:
                LOG.debug ("item:%s"%item)
                if item["name"] == name:
                    vserverinfo=copy.deepcopy(item)
                    return vserverinfo
        if vtype is types.DictType:
            if var["name"] == name:
                 vserverinfo = copy.deepcopy(var)
                 return vserverinfo

        return None

     def vserver_L4_get(self,name):
        "get the vserver in adsg"
        vserver_search_req = (request_struct_adsg.virtual_L4_server_object.call
                           .search.toDict().items())
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        requestBody={

        "data": {
           "accountId":"1"
               },
            "oldValues": None
          }
        r = self.send(
                         method=vserver_search_req[0][0],
                         url=vserver_search_req[0][1],
                         body=requestBody,header=headers)

        if self.inspect_response(r) is not True:
            LOG.error ("vserver_L4_get from adsg failure vservername=%s"%name)
            raise adsg_ex.VipGetError(vip=name)

        LOG.warn ("ritem:%s"%r)
        if r['data']['resourceList'] is None or "L4VServer" not in r['data']['resourceList']:
            return None
        var=r['data']['resourceList']['L4VServer']
        vtype=type(var)
        LOG.debug ("vlist type:%s"%vtype)
        if vtype is types.ListType:
            for item in var:
                LOG.debug ("item:%s"%item)
                if item["name"] == name:
                    vserverinfo=copy.deepcopy(item)
                    return vserverinfo
        if vtype is types.DictType:
            if var["name"] == name:
                 vserverinfo = copy.deepcopy(var)
                 return vserverinfo

        return None


     def vserver_pool_get(self,vserver_name,pool_name):
        "get the vserver in adsg"
        vserver_search_req = (request_struct_adsg.virtual_server_object.call
                           .search_vserver_pool.toDict().items())
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        requestBody={

        "data": {
           "accountId":"1"
               },
            "oldValues": None
          }
        r = self.send(
                         method=vserver_search_req[0][0],
                         url=vserver_search_req[0][1],
                         body=requestBody,header=headers)
        LOG.debug("ritem:%s"%r)
        if "VServer"  not in r['data']['resourceList']:
            return False
        vserver=r['data']['resourceList']['VServer']
        vtype=type(vserver)

        vserverinfo=None
        if vtype is types.ListType:
            for item in vserver:
                LOG.debug("item:%s"%item)
                if item["name"] == vserver_name:
                    vserverinfo=copy.deepcopy(item)
        if vtype is types.DictType:
            if vserver["name"] == vserver_name:
                 vserverinfo = copy.deepcopy(vserver)
        pool=r['data']['resourceList']['Pool']
        ptype=type(pool)
        poolinfo=None
        if ptype is types.ListType:
            for item in pool:
                LOG.debug("item:%s"%item)
                if item["name"] == pool_name:
                    poolinfo=copy.deepcopy(item)
        if ptype is types.DictType:
            if pool["name"] == pool_name:
                 poolinfo = copy.deepcopy(pool)

        LOG.warn("vserverinfo:%s"%vserverinfo)
        if vserverinfo is not None and poolinfo is not None  and vserverinfo["locations"][0]["pool"] == poolinfo["XMLID"]:
            return True
        else:
            LOG.error("error vserver=%s"%vserver_name +" is not in pool=%s"%pool_name)
            return False




     def create_vserver(self, name, ip_address,
                                           protocol, port,
                                           status="Enabled"):
        "create a vserver in adsg"

        vs = request_struct_adsg.virtual_server_object.ds.toDict()
        vs["data"]["resourceList"]["VServer"][0]["name"] = name
        vs["data"]["resourceList"]["VServer"][0]["dnsName"] = ip_address
        vs["data"]["resourceList"]["VServer"][0]["VIPAddr"]["VIP"]=ip_address
        if(str(protocol).lower() == "http"):
            vs["data"]["resourceList"]["VServer"][0]["httpPort"] = port
            vs["data"]["resourceList"]["VServer"][0]["https"] = False
            vs["data"]["resourceList"]["VServer"][0]["http"] = True
            vs["data"]["resourceList"]["VServer"][0]["httpsPort"] = "443"
        if(str(protocol).lower() == "https"):
            vs["data"]["resourceList"]["VServer"][0]["httpsPort"] = port
            vs["data"]["resourceList"]["VServer"][0]["https"] = True
            vs["data"]["resourceList"]["VServer"][0]["http"] = False
            vs["data"]["resourceList"]["VServer"][0]["httpPort"]="80"
        vs["data"]["resourceList"]["VServer"][0]["status"] = status
        vs["data"]["resourceList"]["VServer"][0]["locations"][0]["path"]="/"
        vs["data"]["resourceList"]["VServer"][0]["locations"][0]["name"]="loc_%s"%name
        vs["data"]["resourceList"]["VServer"][0]["locations"][0]["status"]="Enabled"

        return vs["data"]["resourceList"]["VServer"][0]

     def L7_virtual_server_create(self, name, ip_address, protocol, port,
                              service_group_id,
                              s_pers,
                              c_pers,
                              app_cookie,
                              status,cidr):
        create_vip_req = (request_struct_adsg.virtual_server_object.call
                          .create.toDict().items())
        #create the vserver
        LOG.warn("create vserver start")
        vserver=self.create_vserver(name,ip_address,protocol,port,status)
        LOG.warn("vserver=%s"%vserver)



        locationid =vserver["locations"][0]["XMLID"]
        vserver["locations"][0]["serverdType"]="ServedByPool"
        
        pool=self.service_group_get(service_group_id)
        pool["locations"]=[locationid]
        poolid=pool["XMLID"]
        vserver["locations"][0]["pool"]=poolid
        if c_pers is not None:
            pool['insertCookieName'] = c_pers
            pool["sessionPersistenceMode"]="InsertCookie"
            pool["sessionPersistenceStatus"]="Enabled"
        elif s_pers is not None:
            pool["loadBalancingAlgorithm"]=s_pers
            pool["sessionPersistenceStatus"]="Disabled"
        elif app_cookie is not None:
            pool["sessionPersistenceMode"]="MonitorCookie"
            pool['insertCookieName']=app_cookie
            pool["sessionPersistenceStatus"]=status
        else:
            pool['insertCookieName'] = "deletecookie"
            pool["sessionPersistenceMode"]="InsertCookie"
            pool["sessionPersistenceStatus"]="Disabled"
        
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }
        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{
                "VServer":[{}],
                "Pool":[{}]

            }
                },
                  "oldValues": None
                }

        requestBody["data"]["resourceList"]["VServer"][0]=copy.deepcopy(vserver)
        requestBody["data"]["resourceList"]["Pool"][0]=copy.deepcopy(pool)
        r = self.send(
                      method=create_vip_req[0][0],
                      url=create_vip_req[0][1],
                      body=requestBody,header=headers)

        if self.inspect_response(r) is not True:
            LOG.error ("create vserver in adsg failure vservername=%s"%name)
            raise adsg_ex.VipCreateError(vip=name)

        else:
            LOG.info("create vserver in adsg success")

     def create_L4_vserver(self,name,ip_address,protocol,port,status,cidr):
        "create a vserver in adsg"
        localips=self.localips
        liplist=localips.split(",")
        check=False
        LOG.warn("liplist=%s"%liplist)
        lip=""
        for lp in liplist:
            result=self._check_subnet_ip(cidr,lp)
            if result is True:
               LOG.warn("lip=%s"%lp+" is on cidr=%s"%cidr)
               check=True
               lip=lp 
               break

        if check is False:
               LOG.error("lips = %s"%liplist +"is invalid on pool cidr=%s"%cidr)
               raise  adsg_ex.VipCreateError(vip=name)

        vs = request_struct_adsg.virtual_L4_server_object.ds.toDict()
        vs["data"]["resourceList"]["L4VServer"][0]["name"] = name

        #use adsg northif ip as lip,make sure lip can communicate with backend servers for L4
        vs["data"]["resourceList"]["L4VServer"][0]["lip"] = lip

        vs["data"]["resourceList"]["L4VServer"][0]["VIPAddr"]["VIP"]=ip_address
        vs["data"]["resourceList"]["L4VServer"][0]["port"] = port
        vs["data"]["resourceList"]["L4VServer"][0]["protocol"] = protocol
        vs["data"]["resourceList"]["L4VServer"][0]["status"] = status

        return vs["data"]["resourceList"]["L4VServer"][0]


     def L4_virtual_server_create(self, name,ip_address, protocol, port,service_group_id,
                            s_pers,
                            c_pers,
                            app_cookie,
                            status,cidr):
        create_vip_req = (request_struct_adsg.virtual_L4_server_object.call
                          .create.toDict().items())
        alg=None
        if s_pers is not None:
            alg=self.l4algset[s_pers]
        if c_pers is not None or app_cookie is not None:
            LOG.error("L4 loadbalance can not set cookies for appcookie or httpcookie,skip")
            raise adsg_ex.VipCreateError(vip=name)

        #create the vserver
        LOG.warn("create vserver start")
        vserver=self.create_L4_vserver(name,ip_address,protocol,port,status,cidr)
        LOG.warn("vserver=%s"%vserver)

        vserverxmlid=vserver["XMLID"]
        pool=self.service_l4_group_get(service_group_id)
        pool["vServer"]=vserverxmlid
        if alg is not None:
            pool["loadBalanceAlgorithm"]=alg
        poolid=pool["XMLID"]
        vserver["pool"]=poolid

        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }
        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{
                "L4VServer":[{}],
                "L4Pool":[{}]

            }
                },
                  "oldValues": None
                }

        requestBody["data"]["resourceList"]["L4VServer"][0]=copy.deepcopy(vserver)
        requestBody["data"]["resourceList"]["L4Pool"][0]=copy.deepcopy(pool)
        r = self.send(
                      method=create_vip_req[0][0],
                      url=create_vip_req[0][1],
                      body=requestBody,header=headers)

        if self.inspect_response(r) is not True:
            LOG.error ("create vserver in adsg failure vservername=%s"%name)
            raise adsg_ex.VipCreateError(vip=name)

        else:
            LOG.info("create vserver in adsg success")

      
     def _check_subnet_ip(self,cidr, ip_address):
        """Validate that the IP address is on the subnet."""
        ip = netaddr.IPAddress(ip_address)
        net = netaddr.IPNetwork(cidr)
        # Check that the IP is valid on subnet. This cannot be the
        # network or the broadcast address
        LOG.warn("net.netmask=%s"%net.netmask)
        LOG.warn("net.network=%s"%net.network)
        r=net.netmask & ip
        LOG.warn("r=%s"%r)    
        if (ip != net.network and
                ip != net.broadcast and
                net.netmask & ip == net.network):
            return True
        return False
     
     def virtual_server_create(self, name, ip_address, protocol, port,
                              service_group_id,
                              s_pers,
                              c_pers,
                              app_cookie,
                              status,cidr):
            
         key=protocol+"_VIP_CREATE"
         self.funcSet[key](name, ip_address, protocol, port,
                               service_group_id,
                               s_pers,
                               c_pers,
                               app_cookie,
                              status,cidr)


     def L7_virtual_server_update(self,name, protocol, service_group_id,
                            s_pers,
                            c_pers,
                            app_cookie,
                            status):
        vserver_update_req = (request_struct_adsg.virtual_server_object.call
                           .update.toDict().items())
        LOG.warn("L7_virtual_server_update")
        LOG.warn("s_pers=%s"%s_pers+" c_pers=%s"%c_pers)

        vserver = self.vserver_get(name)
        if(vserver is None):
           LOG.error( "get vserver name=%s"%name + "failure")
           raise adsg_ex.VipUpdateError(vip=name)
        locationid = vserver["locations"][0]["XMLID"]
        vserver["locations"][0]["vServer"]=vserver["XMLID"]
        vserver["locations"][0]["serverdType"]="ServedByPool"
        pool=self.service_group_get(service_group_id)
        if pool is None:
           LOG.error ( "get pool name=%s"%service_group_id + "failure")
           raise adsg_ex.VipUpdateError(vip=name)
        pool["locations"]=[locationid]
        poolid=pool["XMLID"]
        vserver["locations"][0]["pool"]=poolid 


        if c_pers is not None:
            pool["sessionPersistenceMode"]="InsertCookie"
            pool['insertCookieName'] = c_pers
            pool['sessionPersistenceStatus'] = status
        elif s_pers is not None:
            pool["loadBalancingAlgorithm"]=s_pers
            pool['sessionPersistenceStatus'] = "Disabled"
        elif app_cookie is not None:
                pool["sessionPersistenceMode"]="MonitorCookie"
                pool['insertCookieName']=app_cookie
                pool["sessionPersistenceStatus"]=status
        else:
            pool["sessionPersistenceMode"]="InsertCookie"
            pool['insertCookieName'] = "deletecookie"
            pool['sessionPersistenceStatus'] = "Disabled"

        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }
      
        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{
                "VServer":[{}],
                "Pool":[{}]}}
        }

        requestBody["data"]["resourceList"]["Pool"][0] = copy.deepcopy(pool)
        requestBody["data"]["resourceList"]["VServer"][0]=copy.deepcopy(vserver)
       
       
        LOG.debug ("requestBody:%s"% requestBody["data"])
        r = self.send(
                      method=vserver_update_req[0][0],
                      url=vserver_update_req[0][1],
                      body=requestBody,header=headers)
        if self.inspect_response(r, func='delete') is not True:
            LOG.error("vserver update Error,vserver name=%s"%name,"poolid="%service_group_id)
            raise adsg_ex.VipUpdateError(vip=name)
     def L4_virtual_server_update(self, name, protocol, service_group_id,
                            s_pers=None,
                            c_pers=None,
                            app_cookie=None,
                            status=""):

        pool_update_req = (request_struct_adsg.virtual_L4_server_object.call
                           .update.toDict().items())
        LOG.warn("L4_virtual_server_update")
        LOG.warn("s_pers=%s"%s_pers+" c_pers=%s"%c_pers)
        alg=None
        if s_pers is not None:
            alg=self.l4algset[s_pers]
        if c_pers is not None or app_cookie is not None:
            LOG.error("L4 loadbalance can not set cookies for appcookie or httpcookie,skip")
            raise adsg_ex.VipUpdateError(vip=name)        
        vserver = self.vserver_L4_get(name)
        if(vserver is None):
           LOG.error( "get vserver name=%s"%name + "failure")
           raise adsg_ex.VipUpdateError(vip=name)

        vserverxmlid=vserver["XMLID"]
        pool=self.service_l4_group_get(service_group_id)

        if pool is None:
           LOG.error ( "get pool name=%s"%service_group_id + "failure")
           raise adsg_ex.VipUpdateError(vip=name)
        pool["vServer"]=vserverxmlid
        poolid=pool["XMLID"]
        vserver["pool"]=poolid
        if alg is not None:
            pool["loadBalanceAlgorithm"]=alg

        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{
                "L4VServer":[{}],
                "L4Pool":[{}]}}
        }

        requestBody["data"]["resourceList"]["L4Pool"][0] = copy.deepcopy(pool)
        requestBody["data"]["resourceList"]["L4VServer"][0]=copy.deepcopy(vserver)


        LOG.debug ("requestBody:%s"% requestBody["data"])
        r = self.send(
                      method=pool_update_req[0][0],
                      url=pool_update_req[0][1],
                      body=requestBody,header=headers)
        if self.inspect_response(r, func='delete') is not True:
            LOG.error("vserver update Error,vserver name=%s"%name,"poolid="%service_group_id)
            raise adsg_ex.VipUpdateError(vip=name)


     def virtual_server_update(self, name, protocol, service_group_id,
                            s_pers=None,
                            c_pers=None,
                            app_cookie=None,
                            status=""):

          key=protocol+"_VIP_UPDATE"
          self.funcSet[key](name, protocol, service_group_id,
                             s_pers,
                            c_pers,
                            app_cookie,
                             status)


     def L7_virtual_server_delete(self, vip_id,pool_id):

        vs_delete_req = (request_struct_adsg.virtual_server_object.call.
                         delete.toDict().items())

        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }


        vserver = self.vserver_get(vip_id)
        if vserver is None:
            LOG.error("vip:%s"%vip_id + "is not in pool:%s"%pool_id)
            return
        pool=self.service_group_get(pool_id)
        if pool is None:
           LOG.error( "get pool name=%s"%pool_id + "failure")
           return
        pool["sessionPersistenceMode"]="InsertCookie"
        pool['insertCookieName'] = "deletecookie"
        pool['sessionPersistenceStatus'] = "Disabled"
        vObjectId = vserver["objectId"]
        LocationId=vserver["locations"][0]["objectId"]
        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "deletionList":["VServer,%s"%vObjectId,"Location,%s"%LocationId],
            "resourceList":{  "Pool":[{}]}
                },
                  "oldValues": None
                }
        requestBody["data"]["resourceList"]["Pool"][0] = copy.deepcopy(pool)
        r = self.send(
                      method=vs_delete_req[0][0],
                      url=vs_delete_req[0][1],
                      body=requestBody,header=headers)
        if self.inspect_response(r) is not True:
            LOG.error ("delete vserver failure vservername=%s"%vip_id)
            raise adsg_ex.VipDeleteError(vip=vip_id)

        LOG.warn("delete vserver success vservername=%s"%vip_id)


     def L4_virtual_server_delete(self, vip_id,pool_id):

        vs_delete_req = (request_struct_adsg.virtual_L4_server_object.call.
                         delete.toDict().items())

        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }


        vserver = self.vserver_L4_get(vip_id)
        if vserver is None:
            LOG.error("vip:%s"%vip_id + "is not in pool:%s"%pool_id)
            return
        pool=self.service_l4_group_get(pool_id)
        if pool is None:
           LOG.error( "get pool name=%s"%pool_id + "failure")
           return

        vObjectId = vserver["objectId"]
        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "deletionList":["L4VServer,%s"%vObjectId],
            "resourceList":{  "L4Pool":[{}]}
                },
                  "oldValues": None
                }
        requestBody["data"]["resourceList"]["L4Pool"][0] = copy.deepcopy(pool)
        r = self.send(
                      method=vs_delete_req[0][0],
                      url=vs_delete_req[0][1],
                      body=requestBody,header=headers)
        if self.inspect_response(r) is not True:
            LOG.error ("delete vserver failure vservername=%s"%vip_id)
            raise adsg_ex.VipDeleteError(vip=vip_id)

        LOG.warn("delete vserver success vservername=%s"%vip_id)

     def virtual_server_delete(self, vip_id, pool_id, protocol):

         key=protocol+"_VIP_DELETE"
         self.funcSet[key](vip_id,pool_id)



     def L7_health_monitor_set(self, mon_type, pool_name,hm_name,
                            interval, timeout, max_retry_num, delete,method,url,expect_code):
        pool_update_req = (request_struct_adsg.service_group_json_obj.call
                           .update.toDict().items())
        pool = self.service_group_get(pool_name)
        if pool is None:
            LOG.error("get pools failure.poolname=%s"%pool_name)
            raise adsg_ex.SgGetError(sg=pool_name)

        protocol=None

        if mon_type == 'TCP':
            protocol = "TCP"
        elif mon_type == 'PING':
            protocol = "ICMP"
        elif mon_type == 'HTTP':
            protocol = "HTTP"
        elif mon_type == 'HTTPS':
            protocol="HTTPS"

        pool["healthMonitorChecker"]=protocol
        pool["healthMonitorFailureThreshold"]="%s"%max_retry_num
        pool["healthMonitorInterval"]="%s"%interval
        pool["healthMonitorSuccessThreshold"]="%s"%max_retry_num
        pool["healthMonitorTimeout"]="%s"%timeout
        
        if protocol == "ICMP" or protocol == "HTTPS":
            LOG.error("L7 not support ICMP or HTTPS healthchecker.")
            raise adsg_ex.HealthMonitorUpdateError(hm=hm_name)
        
        if protocol == "HTTP":
            pool["healthMonitorCheckerParamSendFile"] = "%s" % (url)
            
            pool["healthMonitorCheckerParamExpectedFile"] = expect_code       
 
        if delete is True:
            pool["healthMonitorStatus"]="Disabled"
        else:
            pool["healthMonitorStatus"]="Enabled"
        
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{
                "Pool":[{}]}}
        }

        requestBody["data"]["resourceList"]["Pool"][0] = copy.deepcopy(pool)
        LOG.debug("requestBody:%s"% requestBody["data"])
        r = self.send(
                      method=pool_update_req[0][0],
                      url=pool_update_req[0][1],
                      body=requestBody,header=headers)
        if self.inspect_response(r) is not True:
           raise adsg_ex.HealthMonitorUpdateError(hm=hm_name)
     def L4_health_monitor_set(self, mon_type, pool_name,hm_name,
                            interval, timeout, max_retry_num, delete,method,url,expect_code):

        pool_update_req = (request_struct_adsg.service_L4_group_json_obj.call
                           .update.toDict().items())
        pool = self.service_l4_group_get(pool_name)
        if pool is None:
            LOG.error("get pools failure.poolname=%s"%pool_name)
            raise adsg_ex.SgGetError(sg=pool_name)
        protocol=None
        LOG.warn("pool=%s"%pool)
        if mon_type == 'TCP':
            protocol = "TCP"
        elif mon_type == 'PING':
            protocol = "ICMP"
        elif mon_type == 'HTTP':
            protocol = "HTTP"
        elif mon_type == 'HTTPS':
            protocol="HTTPS"
        LOG.warn("yyyyyyyyyyddyyyyyyyyyyyyyyyyyyyy")
        pool["healthMonitorChecker"]=protocol
        pool["healthMonitorFailureThreshold"]="%s"%max_retry_num
        pool["healthMonitorInterval"]="%s"%interval
        pool["healthMonitorSuccessThreshold"]="%s"%max_retry_num
        pool["healthMonitorTimeout"]="%s"%timeout
        
        if protocol == "HTTP" or protocol == "HTTPS":
            LOG.error("L4 not use http or https healthchecker")
            raise adsg_ex.HealthMonitorUpdateError(hm=hm_name)
        if delete is True:
            pool["healthMonitorStatus"]="Disabled"
        else:
            pool["healthMonitorStatus"]="Enabled"
        headers = {
            "Accept":"application/json",
            "Content-Type":"application/json",
         }

        requestBody={
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{
                "L4Pool":[{}]}}
        }
        LOG.warn("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")
        requestBody["data"]["resourceList"]["L4Pool"][0] = copy.deepcopy(pool)
        LOG.debug("requestBody:%s"% requestBody["data"])
        r = self.send(
                      method=pool_update_req[0][0],
                      url=pool_update_req[0][1],
                      body=requestBody,header=headers)
        if self.inspect_response(r) is not True:
           raise adsg_ex.HealthMonitorUpdateError(hm=hm_name)



     def health_monitor_create(self, mon_type, pool_name,
                              interval, timeout, max_retries,hm_name
                             ,protocol,method,url,expect_code):

        key=protocol+"_HM_CREATE"
        self.funcSet[key](mon_type, pool_name,hm_name,
                                 interval, timeout, max_retries,False,method,url,expect_code)



     def health_monitor_update(self, mon_type, pool_name,
                              interval, timeout, max_retries,
                             hm_name,protocol,method,url,expect_code):

        key=protocol+"_HM_UPDATE"
        self.funcSet[key](mon_type, pool_name,hm_name,
                                  interval, timeout, max_retries,False,method,url,expect_code)


     def health_monitor_delete(self, pool_name,protocol):


        key=protocol+"_HM_DELETE"
        self.funcSet[key]("TCP", pool_name,"",
                                  "2", "1", "1",True,"","","")



     def select_device(self, tenant_id=""):
        if len(self.config.devices) == 0:
            raise adsg_ex.ADSGNoDevices()

        nodes = 256

        node_list = []
        x = 0
        while x < nodes:
            node_list.insert(x, (x, []))
            x += 1
        z = 0
        key_list = self.config.devices.keys()
        LOG.debug("THIS IS THE KEY LIST %s", key_list)
        while z < nodes:
            for key in key_list:
                key_index = int(hashlib.sha256(key).hexdigest(), 16)
                result = key_index % nodes

                if result == nodes:
                    result = 0
                else:
                    result = result + 1
                node_list[result][1].insert(result, self.config.devices[key])

            z += 1
        tenant_hash = int(hashlib.sha256(tenant_id).hexdigest(), 16)
        limit = 256
        th = tenant_hash
        device_info={}
        for i in range(0, limit):
            LOG.debug("NODE_LENGTH------> %d", len(node_list[th % nodes][1]))
            if len(node_list[th % nodes][1]) > 0:
                node_tenant_mod = tenant_hash % len(node_list[th % nodes][1])
                LOG.debug("node_tenant_mod---> %s", node_tenant_mod)
                device_info = node_list[th % nodes][1][node_tenant_mod]
                LOG.debug("DEVICE_INFO----> %s", device_info['host'])
                device_info['tenant_id'] = tenant_id
                break
            th = th + 1
        return device_info






