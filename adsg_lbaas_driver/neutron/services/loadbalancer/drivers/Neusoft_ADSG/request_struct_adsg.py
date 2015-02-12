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
import copy


class wrapper(object):

    def __init__(self, d=None, create=True):
        if d is None:
            d = {}
        supr = super(wrapper, self)
        supr.__setattr__('_data', d)
        supr.__setattr__('__create', create)

    def __getattr__(self, name):
        try:
            value = self._data[name]
        except KeyError:
            if not super(wrapper, self).__getattribute__('__create'):
                raise
            value = {}
            self._data[name] = value

        if hasattr(value, 'items'):
            create = super(wrapper, self).__getattribute__('__create')
            return wrapper(value, create)
        return value

    def __setattr__(self, name, value):
        self._data[name] = value

    def toDict(self):

        return self.__dict__['_data']

    def __getitem__(self, key):
        try:
            value = self._data[key]
        except KeyError:
            if not super(wrapper, self).__getattribute__('__create'):
                raise
            value = {}
            self._data[key] = value

        if hasattr(value, 'items'):
            create = super(wrapper, self).__getattribute__('__create')
            return wrapper(value, create)
        return value

    def __setitem__(self, key, value):
        self._data[key] = value

    def __iadd__(self, other):
        if self._data:
            raise TypeError("only be replaced if it's empty")
        else:
            return other


'''
This returns a service group dict object.
'''

service_group_json_obj = wrapper(copy.deepcopy({
    "call": {"create": {"POST": "/Administration/rest/adsg/configure/save"},
             "update": {"POST": "/Administration/rest/adsg/configure/save"},
             "delete": {"POST": "/Administration/rest/adsg/configure/save"},
             "search": {"GET": "/Administration/rest/adsg/configure/Pool?accountId=1"
                                }
             },

    "ds": {
        "dataSource":"commitData",
        "operationType": "insert",
        "data": {
            "accountId":"1",
            "resourceList":{
                "Pool":[{
                    "http":"80",
                    "XMLID":"3",
                    "accountId":"1",
                    "type":"Pool",
                    "status":"Enabled",
                    "name":"NewPool",
                    "protocol":"http",
                    "port":"80",
                    "comments":"",
                    "healthMonitorStatus":"Disabled",
                    "healthMonitorChecker":"TCP",
                    "healthMonitorCheckerParamSendFile":"",
                    "healthMonitorCheckerParamExpectedFile":"",
                    "locations":[
                    ],
                    "servers":[
                    ],
                    "cloudServers":[
                    ]
                        }]
            }
        },
         "oldValues": None
    }
}))


service_L4_group_json_obj = wrapper(copy.deepcopy({
    "call": {"create": {"POST": "/Administration/rest/adsg/configure/save"},
             "update": {"POST": "/Administration/rest/adsg/configure/save"},
             "delete": {"POST": "/Administration/rest/adsg/configure/save"},
             "search": {"GET": "/Administration/rest/adsg/configure/L4Pool?accountId=1"
                                }
             },

    "ds":
    {
	"dataSource": "commitData",
	"operationType": "insert",
	"data": {
		"accountId": "1",
		"resourceList": {
			"L4Pool": [{
				"XMLID": "1",
				"accountId": "1",
				"name": "",
				"loadBalanceAlgorithm": "",
				"protocol": "",
				"healthMonitorStatus": "Disabled",
				"healthMonitorChecker": "TCP",
				"healthMonitorFailureThreshold": "3",
				"healthMonitorSuccessThreshold": "3",
				"healthMonitorTimeout": "3",
				"healthMonitorInterval": "5",
				"vServer": "",
				"servers": []
			}]
		}
	},
	"oldValues": None
}

}))

'''
Format of service_group_create_member
'''
service_group_member_obj = wrapper(copy.deepcopy({
    "call": {
             "create": {"POST": "/Administration/rest/adsg/configure/save"},
             "update": {"POST": "/Administration/rest/adsg/configure/save"},
             "delete": {"POST": "/Administration/rest/adsg/configure/save"},
             },
    "ds": {
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{
                "Pool":[{
                    "name":"",
                    "servers":[
                    ],
                    "cloudServers":[
                    ],
                    "objectId":""
                        }]
                }
             }
          }
}))

service_L4_group_member_obj = wrapper(copy.deepcopy({
    "call": {
             "create": {"POST": "/Administration/rest/adsg/configure/save"},
             "update": {"POST": "/Administration/rest/adsg/configure/save"},
             "delete": {"POST": "/Administration/rest/adsg/configure/save"},
             },
    "ds": {
        "dataSource":"commitData",
        "operationType": "update",
        "data": {
            "accountId":"1",
            "resourceList":{
                "L4Pool":[{
                    "name":"",
                    "servers":[
                    ],

                    "pool":""
                        }]
                }
             }
          }
}))

'''
Virtual Server Format
'''
virtual_server_object = wrapper(copy.deepcopy({
    "call": {"create": {"POST": "/Administration/rest/adsg/configure/save"},
             "update": {"POST": "/Administration/rest/adsg/configure/save"},
             "delete": {"POST": "/Administration/rest/adsg/configure/save"},
             "search": {"GET": "/Administration/rest/adsg/configure/VServer?accountId=1"},
             "search_vserver_pool": {"GET": "/Administration/rest/adsg/configure/VServer,Pool?accountId=1"},

             },
    "ds": {
         "dataSource":"commitData",
         "operationType":"update",
         "data":{"accountId":"1",
                  "resourceList":{
                          "VServer":[ { "XMLID":"1",
                                        "accountId":"1",
                                        "name":"" ,
                                        "http":"",
                                        "httpPort":"",
                                        "https":"",
                                        "httpsPort":"",
                                        "dnsName":"",
                                        "activeChallenge":"Disabled",
                                        "locations":[
                                                   {
                                                     "XMLID":"2",
                                                     "accountId":"1",
                                                     "path":"/",
                                                     "name":"",
                                                     "status":"Enabled",
                                                     "gzip":"Disabled",
                                                     "gzipTypes":"application/json application/rss+xml"
                                                                 " application/javascript application/x-javascript application/atom "
                                                                 "application/atom+xml text/plain text/mathhtml text/xss text/xml text/css text/javascript",
                                                     "proxyCacheStatus":"Disabled",
                                                     "proxyCacheTypes":"application/pdf image/gif image/jpeg image/png",
                                                     "fileFilter":"*",
                                                     "serverdType":"ServedLocally",
                                                     "pool":"",
                                                     "errorMessage":"",
                                                     "comments":"",
                                                     "vServer":"1",
                                                     "reverseProxies":[ ],
                                                     "bodyReplacementRules":[ ],
                                                     "serverResponseHeaders":[ ],
                                                     "serverResponseRedirects":[ ]
                                                   }
                                                 ],
                                         "VIPAddr":{
                                             "accountId":"1",
                                             "XMLID":"3",
                                             "status":"Enabled",
                                             "vServer":"1",
                                             "VIP":"" },
                                        "trafficRules":[ ]
                                       }
                                    ]
                                }
                },
         "oldValues":None
    }
}))



virtual_L4_server_object = wrapper(copy.deepcopy({
    "call": {"create": {"POST": "/Administration/rest/adsg/configure/save"},
             "update": {"POST": "/Administration/rest/adsg/configure/save"},
             "delete": {"POST": "/Administration/rest/adsg/configure/save"},
             "search": {"GET": "/Administration/rest/adsg/configure/L4VServer?accountId=1"}
             },
    "ds": {
        	 "dataSource": "commitData",
	         "operationType": "insert",
	         "data": {
		             "accountId": "1",
		             "resourceList": {
			         "L4VServer": [{
				                    "accountId": "1",
				                    "XMLID": "1",
				                    "name": "",
				                    "status": "",
			                     	"lip": "",
				                    "persistent_mask": "255.255.255.255",
				                    "port": "",
				                    "protocol": "",
				                    "synFlood": "Disabled",
				                    "timeout": "300",
				                    "VIPAddr": {
					                             "accountId": "1",
					                             "XMLID": "2",
					                             "status": "Enabled",
					                             "l4vServer": "1",
					                             "VIP": ""
				                                },
                                    "pool": ""

			                        }]
		                                }
	                 },
	                 "oldValues": None
              }
       }))










