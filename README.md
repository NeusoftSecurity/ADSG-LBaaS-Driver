#Overview


ADSG supports Load Balancer as a Service (LBaaS) on OpenStack (Havana version or later).
ADSG LBaaS driver is implemented based on OpenStack haproxy’s driver and thus it can
provide basic load balancing service for OpenStack server instances.
This guide employs three typical load balancing scenarios of ADSG. It describe how to integrate
ADSG LBaaS driver as an OpenStack component, and how to configure ADSG load balancer on
OpenStack to provide loading balancing as a service for clients.
For information about how to install and configure ADSG, see Neusoft NetEye Application
Delivery Security Gateway Quick Start Guide.

#Load Balancing Scenarios 

Both physical and virtual ADSG devices can be deployed in OpenStack environment. Typical
deployment scenarios include:<br>
2.1. VLAN Mode. Physical ADSG is deployed in OpenStack private cloud environment,
and provide load balancing service for back-end servers through Layer 2 VLAN.<br>
![github](https://github.com/liuxinneu/images/blob/master/vlan.PNG)  


2.2. DSNAT Mode. Virtual ADSG is launched in an internal network of OpenStack, and
provide load balancing service for back-end servers through Neutron router.<br>
![github](https://github.com/liuxinneu/images/blob/master/DSNAT.PNG)

2.3. Proxy Mode. Physical ADSG is deployed in the external network of OpenStack.<br>
![github](https://github.com/liuxinneu/images/blob/master/agent.PNG)
<br>

#Install ADSG LBaaS Driver

1. Download the NEUSOFT_ADSG driver and install it on to “..neutron/neutron/services/loadbalancer/drivers/NEUSOFT_ADSG” directory. <br>
2. Modify the configuration file “/etc/neutron/neutron.conf”. <br>
  Comment out the original haproxy settings.<br>
  Add information about ADSG:<br>
service_provider = LOADBALANCER:Neusoft_ADSG:neutron.services.loadbalancer.drivers.Neusoft_ADSG.adsg.AdsgDriver:default <br>
3. Enter service neutron-server restart to restart Neutron services.<br>
4. Configure ADSG LBaaS driver. Create a directory “mkdir -p /etc/neutron/services/loadbalancer/Neusoft_ADSG” and a configuration file config.py, and set as follows:<br>
devices = { <br>
"adsg1": { <br>
"username":"admin" <br>
"host": "10.1.3.119" <br>
"port": 10000 <br>
"protocol": "https" <br>
"password": "neteye" <br>
"localip": "172.16.0.10,172.16.1.10"<br>
"use_float": False <br>
"method": "hash" <br>
         } <br>
          } <br>
This table describes the detailed information of parameters above:<br>

**username\: ** Northbound interface name.<br>
**password\: ** Northbound interface password.<br>
**host\: ** Northbound interface IP address, used to communicate with the node where the OpenStack LBaaS driver is installed.<br>
**port\: **Number of the protocol used by the northbound interface.<br>
**protocol\: ** Protocol used by the northbound interface.<br>
**localip\: ** The IP address of one ADSG interface, used to communicate with back-end servers. It must be in the same IP segment as the pool subnet, otherwise, you cannot create a VIP. Multiple IPs are supported and they are separated by commas without spaces. The IP is configured for Layer 4 load balancing only and you can supply a null value for it when using Layer 7 load balancing.<br> 
**use_float\: ** Includes True and False.<br> 
    • True—indicates that floating IPs must be set for back-end servers on OpenStack, so that the servers can access external       networks. <br> 
    • False—indicates that there is no need to assign floating IPs to back-endservers. You are recommended to set use_float        to False in VLAN mode.<br> 
**method\: **If there are multiple ADSG devices, the algorithm can help tenants to choose the optimal ADSG device.
