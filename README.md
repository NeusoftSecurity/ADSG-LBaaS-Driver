ADSG-LBaaS-Driver Overview
=====
This is the OpenStack LBaaS(Load Balancer as a Service) driver for SEnginx. It can provide basic load balancing service for OpenStack instances.

This driver is implemented based on OpenStack's haproxy driver in Havana version. The latest version of haproxy driver in OpenStack has been changed to support multi-vendor

ADSG github repos:
(https://github.com/NeusoftSecurity/ADSG-LBaaS-Driver) - OpenStack LBaaS driver,


Installation info:

To use this driver, you must:
- Install the adsg-neutron-lbaas module.
- Create a driver config file, a sample of which is given below.
- Enable it in neutron.conf
- Restart neutron-server


Configuration file:

Create a configuration file with a list of ADSG appliances, similar to the
file below, located at:
 /etc/neutron/services/loadbalancer/Neusoft_ADSG/config.py


Example config file:

devices = {
    "adsg1": {
        "username":"admin",
        "host": "190.168.30.8",
        "port": 10000,
        "protocol": "https",
        "password": "neteye",
        "localip" :"192.168.30.9"
        "use_float": False,
        "method": "hash"
           }
    }
