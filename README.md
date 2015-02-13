#Overview

[plain]
ADSG supports Load Balancer as a Service (LBaaS) on OpenStack (Havana version or later).
ADSG LBaaS driver is implemented based on OpenStack haproxy’s driver and thus it can
provide basic load balancing service for OpenStack server instances.
This guide employs three typical load balancing scenarios of ADSG. It describe how to integrate
ADSG LBaaS driver as an OpenStack component, and how to configure ADSG load balancer on
OpenStack to provide loading balancing as a service for clients.
For information about how to install and configure ADSG, see Neusoft NetEye Application
Delivery Security Gateway Quick Start Guide.

#Load Balancing Scenarios and Configurations

Both physical and virtual ADSG devices can be deployed in OpenStack environment. Typical
deployment scenarios include:<br>
2.1. VLAN Mode. Physical ADSG is deployed in OpenStack private cloud environment,
and provide load balancing service for back-end servers through Layer 2 VLAN.<br>
![image](https://github.com/liuxinneu/images/blob/master/%E6%96%B0%E5%A2%9E%E5%81%A5%E5%BA%B7%E7%9B%91%E6%8E%A72.PNG)

2.2. DSNAT Mode. Virtual ADSG is launched in an internal network of OpenStack, and
provide load balancing service for back-end servers through Neutron router.<br>
2.3. Proxy Mode. Physical ADSG is deployed in the external network of OpenStack.<br>
