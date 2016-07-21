tcp_delay kernel module
=======================

TCP delay is a kernel module that enables from user space delay tcp connections from a period of time.

Using tcp_delay 
---------------

Make a netstat and find the connections that you want to delay

        tcp        0      0 192.168.1.17:80         200.85.202.94:23478     ESTABLISHED
        tcp        0      0 192.168.1.17:80         155.245.213.50:44501    ESTABLISHED
        tcp        0      0 192.168.1.17:80         200.46.5.47:90854       ESTABLISHED
        tcp        0      0 192.168.1.17:80         192.168.1.125:87308     ESTABLISHED
        tcp        0      0 192.168.1.17:80         8.18.145.134:12475      ESTABLISHED
        tcp        0      0 192.168.1.17:80         132.245.77.18:8745      ESTABLISHED
        tcp        0      0 192.168.1.17:80         12.1.145.134:53943      ESTABLISHED
        tcp        0      0 192.168.1.17:80         2.1.104.182:23534       ESTABLISHED

do a copy/paste of the connection that you want to delay and redirect to the proc file

        echo "192.168.1.17:80         8.18.145.134:12475" >/proc/net/tcp_delay

for see the connections just cat /proc/net/tcp_delay

Contributing to tcp_delay 
-------------------------

The module has been tested over kernels 4.x

