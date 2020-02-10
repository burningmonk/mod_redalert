# mod_redalert
dos ddos protection module for apache webserver

compile: apxs -i -a -c mod_redalert.c

redalert uses ipset to add malicious IP addresses to ipset list

You should create ipset lists,
ipset create [ipset_name] hash:ip timeout 3600

Timeout is optional, you can get more information about ipset from here:http://ipset.netfilter.org/ipset.man.html

Then you can easily drop all packets came from these IP addresses.

iptables -I INPUT 1 -m set --match-set [ipset name] src -j DROP

