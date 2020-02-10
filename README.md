# mod_redalert
dos ddos protection module for apache webserver

compile: apxs -i -a -c mod_redalert.c

redalert uses ipset to add malicious IP addresses to ipset list

You should create ipset lists,
ipset create [ipset_name] hash:ip timeout 3600

Timeout is optional, you can get more information about ipset from here:http://ipset.netfilter.org/ipset.man.html

Then you can easily drop all packets came from these IP addresses.

iptables -I INPUT 1 -m set --match-set [ipset name] src -j DROP

Your apache configuration file will look like this;

<IfModule mod_redalert.c>
	LogDirectory "/home/me/"
	
	SafeIp 127.0.0.1 1.2.3.4
	
	AddRule * .php 5 75 test1
	AddRule * watch.php 5 15 test2
	AddRule mydomain.com user.php 10 40 test3
	AddRule myotherdomain.com .php 30 90 test4
	
	Watch * .php /home/me/watch1
	Watch mydomain.com user.php /home/me/watch2
</IfModule>

