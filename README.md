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

There is 4 configuration settings you can use;

## LogDirectory

Location of redalert.log file

## SafeIp

Add safe IP addresses here, those IP addresses will be ignored by redalert module

## AddRule

First two parameters is for selecting requests respectively host-name and uri-suffix
				
if request's host-name and uri match's with those two parameters then counter for this ip-rule pair is created Host-name can be * for match with any host-name.
				
Third parameter is period of time in seconds that counter will count all requests in that time for that rule-ip pair.
				
Fourth parameter is count threshold, if this threshold reached then this ip will be added to the ipset list described on 5. parameter. You can add 20 AddRule but less rules better for performance(think that server is under ddos attack, for each request there will be counters as number of addrule, this may magnify the attack's effect)
