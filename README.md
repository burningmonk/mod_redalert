# mod_redalert
dos ddos protection module for apache webserver

compile: **apxs -i -a -c mod_redalert.c**

redalert uses ipset to add malicious IP addresses to ipset list

You should create ipset lists,
ipset create [ipset_name] hash:ip timeout 3600

Timeout is optional, you can get more information about ipset from here:http://ipset.netfilter.org/ipset.man.html

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
				
if request's host-name and uri match's with those two parameters then counter for this ip-rule pair is created if not exist, if created before, increase the counter.

Host-name can be * for match with any host-name.
				
Third parameter is period of time in seconds that counter will count all requests in that time for that rule-ip pair.
				
Fourth parameter is count threshold, if this threshold reached then this ip will be added to the ipset list described on fifth parameter.

You can add 20 AddRule but less rules better for performance. Think that server is under ddos attack, for each request there will be many counters the amount of addrule, this may even magnify the harm of attack.

## Watch

You can log requests matched with your host-name uri-suffix pair to develop proper rule for AddRule. First 2 parameters same with AddRule, 3. parameter is path for log file

For example add this line 

Watch * .php /home/watch1

then execute this command

tail -f /home/watch1

you will see all php requests for all web sites on the fly

### Final

When you sure your configuration is ok and those ip addresses are all malicious, you can drop all packets came from those ip addresses,

iptables -A INPUT -m set --match-set [ipset_name] src -j DROP

### Shared Memory

redalert uses shared memory, you can list or delete the memory if any trouble happens

list shared memories

ipcs -m

delete shared memory created by redalert module

ipcrm -M 0x0006c88b

### Visudo

To make redalert able to run ipset you must give this permision.  Run **visudo** then add this line

www-data ALL=NOPASSWD: /sbin/ipset *

### Log files cannot create

Don't forget to give proper permission on log directories to make module able to deal with files.

chmod 777 /your/log/directory/
