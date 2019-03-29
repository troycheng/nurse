## Nurse
Nurse is a multithread health check/port detect tool for small/medium cluster using [tcp syn-scan](https://nmap.org/book/synscan.html)(syn, syn-ack, rst), for those unstable ports, it can send Alert message via DingTalk Robot Api. 

## Why Nurse?
Health check is common in many tools, like Load Balancing or Service Discovery, even some Monitor Systems. But most of them are too heavy to use, sometimes we(OP/Devops) just want a simple monitor tool which can alert us when the server crashed and when it recoverd, to help us decide whether further operations needed, especially for small teams with no well-established monitor systems. That's why Nurse is introduced here. 

It's simple, only one main file with three header files, no complex dependency. 

It's easy, combined with naming service and crontab it can adjust targets automatically.

It's rapid, only few milliseconds needed for hundreds targets, and alert immediately  

## Require
Linux env, gcc version > 4.8, curl-devel

## Install
`cd nusrse && make`, if no error, nurse will be generated in the same directory.

## Usage
```
./nurse -h
Usage: ./nurse -[frh]
	-f	file contains detect target with format:[ip:port\tserv_name], ie.: 192.168.0.1:80	test
	-r	dingding robot url
	-h	print this help message
For any questions pls feel free to contact frostmourn716@gmail.com
```

**NOTICE:** It requires **root** privilege to run because using [raw socket](http://man7.org/linux/man-pages/man7/raw.7.html). For how does Nurse work, you can refer [Using raw socket to do port scan(1)](https://www.dearcodes.com/index.php/archives/17/) and [Using raw socket to do port scan(2)](https://www.dearcodes.com/index.php/archives/32/) 

To get a DingTalk Robot url you can refer [DingTalk Open Api](https://open-doc.dingtalk.com/docs/doc.htm?spm=a219a.7629140.0.0.karFPe&treeId=257&articleId=105735&docType=1). After adding a robot you can get an url, using `https://oapi.dingtalk.com/robot/send?access_token=123` as an example. 

Detecting targets are organized in a text file, for example:

```
cat detect_host.txt
172.30.4.33:8725  classify
172.30.4.33:8727  rnncn
```

To run nurse, using: 

```
./nurse -f ./detect_host.txt -r https://oapi.dingtalk.com/robot/send?access_token=123 > log.txt 2>&1 &
```

If every thing is ok, it will log like this:

![Nurse log](imgs/nurse_run.jpg)

If some ports are unstable, nurse will send alert message like this:

![Nurse alert](imgs/nurse_example.jpg)

## Future
Now Nurse is just a simple health monitor tool on single server with little configuration for hundreds targets, if needed, it can be extended for larger cluster and support more alert methods. 
