# CNC discovery

This project is a cnc discovery nmap scripts written in lua.


## mtconnect agent
For now i'm trying to start with an [mtconnect agent](https://www.mtconnect.org/standard-download20181).
this is an http service returning xml data.

to test it i'm using the mazak demo agents [here](http://mtconnect.mazakcorp.com/)

## Installation

The easy way is to copy paste scripts into nmap scripts folder `/usr/share/nmap/scripts/` and run the following command

```bash
$ nmap --script mtc-discovery mtconnect.mazakcorp.com -p 5609-5720

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-18 16:44 EDT
Nmap scan report for mazak-corporation-66-42-196-108.static.fuse.net (66.42.196.108)
Host is up (0.053s latency).
Not shown: 105 filtered tcp ports (no-response)
PORT     STATE SERVICE
5609/tcp open  unknown
| mtc-discovery: 
|   agent-version: 1.4.0.12
|   devices: 
|     
|_      name: MFMS10-MC1
5610/tcp open  unknown
| mtc-discovery: 
|   agent-version: 1.4.0.12
|   devices: 
|     
|       manufacturer: Mazak_Corporation
|       serialNumber: 304141
|_      name: MFMS10-MC2
5611/tcp open  unknown
| mtc-discovery: 
|   agent-version: 1.4.0.12
|   devices: 
|     
|       manufacturer: Mazak_Corporation
|       serialNumber: 304141
|_      name: Mazak
5612/tcp open  unknown
| mtc-discovery: 
|   agent-version: 1.6.0.6
|   devices: 
|     
|       manufacturer: Mazak_Corporation
|       serialNumber: 272237
|_      name: MFMS18-MC1
5701/tcp open  unknown
| mtc-discovery: 
|   agent-version: 1.6.0.7
|   devices: 
|     
|       manufacturer: Mazak_Corporation
|       serialNumber: 272237
|_      name: M12345
5717/tcp open  prosharenotify
| mtc-discovery: 
|   agent-version: 1.8.0.3
|   devices: 
|     
|       manufacturer: Mazak_Corporation
|       serialNumber: 272237
|_      name: M12346
5719/tcp open  dpm-agent
| mtc-discovery: 
|   agent-version: 2.3.0.7
|   devices: 
|     
|       manufacturer: Mazak_Corporation
|       serialNumber: 304141
|_      name: HCN001

Nmap done: 1 IP address (1 host up) scanned in 2.35 seconds
```