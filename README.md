# CNC discovery

This project is a cnc discovery nmap scripts written in lua.


## mtconnect agent
For now i'm trying to start with an [mtconnect agent](https://www.mtconnect.org/standard-download20181).
this is an http service returning xml data.

to test it i'm using the mazak demo agents [here](http://mtconnect.mazakcorp.com/)

## Installation

The easy way is to copy paste scripts into nmap scripts folder `/usr/share/nmap/scripts/` and run the following command

```bash
$ nmap --script mtc-discovery x.x.x.x -p 5000

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-19 10:30 EDT
...
PORT     STATE SERVICE
5000/tcp open  unknown
| mtc-discovery: 
|    agent-version: 1.4.0.12
|    devices:
|       name:           MFMS10-MC1
|       serialNumber:   -
|       manufacturer:   -
|       current:        x.x.x.x:5000/MFMS10-MC1/current
|       sample:         x.x.x.x:5000/MFMS10-MC1/sample
|_
```