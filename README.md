# Linux Modbus/TCP Filter Module #


## Overview ##

Modbus is an industrial communications protocol originally published by Modicon (now Schneider Electric) in 1979 for use with their programmable logic controllers (PLCs). This protocol has become a de facto standard for communication across a wide variety of industrial electronic devices.

Modbus is an application layer messaging protocol which operates in a request/response fashion, similar to HTTP or SNMP, where a "master" (client) initiates requests to one or more "slaves" (servers). Modbus masters may be PCs, workstations or high-end PLCs, while slave devices are low-end PLCs or RTUs, sensors or actuators. Where Modbus is directed over an Ethernet network, requests are directed to and dispatched from TCP/IP port 502 of the "slave" device.

A Modbus/TCP filter for Linux has made available by Venkat Pothamsetty and Matthew Franz previously and provided for download from http://modbusfw.sourceforge.net. The most recent version of this code however was written for Linux kernel 2.6.16 and no longer compiles against recent Linux kernel versions. To this end, this new filter match module for Modbus/TCP has been written and includes Modbus frame matching features beyond that available in the previous work by Pothamsetty and Franz.


## Packet Format ##

Modbus messages on an Ethernet network employ the following frame format:

![Modbus TCP Packet Format]()

Field                  | Length  | Description
:----------------------|:-------:|:---------------------------------
Transaction identifier | 2 bytes | Identification of Modbus request/response transaction tracking
Protocol identifier    | 2 bytes | Protocol identifer (0 = Modbus)
Length                 | 2 bytes | Number of bytes to follow
Unit identifier        | 1 byte  | Slave device address
Function code          | 1 byte  | Function
Data                   | Varies  | Data (actual length depends upon function code)


With respect to these fields of the Modbus request/response packet:

* **Transaction identifier -** The transaction identifier field is specified by the Modbus client in request messages and copied by the server to be included in response messages. This field is used for transaction pairing of request and response packets.

* **Protocol identifier -** The protocol identifier field may be used for intra-system multi-plexing. For Modbus, this field always has the value of zero.

* **Length -** The length field contains the number of bytes in the Modbus message following the length field, including the unit identifier and data fields.

* **Unit identifier -** The "slave address" field employed by Modbus on serial line messaging is replaced by a single byte "unit identifier" for Modbus/TCP messages. This field allows a device on a single IP address to act as a bridge or proxy to multiple independent Modbus slave devices.

* **Function code -** The function code associated with the Modbus request/response. Valid codes are in the range from 1 to 255 while the range from 128 to 255 are reserved and represent exception responses from a Modbus slave device. Function code "0" is not valid.


The details of the Modbus packet format can be found in further detail in the Modbus Application Protocol specification found on the Modbus Organization web site.


## Installation ##

The Modbus/TCP filter module been built on [Ubuntu 24.04.1 LTS (Noble Numbat)](http://releases.ubuntu.com/noble/) with GNU/Linux 6.8.12 and iptables 1.8.11. This installation involves the patching, building and installation of iptables and the build and installation of the Linux kernel Modbus/TCP filter module.


### Patching, building and installation of iptables ###

	~/git/modbusfw$ tar xf iptables-1.8.11.tar.xz
	~/git/modbusfw$ cd iptables-1.8.11
	~/git/modbusfw/iptables-1.8.11$ patch -p1 < ../iptables-1.8.11-modbusfw.patch
	patching file extensions/libxt_modbus.c
	patching file include/linux/netfilter/xt_modbus.h
	~/git/modbusfw/iptables-1.8.11$ 


There are no specific configuration or build requirements for iptables following the application of the Modbus/TCP filter patch as shown above. For building and installing iptables, please refer to the INSTALL file in the iptables source folder.


### Build and installation of Modbus/TCP filter module ###

	~/git/modbusfw$ cd src/kernel
	~/git/modbusfw/src/kernel$ make
	make -C /lib/modules/`uname -r`/build M=$PWD
	make[1]: Entering directory '/home/rob/build/kernel/linux-6.8.12'
	  CC [M]  /home/rob/git/modbusfw/src/kernel/xt_modbus.o
	  MODPOST /home/rob/git/modbusfw/src/kernel/Module.symvers
	  CC      /home/rob/git/modbusfw/src/kernel/xt_modbus.mod.o
	  LD [M]  /home/rob/git/modbusfw/src/kernel/xt_modbus.ko
	make[1]: Leaving directory '/home/rob/build/kernel/linux-6.8.12'
	~/git/modbusfw/src/kernel$ sudo modprobe x_tables
	~/git/modbusfw/src/kernel$ sudo insmod xt_modbus.ko
	~/git/modbusfw/src/kernel$


The build of the Modbus/TCP filter module is dependent upon Linux kernel source files. The location of these source files can be specified using the environment variable KDIR prior to calling make. If this source location is not specified, the make file will default to looking for these source files in /lib/modules as shown above.

The Modbus/TCP filter module can then be loaded using insmod. Note that this kernel module is dependent upon x_tables functionality and as such, if this module is not loaded or built-in to your kernel image, an unknown symbol error will be returned by insmod. This can be simply corrected by loading x_tables module prior to loading the Modbus/TCP filter module via insmod.

Additionally, while not a problem with earlier versions of Ubuntu, with 24.04.1 LTS it was also found necessary to remove the distribution iptables package and delete distribution libip4tc2 and libxtables library files to prevent conflict between these and the newly built versions.


## Rules Specification ##

With this Modbus/TCP filter module, extended packet matching can be specified using iptables with the *-m* or *--match* options, following my the protocol match name "modbus". It is using this extended packet matching mechanism that Modbus/TCP specific filtering rules can defined based upon Modbus frame fields.

Supported matching options include:

Parameter                            | Descripton
:------------------------------------|:------------------------------------
`[!] --id transaction[:transaction]` | Transaction identifier(s)
`[!] --prot protocol`                | Protocol identifier
`[!] --len length`                   | Length
`[!] --unit addr[:addr]`             | Unit identifier(s)
`[!] --fc function[:function]`       | Function code(s)
`[!] --reg register[:register]`      | Register(s)


Examples:

	# Drop all requests with protocol identifier other than zero (Modbus)
	iptables -I INPUT -p tcp -m tcp --dport 502 -m modbus ! --prot 0 -j DROP
	# Drop all requests except those directed to Modbus device 7
	iptables -I INPUT -p tcp -m tcp --dport 502 -m modbus ! --unit 7 -j DROP
	# Allow read holding register requests for registers 1-100
	iptables -I INPUT -p tcp -m tcp --dport 502 -m modbus --fc 3 --reg 1:100 -j ACCEPT


## Links ##

* [Modbus Organization](http://www.modbus.org)

	The Modbus Organization is a group of independent users and suppliers of automation devices that seeks to drive the adoption of the Modbus communication protocol suite and the evolution to address architectures for distributed automation systems across multiple market segments. The Modbus Organization also provides the infrastructure to obtain and share information about the protocols, their application and certification to simplify implementation by users.

	Protocol specification and test tools can also be downloaded from http://www.modbus.org

* [Modbus - Wikipedia](https://en.wikipedia.org/wiki/Modbus)

	General overview and description of the Modbus protocol.

* [Linux DNP3 Filter Module](https://github.com/61131/dnp3fw)

	Similar Linux kernel filter module by the same author for the DNP3 protocol.


