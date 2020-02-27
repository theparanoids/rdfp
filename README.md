# rdfp
Zeek Remote desktop fingerprinting script based on FATT (Fingerprnt All The Things).
https://github.com/0x4D31/fatt

## Background
This is the result of a collaboration with Adel K. while he was working on FATT's remote desktop fingerpinting.  This is a Zeek package to be used to fingerprint the Remote Desktop clients.

Please reference Microsoft's RDP specification located below.

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5073f4ed-1e93-45e1-b039-6e30c385867c


## Install
zkg https://github.com/yahoo/rdfp
Add "**@load ./rdfp**" to local.bro.

## How It Works

The script will create a new log which will log the details which build the fingerprint and some additional information.  The fingerperint is created by concatenating extracted fields from different data packets.  

First the Cleint Core Data packet is parsed and extracts the Major and Minor version of the client.  Next the Client Security Data is parsed and the Encryption Method and a list of the flags are added.  This is followied by the Client Cluster Data flags.  This is followed by the extEncryptionMethods value which is definied specifically for French locale clients.  The last group of data is the Channel Defintion options for each channel defined which provide details about the data transport.

Here is an example output based on the [rdp_proprietary-encryption.pcap](https://github.com/zeek/zeek/tree/master/testing/btest/Traces/rdp) provided by Zeek.org.

```4,8,0000001b,0000000d,00000000,rdpdr:80800000-rdpsnd:c0000000-drdynvc:c0800000-cliprdr:c0a00000```

Associated MD5 hash

```471a0d621e6184364949f1a62040e7f6```

Sample rdfp.log based on the same pcap file.

```#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	rdfp
#open	2020-02-04-14-52-01
#fields	id.orig_h	id.orig_p	id.resp_h	id.resp_p	cookie	verMajor	verMinor	clusterFlags	encMethods	extEncMethods	channelDef	rdfp_string	rdfp_hash
#types	addr	port	addr	port	string	int	int	string	string	string	string	string	string
172.21.128.16	1312	10.226.24.52	3389	FTBCO\\A70	4	8	0000000d	0000001b	00000000	rdpdr:80800000-rdpsnd:c0000000-drdynvc:c0800000-cliprdr:c0a00000	4,8,0000001b,0000000d,00000000,rdpdr:80800000-rdpsnd:c0000000-drdynvc:c0800000-cliprdr:c0a00000	471a0d621e6184364949f1a62040e7f6
#close	2020-02-04-14-52-01
```

## Disclaimer

This technique is specifically for non-TLS encrypted RDP sessions. For SSL/TLS encrypted RDP sessions refer to the JA3 fingerprint technique.  https://github.com/salesforce/ja3

## Contribute
Please refer to the CONTRIBUTING.md file for information about how to get involved. We welcome issues, feature requests, pull requests, and documentation updates in GitHub.

## License

This project is licensed under the terms of the Apache 2.0 open source license. Please refer to LICENSE for the full terms.
