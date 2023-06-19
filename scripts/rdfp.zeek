# Copyright 2020, Verizon Media
# Licensed under the terms of the Apache 2.0 license. See LICENSE file in github.com/yahoo/rdfp root directory for terms.

#          RDFP = md5(verMajor;verMinor;clusterFlags;encryptionMethods;extEncMethods;channelDef)

module RDPrinting;

export {

	redef enum Log::ID += { RDFP };
}

	type RDPFPStorage: record {
		id:		conn_id &log &optional;
       		cookie:		string &log &optional;
		verMajor:	int &default=0 &log;
       		verMinor:	int &default=0 &log;
       		clusterFlags:	string &default="" &log;
       		encMethods:	string &default="" &log;
       		extEncMethods:	string &default="" &log;
       		channelDef:	string &default="" &log;
       		rdfp_string:	string &default="" &log;
       		rdfp_hash:	string &default="" &log;

  };


redef record connection += {
	rdfp: RDPFPStorage &optional;
};

const sep = "-";
const rdfp_sep = ",";

event zeek_init() {
	Log::create_stream(RDPrinting::RDFP, [$columns=RDPFPStorage, $path="rdfp"]);
}

const negproto: table[count] of string &redef;

redef negproto += {
    [0] = "RDP",
    [1] = "SSL",
    [2] = "HYBRID",
    [3] = "Undefined",
    [4] = "RDSTLS",
    [5] = "undef5",
    [6] = "undef6",
    [7] = "undef8",
    [8] = "HYBRID-EX",
    [16] = "RDSAAD"
};

event rdp_connect_request(c: connection, cookie: string) &priority=5
{
if ( !c?$rdfp )
	c$rdfp = RDPFPStorage();
c$rdfp$id = c$id;
c$rdfp$cookie = cookie;
}

event rdp_client_core_data(c: connection, data: RDP::ClientCoreData) &priority=5
{
if ( !c?$rdfp )
        c$rdfp = RDPFPStorage();

c$rdfp$verMajor = data$version_major;
c$rdfp$verMinor = data$version_minor;
}

event rdp_client_cluster_data(c: connection, data: RDP::ClientClusterData)
{
if ( !c?$rdfp )
        c$rdfp = RDPFPStorage();
c$rdfp$clusterFlags = fmt("%08x",data$flags);
}

event rdp_client_security_data(c: connection, data: RDP::ClientSecurityData)
{
if ( !c?$rdfp )
        c$rdfp = RDPFPStorage();
local encMethod = fmt("%08x",data$encryption_methods);
c$rdfp$encMethods = encMethod;
c$rdfp$extEncMethods = fmt("%08x",data$ext_encryption_methods);
}


event rdp_client_network_data(c: connection, channels: RDP::ClientChannelList)
{
if ( !c?$rdfp )
        c$rdfp = RDPFPStorage();
for ( i in channels ) {
  if ( c$rdfp$channelDef == "" )
    {
    c$rdfp$channelDef = fmt("%s:%08x", gsub(channels[i]$name,/\x00/,""), channels[i]$options);
    }
  else {
    c$rdfp$channelDef += fmt("%s%s:%08x", sep, gsub(channels[i]$name,/\x00/,""), channels[i]$options);

    }
  }
}

##          RDFP = md5(verMajor;verMinor;clusterFlags;encryptionMethods;extEncMethods;channelDef)

event rdp_begin_encryption(c: connection, security_protocol: count)
{
if ( !c?$rdfp )
	c$rdfp = RDPFPStorage();
local myproto = cat(negproto[security_protocol]);
if( c?$rdfp ) {
local rdfp_string = join_string_vec(vector(cat(c$rdfp$verMajor),
					cat(c$rdfp$verMinor),
					c$rdfp$encMethods,
					c$rdfp$clusterFlags,
					cat(c$rdfp$extEncMethods),
					c$rdfp$channelDef
					), rdfp_sep);
c$rdfp$rdfp_hash = md5_hash(rdfp_string);
c$rdfp$rdfp_string = rdfp_string;
c$rdfp$id = c$id;
   Log::write(RDPrinting::RDFP, c$rdfp);
  }
}
