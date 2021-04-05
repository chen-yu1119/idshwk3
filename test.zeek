global relation: table[addr] of set[string]={};

event http_header(c:connection, is_orig:bool, name:string, value:string)
{
	local Addr: addr = c$id$orig_h;
	local UserAgent: string=to_lower(value);
	if(name=="USER-AGENT")
	{
		if(Addr in relation)
		{
			add relation[Addr][UserAgent];
		}
		else
		{
			relation[Addr]=set(UserAgent);
		}
	}
}

event zeek_done()
{
	local s: string=" is a proxy";
	for(i in relation)
	{
		if((|relation[i]|)>=3)
			print i,s;
	}
}
