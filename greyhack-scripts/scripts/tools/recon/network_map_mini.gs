ti=params[0]
if not is_valid_ip(ti) then exit("Invalid IP: "+ti) end if
r=get_router(ti)
if r==null then exit("Could not get router for "+ti) end if
li=r.computers_lan_ip
if li==null then exit("Could not retrieve LAN machines") end if
if li.len==0 then exit("No LAN machines found") end if
for ip in li
ps=r.device_ports(ip)
if ps==null then continue end if
for p in ps
if p.is_closed!=1 then
pi=r.port_info(p)
if pi==null or pi=="" then pi="Unknown" end if
print(ip+":"+p.port_number+" — "+pi)
end if
end for
end for
// Size: 347 chars
