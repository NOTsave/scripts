ti=params[0]
if not is_valid_ip(ti) then exit("Invalid IP address: "+ti) end if
r=get_router(ti)
if r==null then exit("Cannot get router for IP: "+ti) end if
lm=r.computers_lan_ip
if lm==null or lm.len==0 then exit("No LAN machines found") end if
for mi in lm
if mi==null then continue end if
ps=r.device_ports(mi)
if ps==null then continue end if
for p in ps
if p==null then continue end if
if p.is_closed then continue end if
pi=r.port_info(p)
if pi==null or pi=="" then pi="Unknown" end if
print(mi+":"+p.port_number+" — "+pi)
end for
end for
// Size: 398 chars
