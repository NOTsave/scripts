ti=""
if params.len>=1 then
ti=params[0]
else
ti=user_input("Target IP: ")
end if
if not is_valid_ip(ti) then exit("Invalid IP: "+ti)
r=get_router(ti)
if r==null then exit("Could not get router for "+ti)
print("[*] Scanning "+ti+"...")
print("    Router: "+r.public_ip+" ("+r.essid_name+")")
print("")
p=[]
ir=(ti==r.public_ip or ti==r.local_ip)
if ir then
p=r.used_ports
print("Target is the router — listing "+p.len+" forwarded ports")
else
p=r.device_ports(ti)
if p==null then exit("Could not get ports for "+ti+" (is it connected?)")
print("Target is LAN machine — found "+p.len+" open ports")
end if
print("")
if p.len==0 then
print("No ports found.")
else
print("PORT     SERVICE INFO")
print("-"*50)
for po in p
if po.is_closed then continue
pn=po.port_number
i=r.port_info(po)
if i==null then i="Unknown"
ps=str(pn)
while ps.len<8
ps=ps+" "
end while
print(ps+i)
end for
end if
print("")
print("[*] Recon complete.")
// Size: 784 chars
