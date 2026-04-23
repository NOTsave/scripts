if params.len<1 then exit("Usage: whois_lookup target") end if
t=params[0]
if t=="" then exit("No target provided") end if
if is_valid_ip(t) then
r=whois(t)
if r=="Not found" then
exit("WHOIS not found for IP: "+t)
else
print(r)
end if
else
ri=nslookup(t)
if ri=="Not found" then
exit("Cannot resolve domain: "+t)
end if
r=whois(ri)
if r=="Not found" then
exit("WHOIS not found for IP: "+ri)
else
print(r)
end if
end if
// Size: 298 chars
