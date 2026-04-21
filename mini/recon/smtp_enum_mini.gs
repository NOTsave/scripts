if params.len<2 then exit("Usage: smtp_enum ip port") end if
ti=params[0]
tp=params[1]
if not is_valid_ip(ti) then exit("Error: Invalid IP address") end if
pn=tp.to_int
if typeof(pn)=="string" then exit("Error: Port must be a number") end if
if pn<1 or pn>65535 then exit("Error: Port out of range 1-65535") end if
cr=include_lib("/lib/crypto.so")
if cr==null then exit("Error: Failed to load crypto.so") end if
us=cr.smtp_user_list(ti,pn)
if us==null then
exit("No users found or enumeration failed")
else if us.len==0 then
exit("No users discovered")
else
for u in us
print(u)
end for
end if
// Size: 378 chars
