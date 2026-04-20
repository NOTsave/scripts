cr=include_lib("/lib/crypto.so")
if not cr then exit("crypto.so not found in /lib/")
tb=""
te=""
if params.len>=1 then
    tb=params[0]
else
    tb=user_input("Target BSSID (MAC): ")
end if
if params.len>=2 then
    te=params[1]
else
    te=user_input("Target ESSID (network name): ")
end if
if tb=="" then exit("No BSSID provided")
c=get_shell.host_computer
iface=c.network_devices.split(" ")[0]
print("[*] Enabling monitor mode with airmon...")
r=cr.airmon("start",iface)
if typeof(r)=="string" then exit("airmon failed: "+r)
print("[+] Monitor mode enabled on "+iface+"mon")
print("[*] Capturing handshake from "+tb+"...")
print("    (Deauthing clients to force reconnection)")
r=cr.aireplay(tb,te,5)
if typeof(r)=="string" then exit("aireplay failed: "+r)
print("[+] Handshake captured")
print("[*] Starting aircrack...")
cp=user_input("Capture file path: ")
cf=c.File(cp)
if cf==null then exit("Capture file not found: "+cp)
p=cr.aircrack(cp)
if p==null then
print("[-] Password not found in wordlist")
else
print("[+] PASSWORD CRACKED: "+p)
end if
print("[*] Disabling monitor mode...")
cr.airmon("stop",iface+"mon")
print("[+] Done.")
// Size: 1114 chars
