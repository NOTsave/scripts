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
wp=user_input("Wordlist path (default: /home/player/wordlist.txt): ")
if wp=="" then wp="/home/player/wordlist.txt"
wf=c.File(wp)
if wf==null then exit("Wordlist not found: "+wp)
p=cr.aircrack(tb,wp)
if p==null then
print("[-] Password not found in wordlist")
else
print("[+] PASSWORD CRACKED: "+p)
end if
print("[*] Disabling monitor mode...")
cr.airmon("stop",iface+"mon")
print("[+] Done.")
// Size: 1114 chars
