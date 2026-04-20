// WiFi Cracker — uses crypto.so: airmon + aireplay + aircrack
// Usage: wifi_crack.gs [targetBssid] [targetEssid]

crypto = include_lib("/lib/crypto.so")
if not crypto then exit("crypto.so not found in /lib/")

// Get network interface from system
comp = get_shell.host_computer
iface = comp.network_devices.split(" ")[0]

// Get target info from params or prompt
targetBssid = ""
targetEssid = ""
if params.len >= 1 then
    targetBssid = params[0]
else
    targetBssid = user_input("Target BSSID (MAC): ")
end if
if params.len >= 2 then
    targetEssid = params[1]
else
    targetEssid = user_input("Target ESSID (network name): ")
end if
if targetBssid == "" or targetEssid == "" then exit("BSSID and ESSID required")

// Step 1: Enable monitor mode
print("[*] Enabling monitor mode on " + iface + "...")
result = crypto.airmon("start", iface)
if typeof(result) == "string" then exit("airmon failed: " + result)
print("[+] Monitor mode enabled")

// Step 2: Capture handshake with aireplay
print("[*] Deauthing clients on " + targetBssid + "...")
result = crypto.aireplay(targetBssid, targetEssid, 5)
if typeof(result) == "string" then exit("aireplay failed: " + result)
print("[+] Handshake captured")

// Get capture file path
capturePath = user_input("Capture file path: ")
captureFile = comp.File(capturePath)
if captureFile == null then exit("Capture file not found: " + capturePath)

// Step 3: Crack with aircrack
print("[*] Starting aircrack...")
password = crypto.aircrack(capturePath)
if not password then
    print("[-] Password not found in wordlist")
else
    print("[+] PASSWORD CRACKED: " + password)
end if

// Cleanup: Stop monitor mode
print("[*] Disabling monitor mode...")
crypto.airmon("stop", iface)
print("[+] Done.")
