// Port reconnaissance — lists open ports and service info
// Usage: recon_ports.gs [targetIp]

// Get target IP
targetIp = ""
if params.len >= 1 then
    targetIp = params[0]
else
    targetIp = user_input("Target IP: ")
end if

if not is_valid_ip(targetIp) then exit("Invalid IP: " + targetIp)

// Get router
router = get_router(targetIp)
if router == null then exit("Could not get router for " + targetIp)

print("[*] Scanning " + targetIp + "...")
print("    Router: " + router.public_ip + " (" + router.essid_name + ")")
print("")

// Determine if target is the router itself or a LAN machine
ports = []
isRouter = (targetIp == router.public_ip or targetIp == router.local_ip)

if isRouter then
    // Target is the router — get forwarded ports
    ports = router.used_ports
    print("Target is the router — listing " + ports.len + " forwarded ports")
else if is_lan_ip(targetIp) then
    // Target is a LAN machine
    ports = router.device_ports(targetIp)
    if ports == null then
        exit("Could not get ports for " + targetIp + " (is it connected?)")
    end if
    print("Target is LAN machine — found " + ports.len + " open ports")
else
    // Public IP — scan all LAN machines behind it
    print("Public IP detected — scanning all LAN machines...")
    lanIps = router.computers_lan_ip
    for lanIp in lanIps
        machinePorts = router.device_ports(lanIp)
        if machinePorts != null then
            for p in machinePorts
                ports.push(p)
            end for
        end if
    end for
    print("Found " + ports.len + " total ports across all LAN machines")
end if

print("")

// Print port details
if ports.len == 0 then
    print("No ports found.")
else
    print("PORT     SERVICE INFO")
    print("-" * 50)
    
    for port in ports
        if port.is_closed then continue
        
        portNum = port.port_number
        info = router.port_info(port)
        if info == null or info == "" then info = "Unknown"
        
        // Format: pad port number
        portStr = str(portNum)
        padLen = 8 - portStr.len
        if padLen > 0 then portStr = portStr + (" " * padLen)
        
        print(portStr + info)
    end for
end if

print("")
print("[*] Recon complete.")
