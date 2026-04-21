// Network mapper — lists all LAN machines and their open ports
// Usage: network_map.gs [targetIp]

// Get target IP (router)
targetIp = ""
if params.len >= 1 then
    targetIp = params[0]
else
    targetIp = user_input("Router IP: ")
end if

if not is_valid_ip(targetIp) then exit("Invalid IP: " + targetIp)

// Get router
router = get_router(targetIp)
if router == null then exit("Could not get router for " + targetIp)

print("[*] Mapping network via " + targetIp + "...")
print("    Router: " + router.public_ip + " (" + router.essid_name + ")")
print("")

// Get all LAN machines
lanIps = router.computers_lan_ip
if lanIps == null then exit("Could not retrieve LAN machines")
if lanIps.len == 0 then exit("No LAN machines found")

print("Found " + lanIps.len + " LAN machine(s)")
print("")

// Loop through each LAN machine
for lanIp in lanIps
    // Get ports for this machine
    ports = router.device_ports(lanIp)
    
    if ports == null then
        print("[" + lanIp + "] Error retrieving ports")
        continue
    end if
    
    // Collect open ports
    openPorts = []
    for p in ports
        if p.is_closed != 1 then openPorts.push(p)
    end for
    
    if openPorts.len == 0 then
        print("[" + lanIp + "] No open ports")
    else
        print("[" + lanIp + "] " + openPorts.len + " open port(s):")
        
        // Print each open port
        for p in openPorts
            info = router.port_info(p)
            if info == null or info == "" then info = "Unknown"
            print(str(p.port_number).rfill(8, " ") + info)
        end for
    end if
    
    print("")
end for

print("[*] Network map complete.")
