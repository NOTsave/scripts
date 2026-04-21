// banner_grab.gs - Network banner grabbing tool
// Accepts target IP, scans all LAN machines and their open ports
// Note: Use get_router() for your own network, get_router(ip) for remote target

targetIp = ""

// Get target IP from params or user input
if params.len > 0 then
    targetIp = params[0]
else
    targetIp = user_input("Enter target IP: ")
end if

if targetIp == "" then
    exit("No target IP provided")
end if

// Validate IP address
if not is_valid_ip(targetIp) then
    exit("Invalid IP address: " + targetIp)
end if

print("Banner grabbing for network: " + targetIp)

// Get router - use target IP for remote networks, omit for own network
// For scanning your own LAN: router = get_router()
// For scanning remote target: router = get_router(targetIp)
router = get_router(targetIp)
if router == null then
    exit("Cannot get router for IP: " + targetIp)
end if

// Get all LAN machines
lanMachines = router.computers_lan_ip
if lanMachines == null or lanMachines.len == 0 then
    exit("No LAN machines found")
end if

print("Found " + str(lanMachines.len) + " machines on LAN")
print("Scanning ports and grabbing banners...")

// Scan each machine
for machineIp in lanMachines
    if machineIp == null then continue
    
    print("Scanning machine: " + machineIp)
    
    // Get ports for this machine
    ports = router.device_ports(machineIp)
    if ports == null then
        print("  No ports found for " + machineIp)
        continue
    end if
    
    // Check each port
    for port in ports
        if port == null then continue
        
        // Skip closed ports
        if port.is_closed then continue
        
        // Get port info
        portInfo = router.port_info(port)
        if portInfo == null then
            portInfo = "Unknown service"
        end if
        
        // Print result
        print("  " + machineIp + ":" + port.port_number + " — " + portInfo)
    end for
end for

print("Banner grab complete.")
