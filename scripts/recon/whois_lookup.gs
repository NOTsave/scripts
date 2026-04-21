// whois_lookup.gs - IP/domain whois lookup tool
// Accepts target from params or user_input, resolves domains, runs whois

target = ""

// Get target from params or user input
if params.len > 0 then
    target = params[0]
else
    target = user_input("Enter target IP or domain: ")
end if

if target == "" then
    exit("No target provided")
end if

print("Looking up: " + target)

// Check if target is valid IP
if is_valid_ip(target) then
    // Direct whois on IP
    result = whois(target)
    if result == "Not found" then
        print("WHOIS not found for IP: " + target)
    else
        print("WHOIS results for " + target + ":")
        print(result)
    end if
else
    // Try to resolve domain first
    print("Resolving domain: " + target)
    resolvedIp = nslookup(target)
    
    if resolvedIp == "Not found" then
        print("Domain resolution failed: " + target)
        exit("Cannot resolve domain: " + target)
    end if
    
    print("Resolved to IP: " + resolvedIp)
    
    // Run whois on resolved IP
    result = whois(resolvedIp)
    if result == "Not found" then
        print("WHOIS not found for IP: " + resolvedIp)
    else
        print("WHOIS results for " + target + " (" + resolvedIp + "):")
        print(result)
    end if
end if

print("Lookup complete.")
