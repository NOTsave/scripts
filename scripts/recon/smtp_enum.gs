// smtp_enum.gs - SMTP user enumeration
// Usage: smtp_enum [ip] [port]

// Get target IP from params or prompt
targetIp = ""
if params.len >= 1 then
    targetIp = params[0]
else
    targetIp = user_input("Target IP: ")
end if

// Validate IP
if not is_valid_ip(targetIp) then exit("Error: Invalid IP address")

// Get port from params or prompt
targetPort = ""
if params.len >= 2 then
    targetPort = params[1]
else
    targetPort = user_input("Target port (default 25): ")
    if targetPort == "" then targetPort = "25"
end if

// Validate port
portNum = targetPort.to_int
if typeof(portNum) == "string" then exit("Error: Port must be a number")
if portNum < 1 or portNum > 65535 then exit("Error: Port out of range 1-65535")

// Load crypto.so
crypto = include_lib("/lib/crypto.so")
if crypto == null then exit("Error: Failed to load crypto.so")

// Enumerate SMTP users
print("Enumerating SMTP users on " + targetIp + ":" + portNum)
users = crypto.smtp_user_list(targetIp, portNum)

// Handle result
if users == null then
    print("No users found or enumeration failed")
else if users.len == 0 then
    print("No users discovered")
else
    print("Found " + users.len + " user(s):")
    for user in users
        print("  - " + user)
    end for
end if
