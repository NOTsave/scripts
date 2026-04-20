// IP sanitizer utility — strips your IP from output
// Usage: import_code("/path/to/utils/sanitize_ip.gs")

// Get local IP once at load time
__local_ip = get_shell.host_computer.lan_ip

sanitize_ip = function(text)
    if typeof(text) != "string" then text = str(text)
    return text.replace(__local_ip, "[REDACTED]")
end function

// Also export the IP for other uses
get_local_ip = function()
    return __local_ip
end function
