// ============================================
// Shared Command Validation Library
// Eliminates code duplication between master and slave
// ============================================

// Validate command structure before broadcasting
validate_command = function(cmd)
    if cmd == null then return false
    if typeof(cmd) != "string" then return false
    if cmd.len == 0 then return false
    
    // Load max command length from config
    import_code("/scripts/utils/botnet_config.gs")
    max_length = get_config("ui.max_command_length")
    if max_length == null then max_length = 1024
    
    if cmd.len > max_length then return false
    
    parts = cmd.split(" ")
    if parts.len == 0 then return false
    
    // Check command is in allowed list
    allowed = ["run", "kill", "update", "status", "clean", "worm", "read", "rotate", "help"]
    if allowed.indexOf(parts[0]) == null then return false
    
    // Validate each part contains only printable characters
    for part in parts
        for c in part
            code = c.code
            if code < 32 or code > 126 then return false
        end for
    end for
    
    // Validate argument structure based on command
    if parts[0] == "run" then
        if parts.len < 2 then return false
        // Script path must not contain multiple consecutive slashes
        script_path = parts[1]
        if script_path.indexOf("//") != null then return false
        // Max 4 additional args
        if parts.len > 6 then return false
    else if parts[0] == "worm" then
        if parts.len < 3 then return false
        // Depth must be a number
        depth = parts[2].to_int
        if typeof(depth) != "number" then return false
        if depth < 0 or depth > 10 then return false
    else if parts[0] == "kill" then
        if parts.len < 2 then return false
    else if parts[0] == "read" then
        if parts.len < 2 then return false
        // File path must not contain //
        if parts[1].indexOf("//") != null then return false
    end if
    
    return true
end function

// Validate script arguments for security
validate_script_args = function(script, args)
    // Load allowed scripts from config
    import_code("/scripts/utils/botnet_config.gs")
    allowed_scripts = get_config("security.allowed_scripts")
    if allowed_scripts == null then
        // Fallback to hardcoded list if config fails
        allowed_scripts = [
            "/bin/slave.gs",
            "/bin/worm.gs",
            "/scripts/utils/forensics/wipe_logs.gs",
            "/scripts/utils/file_search.gs",
            "/scripts/utils/find_lib.gs",
            "/scripts/utils/accessLevel.gs"
        ]
    end if
    
    // Check if script is in whitelist
    if allowed_scripts.indexOf(script) == null then return false
    
    // Whitelist approach: only allow alphanumeric, dots, dashes, underscores, slashes
    allowed_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_/"
    
    for arg in args
        if arg.len > 256 then return false  // Max arg length
        for c in arg
            if allowed_chars.indexOf(c) == null then return false
        end for
    end for
    
    return true
end function

// Enhanced error messages for better user feedback
format_error = function(error_type, details)
    import_code("/scripts/utils/botnet_config.gs")
    verbose = get_config("ui.verbose_errors")
    if verbose == null then verbose = true
    
    if verbose then
        if error_type == "INVALID_COMMAND" then
            return "ERROR: Invalid command format. Type 'help' for available commands."
        else if error_type == "SCRIPT_NOT_ALLOWED" then
            return "ERROR: Script not in allowed list. Script: " + details
        else if error_type == "ACCESS_DENIED" then
            return "ERROR: Access denied. Path: " + details + " (outside allowed directories)"
        else if error_type == "FILE_NOT_FOUND" then
            return "ERROR: File not found: " + details
        else if error_type == "NETWORK_FAILED" then
            return "ERROR: Network operation failed: " + details + " (retrying...)"
        else
            return "ERROR: " + error_type + " - " + details
        end if
    else
        return "ERROR: " + error_type
    end if
end function

// Help system for better user experience
show_help = function()
    help_text = "
Botnet Master Controller Commands:
============================

Core Commands:
--------------
run <script> [args...]  - Execute script on target bots
kill <script>           - Stop running script on all bots
update                  - Update bot software on all bots
status                  - Get status from all bots
clean                   - Clean logs on all bots
worm <depth> <ip>      - Launch worm with specified depth
read <file>             - Read file from target bots
rotate                 - Rotate encryption keys
help                    - Show this help message

Examples:
---------
run /bin/slave.gs       - Execute slave on all bots
worm 3 192.168.1.100  - Launch worm at depth 3
status                   - Get bot status and health

Security Notes:
---------------
- All commands are validated before execution
- Scripts must be in allowed whitelist
- File paths are restricted to safe directories
- Network operations include automatic retry logic

For more detailed information, consult the deployment guide.
"
    
    print(help_text)
    return "HELP_SHOWN"
end function
