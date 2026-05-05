// kyber_transport.gs - C2 encryption and transport layer
// Separated from lib_common for clean architecture

import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")

// ============================================
// C2 Transport Configuration
// ============================================

C2_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2

// ============================================
// Key Management
// ============================================

get_c2_keypair = function()
    // Try to load existing keys
    priv = safe_file_read("/root/.botnet/slave.priv")
    pub = safe_file_read("/root/.botnet/slave.pub")
    
    if priv != null and pub != null then
        return {"private": priv, "public": pub}
    end if
    
    // Generate new keypair if none exists
    keys = Kyber.generate_keypair()
    if keys == null or keys.private == null or keys.public == null then
        log_master("ERROR: Failed to generate C2 keypair", "ERROR")
        return null
    end if
    
    // Save keys
    if safe_file_write("/root/.botnet/slave.priv", keys.private) and
       safe_file_write("/root/.botnet/slave.pub", keys.public) then
        set_permissions("/root/.botnet/slave.priv", "600")
        set_permissions("/root/.botnet/slave.pub", "644")
        log_master("Generated new C2 keypair", "INFO")
        return keys
    end if
    
    log_master("ERROR: Failed to save C2 keypair", "ERROR")
    return null
end function

get_master_pubkey = function(path="/root/.botnet/master.pub")
    pub = safe_file_read(path)
    if pub == null then
        log_master("ERROR: Master public key not found at " + path, "ERROR")
    end if
    return pub
end function

// ============================================
// Message Encryption/Decryption
// ============================================

encrypt_command = function(command, master_pubkey)
    if command == null or command == "" then return null
    if master_pubkey == null then return null
    
    cipher = Kyber.encrypt_message(master_pubkey, command)
    if cipher == null then
        log_master("ERROR: Failed to encrypt command", "ERROR")
    end if
    
    return cipher
end function

decrypt_command = function(cipher)
    if cipher == null or cipher == "" then return null
    
    keys = get_c2_keypair()
    if keys == null then return null
    
    command = Kyber.decrypt_message(keys.private, cipher)
    if command == null then
        log_master("ERROR: Failed to decrypt command", "ERROR")
    end if
    
    return command
end function

encrypt_response = function(response, master_pubkey)
    return encrypt_command(response, master_pubkey)
end function

decrypt_response = function(cipher)
    return decrypt_command(cipher)
end function

// ============================================
// Secure Transport
// ============================================

secure_send = function(ip, data, get_password_func)
    // Retry connection with exponential backoff
    connect_func = function()
        return get_shell.connect_service(ip, 22, "backdoor", get_password_func(ip))
    end function
    
    shell = retry_network(connect_func, MAX_RETRIES, RETRY_BASE_DELAY)
    if typeof(shell) == "string" or shell == null then
        log_master("Failed to connect to " + sanitize_ip(ip) + " after retries", "ERROR")
        return false
    end if
    
    // Create temporary encrypted file
    tmp_file = "/tmp/c2_" + str(time) + "_" + str(floor(rnd * 9999)) + ".enc"
    if not safe_file_write(tmp_file, data) then
        shell.close
        return false
    end if
    
    // Transfer file
    result = get_shell.scp(tmp_file, "/root/.botnet/commands/", shell)
    
    // Cleanup
    get_shell.host_computer.File(tmp_file).delete
    shell.close
    
    if typeof(result) == "string" then
        log_master("SCP transfer failed to " + sanitize_ip(ip) + ": " + result, "ERROR")
        return false
    end if
    
    return true
end function

secure_receive = function(ip, get_password_func)
    connect_func = function()
        return get_shell.connect_service(ip, 22, "backdoor", get_password_func(ip))
    end function
    
    shell = retry_network(connect_func, MAX_RETRIES, RETRY_BASE_DELAY)
    if typeof(shell) == "string" or shell == null then
        return null
    end if
    
    responses = []
    resp_dir = shell.host_computer.File("/root/.botnet/responses")
    
    if resp_dir != null then
        for f in resp_dir.get_files
            if f == null then continue
            if f.name[-4:] == ".enc" then
                cipher = f.get_content
                if cipher != null then
                    responses.push(cipher)
                end if
                f.delete
            end if
        end for
    end if
    
    shell.close
    return responses
end function

// ============================================
// Message Validation
// ============================================

validate_command_structure = function(command)
    if command == null or command == "" then return false
    if typeof(command) != "string" then return false
    if command.len > 1024 then return false
    
    // Basic structure validation
    parts = command.split(" ")
    if parts.len == 0 then return false
    
    // Check for forbidden characters
    forbidden = [";", "|", "&", "$", "`", "<", ">"]
    for part in parts
        for char in forbidden
            if part.indexOf(char) != null then
                return false
            end if
        end for
    end for
    
    return true
end function

// ============================================
// Transport Statistics
// ============================================

transport_stats = {
    "messages_sent": 0,
    "messages_received": 0,
    "encryption_failures": 0,
    "connection_failures": 0
}

update_stats = function(event_type)
    if transport_stats.hasIndex(event_type) then
        transport_stats[event_type] = transport_stats[event_type] + 1
    end if
end function

get_transport_stats = function()
    return transport_stats + []  // Return copy
end function

// ============================================
// Heartbeat System
// ============================================

send_heartbeat = function(ip, master_pubkey, get_password_func, metrics=null)
    heartbeat = {
        "type": "heartbeat",
        "timestamp": time,
        "version": "1.0",
        "uptime": time - (globals.start_time or time),
        "commands_executed": transport_stats["messages_sent"],
        "last_contact": globals.last_master_contact or 0
    }
    
    if metrics != null then
        heartbeat = heartbeat + metrics
    end if
    
    heartbeat_json = serialize_heartbeat(heartbeat)
    cipher = encrypt_command(heartbeat_json, master_pubkey)
    
    if cipher != null then
        result = secure_send(ip, cipher, get_password_func)
        if result then
            update_stats("messages_sent")
            globals.last_heartbeat = time
            return true
        end if
    end if
    
    update_stats("connection_failures")
    return false
end function

serialize_heartbeat = function(data)
    // Simple JSON-like serialization for GreyScript
    parts = []
    for key in data.keys
        value = data[key]
        if typeof(value) == "string" then
            parts.push(key + ":" + char(34) + value + char(34))
        else
            parts.push(key + ":" + str(value))
        end if
    end for
    return "{" + parts.join(",") + "}"
end function
