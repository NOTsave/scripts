// lib_common.gs – final with all fixes
red = function(str) return "<color=#c30000><b>" + str + "</b></color>" end function
green = function(str) return "<color=#00c300><b>" + str + "</b></color>" end function
yellow = function(str) return "<color=#ffff00><b>" + str + "</b></color>" end function
blue = function(str) return "<color=#85b8ff><b>" + str + "</b></color>" end function
white = function(str) return "<color=#eeeeee><b>" + str + "</b></color>" end function

rotate_log = function(log_path="/root/.botnet/log.txt", max_size_mb=10)
    comp = get_shell.host_computer
    f = comp.File(log_path)
    if not f then return
    if f.size > max_size_mb * 1024 * 1024 then
        f2 = comp.File(log_path + ".1")
        if f2 then f2.delete
        f.move(log_path + ".1")
        comp.touch(log_path.split("/")[:-1].join("/"), log_path.split("/")[-1])
        log_master("Log rotated (was " + f.size + " bytes)", "INFO")
    end if
end function

globals.log_write_count = 0
log_master = function(msg, level="INFO")
    comp = get_shell.host_computer
    log_file = comp.File("/root/.botnet/log.txt")
    if not log_file then
        comp.create_folder("/root", ".botnet")
        comp.touch("/root/.botnet", "log.txt")
        log_file = comp.File("/root/.botnet/log.txt")
    end if
    timestamp = current_date
    log_file.set_content(log_file.get_content + "[" + timestamp + "] [" + level + "] " + msg + char(10))
    globals.log_write_count = globals.log_write_count + 1
    if globals.log_write_count % 50 == 0 then rotate_log()
    if level == "ERROR" then
        print(red(msg))
    else if level == "WARN" then
        print(yellow(msg))
    else if level == "SUCCESS" then
        print(green(msg))
    else
        print(white(msg))
    end if
end function

write_file = function(path, content)
    comp = get_shell.host_computer
    parts = path.split("/")
    filename = parts.pop()
    dir_path = parts.join("/")
    if not comp.File(dir_path) then
        current = ""
        for part in parts
            if part == "" then continue
            current = current + "/" + part
            if not comp.File(current) then
                parent = current.split("/")[:-2].join("/")
                if parent == "" then parent = "/"
                result = comp.create_folder(parent, part)
                if typeof(result) == "string" then return false
            end if
        end for
    end if
    comp.touch(dir_path, filename)
    f = comp.File(path)
    if f then f.set_content(content)
    return f != null
end function

read_file = function(path)
    f = get_shell.host_computer.File(path)
    if f then return f.get_content
    return null
end function

get_pids = function(script_name)
    comp = get_shell.host_computer
    ps = comp.show_procs
    pids = []
    for line in ps.split(char(10))[1:]
        if line == "" then continue
        parts = line.split(" ")
        if parts.len < 2 then continue
        if parts[-1] == script_name then pids.push(parts[1].to_int)
    end for
    return pids
end function

kill_all = function(script_name)
    for pid in get_pids(script_name)
        get_shell.host_computer.close_program(pid)
    end for
end function

backoff_sleep = function(attempt, base=2, max=300)
    delay = base * (2 ^ attempt)
    if delay > max then delay = max
    wait(delay)
end function

// XOR obfuscation (defense-in-depth)
xor_obfuscate = function(data, key)
    if data == null then return ""
    if key == null then return data
    if key == "" then return data
    if typeof(data) != "string" then data = str(data)
    if typeof(key) != "string" then key = str(key)
    
    // Max 100KB input
    if data.len > 102400 then
        return data
    end if
    
    result = ""
    key_len = key.len
    
    for i in range(0, data.len - 1)
        key_char = key[i % key_len]
        result = result + char(data[i].code ^ key_char.code)
    end for
    
    return result
end function

generate_random_string = function(len)
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    result = ""
    for i in range(0, len-1)
        result = result + chars[floor(rnd * chars.len)]
    end for
    return result
end function

// Kyber-encrypted password storage (preferred)
store_password_kyber = function(file_path, password)
    if password == null then return false
    if file_path == null then return false
    
    pub = safe_file_read("/root/.botnet/slave.pub")
    if not pub then
        // Generate ephemeral keypair for this password
        keys = Kyber.generate_keypair()
        if keys == null then
            log_master("ERROR: Kyber key generation failed", "ERROR")
            return false
        end if
        if keys.private == null or keys.public == null then
            log_master("ERROR: Kyber generated invalid keypair", "ERROR")
            return false
        end if
        
        if not safe_file_write("/root/.botnet/passkey.priv", keys.private) then
            log_master("ERROR: Failed to write passkey.priv", "ERROR")
            return false
        end if
        set_permissions("/root/.botnet/passkey.priv", "600")
        
        if not safe_file_write("/root/.botnet/passkey.pub", keys.public) then
            log_master("ERROR: Failed to write passkey.pub", "ERROR")
            return false
        end if
        
        pub = keys.public
    end if
    
    cipher = Kyber.encrypt_message(pub, password)
    if cipher == null then
        log_master("ERROR: Kyber encryption failed for password", "ERROR")
        return false
    end if
    
    if not safe_file_write(file_path, cipher) then
        log_master("ERROR: Failed to write encrypted password to " + file_path, "ERROR")
        return false
    end if
    
    set_permissions(file_path, "600")
    return true
end function

retrieve_password_kyber = function(file_path)
    if file_path == null then return null
    
    cipher = safe_file_read(file_path)
    if not cipher then return null
    
    priv = safe_file_read("/root/.botnet/slave.priv")
    if not priv then
        priv = safe_file_read("/root/.botnet/passkey.priv")
    end if
    if not priv then
        log_master("ERROR: No private key available for password decryption", "ERROR")
        return null
    end if
    
    password = Kyber.decrypt_message(priv, cipher)
    if password == null then
        log_master("ERROR: Kyber decryption failed for password", "ERROR")
        return null
    end if
    
    return password
end function

// Keep old functions for backwards compatibility, but mark deprecated
store_password = function(file_path, password, key)
    if key == null then key = "botnet_key_2026"
    if key == "" then key = "botnet_key_2026"
    
    log_master("WARN: Using deprecated XOR password storage, migrate to Kyber", "WARN")
    obf = xor_obfuscate(password, key)
    write_file(file_path, obf)
end function

retrieve_password = function(file_path, key)
    if key == null then key = "botnet_key_2026"
    if key == "" then key = "botnet_key_2026"
    
    log_master("WARN: Using deprecated XOR password retrieval, migrate to Kyber", "WARN")
    obf = read_file(file_path)
    if obf == null then return null
    return xor_obfuscate(obf, key)
end function

set_permissions = function(path, perms)
    // GreyScript has no native chmod, but we can use shell run
    get_shell.run("chmod " + perms + " " + path)
end function

// Simple BUFFER system inspired by 5hell's malp
globals.BUFFER = []

buffer_push = function(obj)
    globals.BUFFER.push(obj)
    return globals.BUFFER.len - 1  // Return index
end function

buffer_get = function(index)
    if globals.BUFFER.hasIndex(index) then
        return globals.BUFFER[index]
    end if
    return null
end function

buffer_list = function()
    result = "BUFFER contents (" + globals.BUFFER.len + " items):\n"
    for i in range(0, globals.BUFFER.len - 1)
        obj = globals.BUFFER[i]
        obj_type = typeof(obj)
        if obj_type == "shell" then
            result = result + "[" + i + "] shell -> " + obj.host_computer.public_ip + "\n"
        else if obj_type == "file" then
            result = result + "[" + i + "] file -> " + obj.path + "\n"
        else
            result = result + "[" + i + "] " + obj_type + "\n"
        end if
    end for
    return result
end function

buffer_clear = function()
    globals.BUFFER = []
    log_master("BUFFER cleared", "INFO")
end function

buffer_size = function()
    return globals.BUFFER.len
end function

// Safe file helpers for better resource management
safe_file_read = function(path)
    f = get_shell.host_computer.File(path)
    if f == null then return null
    content = f.get_content
    return content
end function

safe_file_write = function(path, content)
    f = get_shell.host_computer.File(path)
    if f == null then
        // Create if doesn't exist
        parts = path.split("/")
        name = parts.pop
        dir = parts.join("/")
        if dir == "" then dir = "/"
        get_shell.host_computer.touch(dir, name)
        f = get_shell.host_computer.File(path)
        if f == null then return false
    end if
    f.set_content(content)
    return true
end function

// Network retry wrapper for transient failures
retry_network = function(func, max_attempts, base_delay)
    if max_attempts == null then max_attempts = 3
    if base_delay == null then base_delay = 1
    
    for attempt in range(0, max_attempts - 1)
        result = func()
        if result != null then return result
        
        if attempt < max_attempts - 1 then
            delay = base_delay * (2 ^ attempt)
            if delay > 30 then delay = 30
            wait(delay)
        end if
    end for
    
    return null
end function
