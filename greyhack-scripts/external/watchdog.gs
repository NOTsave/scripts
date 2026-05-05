//#######################################################
// Aka_B0B (https://github.com/AkaBobur/watchdog)       #
// Don't forget to credit the author if you use it.     #
// It is a part of Super Script tool                    #
// @Features:                                           #
// Full system file indexing(total_sizes.ini)            #
// Autowipe sensitive files(passwd, Bank.txt, Mail.txt) #
// Process monitoring                                   #
// Custom Watch files+auto deletion(watchdog.conf)      #
// Custom Watch process+auto kill(watchdog.conf)        #
// Whitelist files/folders protection(watchdog.conf)    #
// Configurable trash cleaning(watchdog.conf)           #
// Monitor logging(monitor.log)                         #
//#######################################################

version = "1.5"
config_dir = "/root/watchdog_config"
config_file_path = config_dir + "/watchdog.conf"
log_file_path = "/root/watchdog_config/monitor.log"
previous_processes = {}

normalize_path = function(p)
    // Remove trailing slashes and resolve /./ /../
    while p[-1] == "/"
        p = p[:-1]
    end while
    return p
end function

is_path_monitored = function(path)
    // Reject path traversal attempts
    if path.indexOf("..") != null then
        return false
    end if
    // Only allow deletion under /home, /root, /var – never /bin, /lib, /etc
    forbidden = ["/bin", "/lib", "/etc", "/boot", "/dev"]
    normalized_path = normalize_path(path)
    for prefix in forbidden
        if normalized_path.indexOf(prefix + "/") == 0 or normalized_path == prefix then
            return false
        end if
    end for
    return true
end function

monitor_folder_check = function()
    shell = get_shell
    comp = shell.host_computer
    config_folder = comp.File(config_dir)
    if not config_folder then
        if not globals.config_dir_missing_warning_shown then
            message = "[!] Warning: watchdog_config directory deleted"
            print("<color=red>" + message + "</color>")
            globals.config_dir_missing_warning_shown = true
        end if
        comp.create_folder("/root", "watchdog_config")
        print("<color=green>[*] watchdog_config directory recreated</color>")
        migrate_old_configs()
        comp.touch("/root/watchdog_config", "monitor.log")
        print("<color=green>[*] All config files recreated</color>")
        globals.config_dir_missing_warning_shown = false
        globals.config_file_missing_warning_shown = false
        globals.monitor_log_missing_warning_shown = false
        globals.clean_trash_disabled_notice_shown = false
        sizes_file_path = config_dir + "/total_sizes.ini"
        comp.touch(config_dir, "total_sizes.ini")
        sizes_config_file = comp.File(sizes_file_path)
        if sizes_config_file then index_file_system(sizes_config_file)
    else
        globals.config_dir_missing_warning_shown = false
    end if
end function

load_config = function()
    shell = get_shell
    comp = shell.host_computer
    config = {}
    config.watch_procs = []
    config.watch_files = []
    config.whitelist_files = []
    config.whitelist_folders = []
    config.clean_trash = true
    config_file = comp.File(config_file_path)
    if not config_file or config_file.get_content == "" then return config
    content = config_file.get_content
    lines = content.split(char(10))
    current_section = ""
    for line in lines
        line = line.trim
        if line == "" then continue
        if line.len >= 2 and line[0] == "[" and line[-1] == "]" then
            current_section = line[1:-1].lower
            continue
        end if
        if line.len > 0 and line[0] == "#" then continue
        if current_section == "" then
            if line.indexOf("=") != null then
                parts = line.split("=")
                if parts.len >= 2 then
                    key = parts[0].trim
                    value = parts[1].trim
                    if key == "clean_trash" then config.clean_trash = (value.lower == "true")
                end if
                continue
            end if
        end if
        if current_section == "watch_procs" then
            config.watch_procs.push(line)
        else if current_section == "watch_files" then
            config.watch_files.push(line)
        else if current_section == "whitelist_files" then
            config.whitelist_files.push(line)
        else if current_section == "whitelist_folders" then
            config.whitelist_folders.push(line)
        end if
    end for
    
    // Check for randomized names override
    random_names_file = comp.File("/root/watchdog_config/random_names.dat")
    if random_names_file then
        random_data = random_names_file.get_content
        if random_data then
            parts = random_data.split("|")
            if parts.len >= 1 then
                proc_names = parts[0].split(",")
                config.watch_procs = proc_names
            end if
            if parts.len >= 2 then
                file_names = parts[1].split(",")
                config.watch_files = []
                for name in file_names
                    config.watch_files.push(name + ".tmp")
                end for
            end if
        end if
    end if
    
    return config
end function

migrate_old_configs = function()
    shell = get_shell
    comp = shell.host_computer
    config_content = []
    config_content.push("# Watchdog Configuration File")
    config_content.push("clean_trash = true")
    config_content.push("")
    config_content.push("[watch_procs]")
    config_content.push("viper")
    config_content.push("x")
    config_content.push("jumpfile")
    config_content.push("dsession")
    config_content.push("rshell")
    config_content.push("ps")
    config_content.push("rshell_client")
    config_content.push("doom")
    config_content.push("")
    config_content.push("[watch_files]")
    config_content.push("jumpfile.src")
    config_content.push("jumpfile")
    config_content.push("unity")
    config_content.push("dcall")
    config_content.push("viper")
    config_content.push("")
    config_content.push("[whitelist_files]")
    config_content.push("/root/watchdog_config/watchdog.conf")
    config_content.push("/root/watchdog_config/total_sizes.ini")
    config_content.push("/root/watchdog_config/monitor.log")
    config_content.push("")
    config_content.push("[whitelist_folders]")
    config_content.push("/root/watchdog_config")
    config_content.push("/lib")
    config_content.push("/bin")
    config_content.push("")
    comp.touch("/root/watchdog_config", "watchdog.conf")
    config_file = comp.File(config_file_path)
    config_file.set_content(config_content.join(char(10)))
    print("<color=white>{+} Created default watchdog.conf</color>")
    old_watch_files = comp.File("/root/watchdog_config/watch_files.txt")
    if old_watch_files then old_watch_files.delete
    old_watch_procs = comp.File("/root/watchdog_config/watch_procs.txt")
    if old_watch_procs then old_watch_procs.delete
    print("<color=white>{+} Migrated to new config format</color>")
end function

init = function()
    shell = get_shell
    comp = shell.host_computer
    globals.config_dir_missing_warning_shown = false
    globals.config_file_missing_warning_shown = false
    globals.monitor_log_missing_warning_shown = false
    globals.clean_trash_disabled_notice_shown = false
    globals.clean_trash_enabled_notice_shown = false
    monitor_folder_check()
    if not comp.File(config_file_path) then
        old_files_exist = comp.File("/root/watchdog_config/watch_files.txt") or comp.File("/root/watchdog_config/watch_procs.txt")
        if old_files_exist then
            print("<color=white>{+} Migrating old config files to new format...</color>")
            migrate_old_configs()
        else
            migrate_old_configs()
        end if
    end if
    if not comp.File(log_file_path) then
        comp.touch("/root/watchdog_config", "monitor.log")
        print("<color=white>{+} Created monitor.log file</color>")
    end if
    globals.previous_processes = get_current_process_map()
    globals.last_system_log_state = null
    print("<color=white>[*] System initialized successfully</color>")
end function

log_message = function(message)
    shell = get_shell
    comp = shell.host_computer
    monitor_folder_check()
    log_file = comp.File(log_file_path)
    if not log_file then
        if not globals.monitor_log_missing_warning_shown then
            print("<color=red>[!] Warning: monitor.log deleted</color>")
            globals.monitor_log_missing_warning_shown = true
        end if
        comp.touch("/root/watchdog_config", "monitor.log")
        recreated_file = comp.File(log_file_path)
        if recreated_file then
            print("<color=green>[*] monitor.log recreated</color>")
            globals.monitor_log_missing_warning_shown = false
            log_file = recreated_file
        else
            print("<color=red>[!] Failed to recreate monitor.log</color>")
            return
        end if
    else
        globals.monitor_log_missing_warning_shown = false
    end if
    timestamp = current_date
    log_file.set_content(log_file.get_content + "[" + timestamp + "] " + message + char(10))
end function

get_current_process_map = function()
    comp = get_shell.host_computer
    ps = comp.show_procs.split(char(10))
    process_map = {}
    for each in ps[1:]
        if each == "" then continue
        parts = each.split(" ")
        if parts.len < 2 then continue
        pid = parts[1]
        process_map[pid] = each
    end for
    return process_map
end function

monitor_all_processes = function()
    shell = get_shell
    comp = shell.host_computer
    config_file = comp.File(config_file_path)
    if not config_file then
        if not globals.config_file_missing_warning_shown then
            message = "[!] Warning: watchdog.conf deleted"
            print("<color=red>" + message + "</color>")
            log_message(message)
            globals.config_file_missing_warning_shown = true
        end if
        migrate_old_configs()
        print("<color=green>[*] watchdog.conf recreated</color>")
        log_message("watchdog.conf recreated")
        globals.config_file_missing_warning_shown = false
        config_file = comp.File(config_file_path)
    else
        globals.config_file_missing_warning_shown = false
    end if
    config = load_config()
    current_processes = get_current_process_map()
    for pid in current_processes.indexes
        if not globals.previous_processes.hasIndex(pid) then
            process_info = current_processes[pid].split(" ")
            if process_info.len >= 2 then
                pname = process_info[-1]
                user = process_info[0]
                message = "[!] PROCESS STARTED: " + pname + " (PID: " + pid + ", User: " + user + ")"
                print("<color=red>" + message + "</color>")
                log_message(message)
            end if
        end if
    end for
    for pid in globals.previous_processes.indexes
        if not current_processes.hasIndex(pid) then
            process_info = globals.previous_processes[pid].split(" ")
            if process_info.len >= 2 then
                pname = process_info[-1]
                user = process_info[0]
                message = "[x] PROCESS ENDED: " + pname + " (PID: " + pid + ", User: " + user + ")"
                print("<color=green>" + message + "</color>")
                log_message(message)
            end if
        end if
    end for
    watch_procs = config.watch_procs
    if not watch_procs then watch_procs = []
    for each in comp.show_procs.split(char(10))[1:]
        if each == "" then continue
        parts = each.split(" ")
        if parts.len < 2 then continue
        pid = parts[1]
        if parts.len > 1 then pname = parts[-1]
        if watch_procs.indexOf(pname) != null then
            // Get process owner
            owner = parts[0]
            current_user = active_user
            if current_user == null then current_user = "root"
            if owner != current_user and owner != "root" then
                log_message("Refused to kill process " + pname + " owned by " + owner)
                print("<color=orange>[!] Refused to kill process " + pname + " owned by " + owner + "</color>")
            else
                message = "[!] WATCHED PROCESS DETECTED: " + pname + " (PID: " + pid + ", Owner: " + owner + ")"
                print("<color=yellow>" + message + "</color>")
                log_message(message)
                comp.close_program(pid.to_int)
                print("<color=yellow><b>[+] Terminated process: " + pname + " with ID: " + pid + "</b></color>")
            end if
        end if
    end for
    globals.previous_processes = current_processes
end function

index_file_system = function(config_file)
    comp = get_shell.host_computer
    file_map = get_current_file_state()
    new_content = ""
    for path in file_map.indexes
        new_content = new_content + path + " " + file_map[path] + char(10)
    end for
    config_file.set_content(new_content)
    print("<color=white>[+] File system indexed for monitoring</color>")
    print("<color=white>[i] Indexed </color><color=#FF00AAff>" + file_map.len + "</color><color=white> files</color>")
end function

get_current_file_state = function()
    comp = get_shell.host_computer
    root = comp.File("/")
    file_map = {}
    files_to_check = [root]
    while files_to_check.len > 0
        if files_to_check.len > 100000 then exit("Too many files")
        current = files_to_check.pop
        if current and current.is_folder then
            subdirs = current.get_folders
            if subdirs then
                for subdir in subdirs
                    files_to_check.push(subdir)
                end for
            end if
            files = current.get_files
            if files then
                for file in files
                    file_map[file.path] = file.size
                end for
            end if
        else if current and not current.is_folder then
            file_map[current.path] = current.size
        end if
    end while
    return file_map
end function

wipe_sensitive_files = function()
    comp = get_shell.host_computer
    sensitive_files = ["/root/Config/Bank.txt", "/root/Config/Mail.txt", "/etc/passwd"]
    home_path = comp.File("/home")
    if home_path and home_path.is_folder then
        home_folders = home_path.get_folders
        if home_folders == null then home_folders = []
        for user_folder in home_folders
            if user_folder.name != "guest" then
                sensitive_files.push("/home/" + user_folder.name + "/Config/Bank.txt")
                sensitive_files.push("/home/" + user_folder.name + "/Config/Mail.txt")
            end if
        end for
    end if
    for file_path in sensitive_files
        file = comp.File(file_path)
        if file and file.get_content != "" and file.is_binary == 0 then
            file.delete
            message = "[!] Wiped sensitive file: " + file_path
            print("<color=#ffee00ff>" + message + "</color>")
            log_message(message)
        end if
    end for
end function

find_files_by_name = function(root_dir, file_names, whitelist_files, whitelist_folders)
    comp = get_shell.host_computer
    found_files = []
    files_to_check = [root_dir]
    while files_to_check.len > 0
        current = files_to_check.pop
        if current and current.is_folder then
            skip_folder = false
            current_path = normalize_path(current.path)
            for whitelist_path in whitelist_folders
                normalized_whitelist = normalize_path(whitelist_path)
                if current_path == normalized_whitelist or current_path.indexOf(normalized_whitelist + "/") == 0 then
                    skip_folder = true
                    break
                end if
            end for
            if skip_folder then continue
            subdirs = current.get_folders
            if subdirs then
                for subdir in subdirs
                    files_to_check.push(subdir)
                end for
            end if
            files = current.get_files
            if files then
                for file in files
                    skip_file = false
                    for whitelist_path in whitelist_files
                        if file.path == whitelist_path then
                            skip_file = true
                            break
                        end if
                    end for
                    if skip_file then continue
                    if file_names.indexOf(file.name) != null then found_files.push(file)
                end for
            end if
        else if current and not current.is_folder then
            skip_file = false
            for whitelist_path in whitelist_files
                if current.path == whitelist_path then
                    skip_file = true
                    break
                end if
            end for
            if skip_file then continue
            if file_names.indexOf(current.name) != null then found_files.push(current)
        end if
    end while
    return found_files
end function

monitor_files_and_system = function()
    shell = get_shell
    comp = shell.host_computer
    config_file = comp.File(config_file_path)
    if not config_file then
        if not globals.config_file_missing_warning_shown then
            message = "[!] Warning: watchdog.conf deleted"
            print("<color=red>" + message + "</color>")
            log_message(message)
            globals.config_file_missing_warning_shown = true
        end if
        migrate_old_configs()
        print("<color=green>[*] watchdog.conf recreated</color>")
        log_message("watchdog.conf recreated")
        globals.config_file_missing_warning_shown = false
        config_file = comp.File(config_file_path)
    else
        globals.config_file_missing_warning_shown = false
    end if
    config = load_config()
    watch_files = config.watch_files
    whitelist_files = config.whitelist_files
    whitelist_folders = config.whitelist_folders
    if not watch_files then watch_files = []
    file_sizes_config = config_dir + "/total_sizes.ini"
    sizes_config_file = comp.File(file_sizes_config)
    if not sizes_config_file then
        comp.touch(config_dir, "total_sizes.ini")
        sizes_config_file = comp.File(file_sizes_config)
        sizes_config_file.set_content("")
        print("<color=white>[*] Initializing file system monitor...</color>")
        index_file_system(sizes_config_file)
        return
    end if
    stored_content = sizes_config_file.get_content
    if stored_content == null then stored_content = ""
    stored_files = stored_content.split(char(10))
    stored_map = {}
    for line in stored_files
        if line == "" then continue
        parts = line.split(" ")
        if parts.len < 2 then continue
        stored_map[parts[0]] = parts[1]
    end for
    current_map = get_current_file_state()
    root_dir = comp.File("/")
    watched_files_found = find_files_by_name(root_dir, watch_files, whitelist_files, whitelist_folders)
    files_deleted_count = 0
    for file in watched_files_found
        if not is_path_monitored(file.path) then
            log_message("Skipped deletion of non-monitored file: " + file.path)
            continue
        end if
        message = "[!] SUSPICIOUS FILE DETECTED: " + file.path
        print("<color=red>" + message + "</color>")
        log_message(message)
        file.delete
        files_deleted_count = files_deleted_count + 1
        print("<color=yellow>[x] Deleted file: " + file.path + "</color>")
        log_message("Deleted file: " + file.path)
        current_map.remove(file.path)
        if stored_map.hasIndex(file.path) then stored_map.remove(file.path)
    end for
    for path in current_map.indexes
        skip_file = false
        normalized_path = normalize_path(path)
        for whitelist_path in whitelist_files
            if normalized_path == normalize_path(whitelist_path) then skip_file = true; break
        end for
        if skip_file then continue
        skip_folder = false
        for whitelist_path in whitelist_folders
            normalized_whitelist = normalize_path(whitelist_path)
            if normalized_path.indexOf(normalized_whitelist + "/") == 0 then skip_folder = true; break
        end for
        if skip_folder then continue
        if not stored_map.hasIndex(path) then
            message = "[+] NEW FILE: " + path + " (Size: " + current_map[path] + ")"
            print("<color=#FF00AAff>" + message + "</color>")
            log_message(message)
        else if stored_map[path] != current_map[path] then
            message = "[!] FILE CHANGED: " + path + " (Size: " + stored_map[path] + " → " + current_map[path] + ")"
            print("<color=orange>" + message + "</color>")
            log_message(message)
        end if
    end for
    for path in stored_map.indexes
        skip_file = false
        normalized_path = normalize_path(path)
        for whitelist_path in whitelist_files
            if normalized_path == normalize_path(whitelist_path) then skip_file = true; break
        end for
        if skip_file then continue
        skip_folder = false
        for whitelist_path in whitelist_folders
            normalized_whitelist = normalize_path(whitelist_path)
            if normalized_path.indexOf(normalized_whitelist + "/") == 0 then skip_folder = true; break
        end for
        if skip_folder then continue
        if not current_map.hasIndex(path) then
            message = "[!] FILE DELETED: " + path
            print("<color=red>" + message + "</color>")
            log_message(message)
        end if
    end for
    new_content = ""
    for path in current_map.indexes
        new_content = new_content + path + " " + current_map[path] + char(10)
    end for
    sizes_config_file.set_content(new_content)
end function

monitor_system_log = function()
    shell = get_shell
    comp = shell.host_computer
    system_log = comp.File("/var/system.log")
    if not system_log then
        if not globals.last_system_log_state or globals.last_system_log_state != "missing" then
            message = "[!] WARNING: System.log file missing"
            print("<color=red>" + message + "</color>")
            log_message(message)
            globals.last_system_log_state = "missing"
        end if
        return
    end if
    is_binary_result = system_log.is_binary
    if is_binary_result == null then
        if not globals.last_system_log_state or globals.last_system_log_state != "deleted" then
            message = "[!] WARNING: System.log file deleted during check"
            print("<color=red>" + message + "</color>")
            log_message(message)
            globals.last_system_log_state = "deleted"
        end if
    else if is_binary_result == 0 then
        if not globals.last_system_log_state or globals.last_system_log_state != "corrupted" then
            message = "[!] WARNING: System.log corrupted (not binary)"
            print("<color=red>" + message + "</color>")
            log_message(message)
            globals.last_system_log_state = "corrupted"
        end if
    else
        if globals.last_system_log_state and globals.last_system_log_state != "normal" then
            message = "[+] System.log restored to normal state"
            print("<color=green>" + message + "</color>")
            log_message(message)
        end if
        globals.last_system_log_state = "normal"
    end if
end function

clean_trash_folders = function()
    shell = get_shell
    comp = shell.host_computer
    config = load_config()
    if not config.clean_trash then
        if not globals.clean_trash_disabled_notice_shown then
            print("<color=#888888>[i] Trash cleaning disabled in config (clean_trash = false)</color>")
            globals.clean_trash_disabled_notice_shown = true
        end if
        return
    end if
    if not globals.clean_trash_enabled_notice_shown then
        print("<color=#888888>[i] Trash cleaning enabled in config (clean_trash = true)</color>")
        globals.clean_trash_enabled_notice_shown = true
    end if
    globals.clean_trash_disabled_notice_shown = false
    users = ["root"]
    home_folder = comp.File("/home")
    if home_folder and home_folder.is_folder then
        home_folders = home_folder.get_folders
        if home_folders == null then home_folders = []
        for user_folder in home_folders
            users.push(user_folder.name)
        end for
    end if
    trash_cleaned_count = 0
    for user in users
        if user == "root" then
            trash_path = "/root/.Trash"
        else
            trash_path = "/home/" + user + "/.Trash"
        end if
        trash_folder = comp.File(trash_path)
        if trash_folder and trash_folder.is_folder then
            trash_folder.delete
            message = "[+] Cleaned .Trash folder for user: " + user
            print("<color=#00FF00>" + message + "</color>")
            log_message(message)
            trash_cleaned_count = trash_cleaned_count + 1
        end if
    end for
    if trash_cleaned_count > 0 then
        print("<color=white>[i] Cleaned " + trash_cleaned_count + " .Trash folders</color>")
    end if
end function

main = function()
    print("<color=white><b>:::Super Integrated System Monitoring Tool:::<b></color>")
    print("<color=yellow>[i] By <color=orange>AkaB0B</color>, version: </color>" + "<color=red>" + version + "</color>")
    print("<color=orange>[*] Press Ctrl+C to stop monitoring</color>")
    init()
    config = load_config()
    if config.clean_trash then
        trash_status = "ENABLED"
        trash_color = "#00FF00"
    else
        trash_status = "DISABLED"
        trash_color = "#FF0000"
    end if
    print("<color=" + trash_color + ">[+] Trash cleaning: " + trash_status + "</color>")
    print("<color=white>[+] Watch processes: " + config.watch_procs.len + " items</color>")
    print("<color=white>[+] Watch files: " + config.watch_files.len + " items</color>")
    print("<color=white>[+] Whitelist files: " + config.whitelist_files.len + " items</color>")
    print("<color=white>[+] Whitelist folders: " + config.whitelist_folders.len + " items</color>")
    print("<color=white>[+] Config file: " + config_file_path + "</color>")
    print("<color=white>[+] Log file: " + log_file_path + "</color>")
    log_message("<color=green>::: Monitoring started :::</color>")
    log_message("Trash cleaning: " + trash_status)
    while true
        if comp.File("/tmp/stop_watchdog") then exit()
        monitor_folder_check()
        monitor_all_processes()
        monitor_files_and_system()
        monitor_system_log()
        wipe_sensitive_files()
        clean_trash_folders()
    end while
end function

main()
