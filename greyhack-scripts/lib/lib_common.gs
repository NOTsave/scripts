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
    result = ""
    for i in range(0, data.len-1)
        result = result + char(data[i].code ^ key[i % key.len].code)
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

store_password = function(file_path, password, key="botnet_key_2026")
    obf = xor_obfuscate(password, key)
    write_file(file_path, obf)
end function

retrieve_password = function(file_path, key="botnet_key_2026")
    obf = read_file(file_path)
    if obf == null then return null
    return xor_obfuscate(obf, key)
end function

set_permissions = function(path, perms)
    // GreyScript has no native chmod, but we can use shell run
    get_shell.run("chmod " + perms + " " + path)
end function
