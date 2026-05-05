// watchdog_randomizer.gs - Randomize watchdog config values
// Inspired by 5hell's makfit approach of randomizing filenames
import_code("/lib/lib_common.gs")

WATCHDOG_CONFIG = "/root/watchdog_config/watchdog.conf"
RANDOM_NAMES_FILE = "/root/watchdog_config/random_names.dat"

// Generate process names that blend in with system processes
generate_decoy_names = function(count)
    // System-like prefixes that look legitimate
    prefixes = ["systemd-", "kworker/", "rcu_", "kthread-", "watchdog/", 
                "cron-", "dbus-", "polkit-", "netlink-", "irq_"]
    suffixes = ["logind", "resolved", "timesyncd", "networkd", "journald",
                "udevd", "tmpfiles", "sysusers", "random", "init"]
    
    names = []
    for i in range(0, count - 1)
        prefix = prefixes[floor(rnd * prefixes.len)]
        suffix = suffixes[floor(rnd * suffixes.len)]
        name = prefix + suffix
        names.push(name)
    end for
    return names
end function

// Rotate watchdog names on a schedule
rotate_watchdog_names = function()
    // Generate new names
    proc_names = generate_decoy_names(3)  // 3 monitored names
    file_names = generate_decoy_names(2)  // 2 monitored files
    
    // Read current config
    config_file = get_shell.host_computer.File(WATCHDOG_CONFIG)
    if not config_file then return false
    
    content = config_file.get_content
    if content == null then return false
    
    lines = content.split(char(10))
    new_lines = []
    in_procs = false
    in_files = false
    
    for line in lines
        if line == "[watch_procs]" then
            in_procs = true
            in_files = false
        else if line == "[watch_files]" then
            in_procs = false
            in_files = true
        else if line.len > 0 and line[0] == "[" then
            in_procs = false
            in_files = false
        end if
        
        if in_procs and line.trim != "" and line[0] != "[" then
            // Skip old entries, we'll add new ones
            continue
        end if
        if in_files and line.trim != "" and line[0] != "[" then
            continue
        end if
        new_lines.push(line)
    end for
    
    // Rebuild config with randomized names
    final_config = []
    for line in new_lines
        final_config.push(line)
        if line == "[watch_procs]" then
            for name in proc_names
                final_config.push(name)
            end for
        end if
        if line == "[watch_files]" then
            for name in file_names
                final_config.push(name + ".tmp")
            end for
        end if
    end for
    
    // Save
    config_file.set_content(final_config.join(char(10)))
    
    // Store current names for slave process renaming
    write_file(RANDOM_NAMES_FILE, proc_names.join(",") + "|" + file_names.join(","))
    
    log_master("Watchdog names rotated: " + proc_names.join(", "), "INFO")
    return true
end function

// Initialize with random names on first run
init_randomizer = function()
    config_file = get_shell.host_computer.File(WATCHDOG_CONFIG)
    if not config_file then return false
    
    content = config_file.get_content
    if content.indexOf("viper") != null then
        // Default config detected, randomize
        rotate_watchdog_names()
        log_master("Initial watchdog name randomization complete", "SUCCESS")
    end if
end function

// Run once at load
init_randomizer()
