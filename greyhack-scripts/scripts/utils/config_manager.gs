// config_manager.gs - Encrypted configuration management system
// Stores all botnet settings in encrypted config file

import_code("/lib/kyber_lib.gs")
import_code("/lib/lib_common.gs")

// ============================================
// Configuration File Path
// ============================================

CONFIG_FILE = "/root/.botnet/config.enc"
CONFIG_BACKUP = "/root/.botnet/config.enc.bak"

// ============================================
// Default Configuration
// ============================================

DEFAULT_CONFIG = {
    // General settings
    "general": {
        "max_depth": "5",
        "log_retention": "30days",
        "version": "1.0",
        "debug": "false"
    },
    
    // Exploitation settings
    "exploitation": {
        "ports": "22,80,443,8080,1542",
        "timeout": "30",
        "max_attempts": "2",
        "backoff_base": "1",
        "backoff_max": "5"
    },
    
    // C2 settings
    "c2": {
        "heartbeat_interval": "300",
        "response_timeout": "600",
        "max_retries": "3",
        "retry_delay": "2"
    },
    
    // Forensics settings
    "forensics": {
        "wipe_logs": "true",
        "kill_competitors": "true",
        "watchdog_interval": "300",
        "file_integrity": "true"
    },
    
    // Network settings
    "network": {
        "scan_interval": "60",
        "propagation_delay": "30",
        "max_concurrent_exploits": "5"
    }
}

// ============================================
// Configuration Encryption
// ============================================

encrypt_config = function(config_data)
    // Serialize config to string
    config_str = serialize_config(config_data)
    
    // Get encryption key
    keys = get_c2_keypair()
    if keys == null then return null
    
    // Encrypt with master public key
    master_pub = get_master_pubkey()
    if master_pub == null then return null
    
    cipher = Kyber.encrypt_message(master_pub, config_str)
    if cipher == null then
        log_master("ERROR: Failed to encrypt configuration", "ERROR")
        return null
    end if
    
    return cipher
end function

decrypt_config = function(cipher)
    if cipher == null then return null
    
    // Get decryption key
    keys = get_c2_keypair()
    if keys == null then return null
    
    // Decrypt
    config_str = Kyber.decrypt_message(keys.private, cipher)
    if config_str == null then
        log_master("ERROR: Failed to decrypt configuration", "ERROR")
        return null
    end if
    
    // Parse config
    return parse_config(config_str)
end function

// ============================================
// Configuration Serialization
// ============================================

serialize_config = function(config_data)
    lines = []
    
    for section in config_data.keys
        lines.push("[" + section + "]")
        section_data = config_data[section]
        
        if typeof(section_data) == "map" then
            for key in section_data.keys
                value = section_data[key]
                lines.push(key + "=" + value)
            end for
        end if
        
        lines.push("")  // Empty line between sections
    end for
    
    return lines.join(char(10))
end function

parse_config = function(config_str)
    if config_str == null or config_str == "" then return DEFAULT_CONFIG
    
    config = {}
    current_section = null
    
    lines = config_str.split(char(10))
    for line in lines
        line = line.trim
        if line == "" then continue
        
        // Section header
        if line.len >= 2 and line[0] == "[" and line[-1] == "]" then
            current_section = line[1:-1].lower
            config[current_section] = {}
            continue
        end if
        
        // Key=value pair
        if current_section != null then
            parts = line.split("=")
            if parts.len >= 2 then
                key = parts[0].trim
                value = parts[1].trim
                config[current_section][key] = value
            end if
        end if
    end for
    
    return config
end function

// ============================================
// Configuration Management
// ============================================

load_config = function()
    comp = get_shell.host_computer
    
    // Try to load existing config
    cipher = safe_file_read(CONFIG_FILE)
    if cipher != null then
        config = decrypt_config(cipher)
        if config != null then
            log_master("Loaded configuration from " + CONFIG_FILE, "INFO")
            return config
        end if
    end if
    
    // Create default config
    log_master("Creating default configuration", "INFO")
    if save_config(DEFAULT_CONFIG) then
        return DEFAULT_CONFIG
    end if
    
    return null
end function

save_config = function(config)
    if config == null then return false
    
    // Backup existing config
    comp = get_shell.host_computer
    existing = comp.File(CONFIG_FILE)
    if existing != null then
        existing.copy(CONFIG_BACKUP)
    end if
    
    // Encrypt and save
    cipher = encrypt_config(config)
    if cipher == null then return false
    
    if safe_file_write(CONFIG_FILE, cipher) then
        set_permissions(CONFIG_FILE, "600")
        log_master("Saved configuration to " + CONFIG_FILE, "INFO")
        return true
    end if
    
    return false
end function

// ============================================
// Configuration Access
// ============================================

get_config_value = function(section, key, default_value=null)
    config = load_config()
    if config == null then return default_value
    
    if not config.hasIndex(section) then return default_value
    if not config[section].hasIndex(key) then return default_value
    
    return config[section][key]
end function

set_config_value = function(section, key, value)
    config = load_config()
    if config == null then return false
    
    if not config.hasIndex(section) then
        config[section] = {}
    end if
    
    config[section][key] = str(value)
    return save_config(config)
end function

get_section = function(section)
    config = load_config()
    if config == null then return {}
    
    if config.hasIndex(section) then
        return config[section]
    end if
    
    return {}
end function

// ============================================
// Configuration Validation
// ============================================

validate_config = function(config)
    if config == null then return false
    
    // Validate required sections
    required_sections = ["general", "exploitation", "c2", "forensics"]
    for section in required_sections
        if not config.hasIndex(section) then
            log_master("ERROR: Missing required section: " + section, "ERROR")
            return false
        end if
    end for
    
    // Validate key types and ranges
    general = config["general"]
    if general.hasIndex("max_depth") then
        depth = general["max_depth"].to_int
        if typeof(depth) != "number" or depth < 1 or depth > 10 then
            log_master("ERROR: Invalid max_depth value", "ERROR")
            return false
        end if
    end if
    
    exploitation = config["exploitation"]
    if exploitation.hasIndex("timeout") then
        timeout = exploitation["timeout"].to_int
        if typeof(timeout) != "number" or timeout < 5 or timeout > 300 then
            log_master("ERROR: Invalid timeout value", "ERROR")
            return false
        end if
    end if
    
    c2 = config["c2"]
    if c2.hasIndex("heartbeat_interval") then
        interval = c2["heartbeat_interval"].to_int
        if typeof(interval) != "number" or interval < 60 or interval > 3600 then
            log_master("ERROR: Invalid heartbeat_interval value", "ERROR")
            return false
        end if
    end if
    
    return true
end function

// ============================================
// Configuration Migration
// ============================================

migrate_config = function()
    // Handle configuration version upgrades
    config = load_config()
    if config == null then return false
    
    general = config["general"]
    if general == null then
        config["general"] = {}
        general = config["general"]
    end if
    
    // Add version if missing
    if not general.hasIndex("version") then
        general["version"] = "1.0"
    end if
    
    // Add debug flag if missing
    if not general.hasIndex("debug") then
        general["debug"] = "false"
    end if
    
    // Save migrated config
    return save_config(config)
end function

// ============================================
// Configuration Utilities
// ============================================

reset_config = function()
    log_master("Resetting configuration to defaults", "WARN")
    return save_config(DEFAULT_CONFIG)
end function

backup_config = function()
    config = load_config()
    if config == null then return false
    
    timestamp = str(time)
    backup_file = "/root/.botnet/config.backup." + timestamp + ".enc"
    
    cipher = encrypt_config(config)
    if cipher != null then
        if safe_file_write(backup_file, cipher) then
            log_master("Created configuration backup: " + backup_file, "INFO")
            return true
        end if
    end if
    
    return false
end function

restore_config = function(backup_file)
    cipher = safe_file_read(backup_file)
    if cipher == null then
        log_master("ERROR: Backup file not found: " + backup_file, "ERROR")
        return false
    end if
    
    config = decrypt_config(cipher)
    if config == null then
        log_master("ERROR: Failed to decrypt backup", "ERROR")
        return false
    end if
    
    if validate_config(config) then
        if save_config(config) then
            log_master("Restored configuration from backup", "INFO")
            return true
        end if
    end if
    
    return false
end function

print_config = function()
    config = load_config()
    if config == null then return
    
    print("=== Botnet Configuration ===")
    for section in config.keys
        print("[" + section + "]")
        section_data = config[section]
        
        if typeof(section_data) == "map" then
            for key in section_data.keys
                value = section_data[key]
                print("  " + key + " = " + value)
            end for
        end if
        print("")
    end for
end function
