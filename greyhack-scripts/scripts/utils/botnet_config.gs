// ============================================
// Botnet Configuration Management
// Centralizes all paths and settings
// ============================================

// Default configuration values
DEFAULT_CONFIG = {
    "paths": {
        "botnet_root": "/root/.botnet",
        "bin_dir": "/bin",
        "lib_dir": "/lib",
        "scripts_dir": "/scripts",
        "utils_dir": "/scripts/utils",
        "tools_dir": "/scripts/tools",
        "data_dir": "/data",
        "tmp_dir": "/tmp"
    },
    "files": {
        "master_priv": "/root/.botnet/master.priv",
        "master_pub": "/root/.botnet/master.pub",
        "slave_priv": "/root/.botnet/slave.priv",
        "slave_pub": "/root/.botnet/slave.pub",
        "infected_file": "/root/.botnet/infected.txt",
        "depth_markers_dir": "/root/.botnet/depth_markers",
        "config_file": "/root/.botnet/config.enc"
    },
    "security": {
        "hard_depth_cap": 5,
        "default_max_depth": 3,
        "allowed_prefixes": [
            "/root/.botnet/",
            "/scripts/utils/",
            "/bin/",
            "/tmp/"
        ],
        "allowed_scripts": [
            "/bin/slave.gs",
            "/bin/worm.gs",
            "/scripts/utils/forensics/wipe_logs.gs",
            "/scripts/utils/file_search.gs",
            "/scripts/utils/find_lib.gs",
            "/scripts/utils/accessLevel.gs"
        ]
    },
    "network": {
        "default_ssh_port": 22,
        "default_user": "root",
        "max_retries": 3,
        "base_delay": 1,
        "spread_delay": 30
    },
    "ui": {
        "max_command_length": 1000,
        "help_enabled": true,
        "verbose_errors": true
    }
}

// Runtime configuration (loaded from file or defaults)
CONFIG = null

// Load configuration from encrypted file or use defaults
load_botnet_config = function()
    if CONFIG != null then return CONFIG
    
    config_file = DEFAULT_CONFIG.files.config_file
    if config_file == null then return DEFAULT_CONFIG
    
    // Try to load encrypted config
    import_code("/scripts/utils/config_manager.gs")
    if typeof(globals.load_config) == "function" then
        loaded = globals.load_config(config_file)
        if loaded != null then
            CONFIG = loaded
            return CONFIG
        end if
    end if
    
    // Fallback to defaults
    CONFIG = DEFAULT_CONFIG
    return CONFIG
end function

// Get configuration value by path (e.g., "paths.botnet_root")
get_config = function(path)
    if CONFIG == null then load_botnet_config()
    
    parts = path.split(".")
    current = CONFIG
    
    for part in parts
        if current == null or typeof(current) != "object" then return null
        if typeof(current[part]) == "undefined" then return null
        current = current[part]
    end for
    
    return current
end function

// Set configuration value by path
set_config = function(path, value)
    if CONFIG == null then load_botnet_config()
    
    parts = path.split(".")
    current = CONFIG
    
    // Navigate to parent object
    for i in range(0, parts.len - 1)
        part = parts[i]
        if typeof(current[part]) == "undefined" then
            current[part] = {}
        end if
        current = current[part]
    end for
    
    // Set the value
    current[parts[parts.len - 1]] = value
    
    // Save configuration
    import_code("/scripts/utils/config_manager.gs")
    if typeof(globals.save_config) == "function" then
        globals.save_config(DEFAULT_CONFIG.files.config_file, CONFIG)
    end if
end function

// Convenience getters for common paths
get_botnet_root = function()
    return get_config("paths.botnet_root")
end function

get_master_priv_file = function()
    return get_config("files.master_priv")
end function

get_master_pub_file = function()
    return get_config("files.master_pub")
end function

get_slave_priv_file = function()
    return get_config("files.slave_priv")
end function

get_slave_pub_file = function()
    return get_config("files.slave_pub")
end function

get_infected_file = function()
    return get_config("files.infected_file")
end function

get_depth_markers_dir = function()
    return get_config("files.depth_markers_dir")
end function

get_allowed_prefixes = function()
    return get_config("security.allowed_prefixes")
end function

get_allowed_scripts = function()
    return get_config("security.allowed_scripts")
end function

get_hard_depth_cap = function()
    return get_config("security.hard_depth_cap")
end function

get_default_max_depth = function()
    return get_config("security.default_max_depth")
end function

get_max_retries = function()
    return get_config("network.max_retries")
end function

get_base_delay = function()
    return get_config("network.base_delay")
end function

get_spread_delay = function()
    return get_config("network.spread_delay")
end function

// Initialize configuration on import
load_botnet_config()
