// cerebrum.gs - Dictionary loader and manager
// Ported from 5hell's cerebrum module
// Loads tiered password dictionaries for brutus attacks
import_code("/lib/lib_common.gs")

cerebrum = {}

// Dictionary tiers - from most common to least common
cerebrum.tiers = {
    "common": ["password", "123456", "qwerty", "admin", "letmein", "welcome", "monkey", "dragon", "master", "hello", "freedom", "whatever", "qazwsx", "trustno1", "123qwe"],
    "names": ["root", "admin", "user", "guest", "test", "demo", "oracle", "mysql", "postgres", "apache", "nginx", "tomcat"],
    "patterns": ["123", "1234", "12345", "123456", "password", "pass", "admin", "root", "qwerty", "abc", "test"],
    "leetspeak": ["p@ssw0rd", "adm1n", "r00t", "p@ss", "t3st", "h3ll0", "w3lc0m3", "m0nk3y", "dr@g0n"],
    "years": ["2023", "2024", "2025", "2026", "2022", "2021", "2020", "2019", "2018", "2017"],
    "keyboard": ["qwerty", "asdf", "zxcv", "qwe", "asd", "zxc", "123qwe", "qwe123", "asdf123", "zxc123"]
}

// Loaded dictionaries cache
cerebrum.loaded_dicts = {}
cerebrum.current_index = {}

// Initialize cerebrum
cerebrum.init = function()
    log_master("Cerebrum dictionary manager initialized", "INFO")
    
    // Load all tiers
    for tier_name in cerebrum.tiers.indexes
        cerebrum.load_tier(tier_name)
    end for
    
    log_master("Loaded " + len(cerebrum.tiers) + " dictionary tiers", "SUCCESS")
end function

// Load a specific tier into memory
cerebrum.load_tier = function(tier_name)
    if not cerebrum.tiers.hasIndex(tier_name) then
        log_master("Unknown tier: " + tier_name, "ERROR")
        return false
    end if
    
    cerebrum.loaded_dicts[tier_name] = cerebrum.tiers[tier_name]
    cerebrum.current_index[tier_name] = 0
    
    log_master("Loaded tier '" + tier_name + "' with " + len(cerebrum.tiers[tier_name]) + " entries", "DEBUG")
    return true
end function

// Get next password from a tier
cerebrum.next_password = function(tier_name)
    if not cerebrum.loaded_dicts.hasIndex(tier_name) then
        if not cerebrum.load_tier(tier_name) then return null
    end if
    
    dict = cerebrum.loaded_dicts[tier_name]
    idx = cerebrum.current_index[tier_name]
    
    if idx >= dict.len then
        // Reset to beginning if we've exhausted the tier
        cerebrum.current_index[tier_name] = 0
        idx = 0
    end if
    
    password = dict[idx]
    cerebrum.current_index[tier_name] = idx + 1
    
    return password
end function

// Generate combinations (password + suffixes)
cerebrum.generate_combinations = function(base_password, suffixes)
    combinations = [base_password]
    
    for suffix in suffixes
        combinations.push(base_password + suffix)
        combinations.push(suffix + base_password)
        combinations.push(base_password + suffix.upper)
        combinations.push(base_password + suffix + "!")
        combinations.push(base_password + suffix + "123")
    end for
    
    return combinations
end function

// Get common suffixes for combinations
cerebrum.get_suffixes = function()
    return ["", "1", "12", "123", "1234", "2023", "2024", "2025", "!", "@", "#", "$", "%"]
end function

// Reset all tier indices
cerebrum.reset = function()
    for tier_name in cerebrum.current_index.indexes
        cerebrum.current_index[tier_name] = 0
    end for
    log_master("Reset all dictionary tier indices", "DEBUG")
end function

// Get statistics
cerebrum.get_stats = function()
    stats = {}
    total_passwords = 0
    
    for tier_name in cerebrum.loaded_dicts.indexes
        tier_size = len(cerebrum.loaded_dicts[tier_name])
        current_idx = cerebrum.current_index[tier_name]
        
        stats[tier_name] = {
            "total": tier_size,
            "current": current_idx,
            "remaining": tier_size - current_idx
        }
        
        total_passwords = total_passwords + tier_size
    end for
    
    stats["total"] = total_passwords
    return stats
end function

// Auto-initialize on load
cerebrum.init()
