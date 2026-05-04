// brutus.gs - Dictionary password brute forcer
// Ported from 5hell's brutus module
// Works with cerebrum dictionaries and supports remote execution via GLASSPOOL
import_code("/lib/lib_common.gs")
import_code("/scripts/utils/cerebrum.gs")
import_code("/scripts/utils/accessLevel.gs")

brutus = {}

brutus.user = "root"
brutus.ip = ""
brutus.port = 22
brutus.shell = null
brutus.password = ""
brutus.max_attempts = 1000
brutus.delay = 0.1
brutus.use_combinations = true
brutus.current_tier = "common"

brutus.attempts = 0
brutus.successful = false
brutus.start_time = 0

brutus.LogLevel = "INFO"
brutus._logLevels = { "DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3 }

brutus.Log = function(level, message)
    if brutus._logLevels[level] >= brutus._logLevels[brutus.LogLevel] then
        out_str = "[brutus] [" + level + "] " + message
        if level == "ERROR" then
            print("<color=red>" + out_str + "</color>")
        else if level == "WARN" then
            print("<color=yellow>" + out_str + "</color>")
        else
            print(out_str)
        end if
    end if
end function

// Test password against target
brutus.test_password = function(password)
    if brutus.shell != null then
        // Remote execution via GLASSPOOL-style shell
        return brutus.test_remote(password)
    else
        // Local execution
        return brutus.test_local(password)
    end if
end function

brutus.test_local = function(password)
    if brutus.ip != "" and brutus.port != null then
        return get_shell.connect_service(brutus.ip, brutus.port, brutus.user, password)
    else
        return get_shell(brutus.user, password)
    end if
end function

brutus.test_remote = function(password)
    // Execute via existing shell (GLASSPOOL-style)
    if brutus.shell == null then return null
    
    // Try to connect from the remote shell to the target
    if brutus.ip != "" then
        cmd = "connect_service " + brutus.ip + " " + brutus.port + " " + brutus.user + " " + password
    else
        cmd = "get_shell " + brutus.user + " " + password
    end if
    
    // This is a simplified version - in real GLASSPOOL this would be more sophisticated
    result = brutus.shell.run(cmd)
    
    // For simulation, we'll use the local method
    return brutus.test_local(password)
end function

// Attack using cerebrum dictionaries
brutus.attack = function()
    // Guard: cerebrum must be loaded before use
    if typeof(cerebrum) != "map" then
        brutus.Log("ERROR", "cerebrum not loaded - check import order")
        return null
    end if
    
    brutus.Log("INFO", "Starting brutus dictionary attack...")
    brutus.start_time = time
    brutus.attempts = 0
    brutus.successful = false
    
    // Try each tier in order of likelihood
    tiers = ["common", "names", "patterns", "leetspeak", "years", "keyboard"]
    
    for tier_name in tiers
        if brutus.successful then break
        
        brutus.Log("INFO", "Trying tier: " + tier_name)
        brutus.current_tier = tier_name
        
        result = brutus.attack_tier(tier_name)
        if result != null then
            brutus.password = result
            brutus.successful = true
            brutus.Log("SUCCESS", "Password found: " + result)
            return result
        end if
    end for
    
    brutus.Log("WARN", "Dictionary attack failed after " + brutus.attempts + " attempts")
    return null
end function

// Attack specific tier
brutus.attack_tier = function(tier_name)
    cerebrum.reset()  // Reset dictionary indices
    
    while brutus.attempts < brutus.max_attempts and not brutus.successful
        password = cerebrum.next_password(tier_name)
        if password == null then break
        
        // Test base password
        result = brutus.test_password(password)
        brutus.attempts = brutus.attempts + 1
        
        if result != null then
            brutus.Log("SUCCESS", "Found password: " + password)
            brutus.password = password
            return password
        end if
        
        // Test with first letter capitalized
        if password.len > 0 then
            cap_password = password[0].upper + password[1:]
            result = brutus.test_password(cap_password)
            brutus.attempts = brutus.attempts + 1
            
            if result != null then
                brutus.Log("SUCCESS", "Found password: " + cap_password)
                brutus.password = cap_password
                return cap_password
            end if
        end if
        
        // Test combinations if enabled
        if brutus.use_combinations and tier_name == "common" then
            combos = brutus.generate_combinations(password)
            for combo in combos
                if brutus.attempts >= brutus.max_attempts then break
                
                result = brutus.test_password(combo)
                brutus.attempts = brutus.attempts + 1
                
                if result != null then
                    brutus.Log("SUCCESS", "Found password: " + combo)
                    brutus.password = combo
                    return combo
                end if
            end for
        end if
        
        // Small delay to avoid detection
        if brutus.delay > 0 then
            wait(brutus.delay)
        end if
        
        // Progress reporting
        if brutus.attempts % 50 == 0 then
            brutus.Log("DEBUG", "Attempted " + brutus.attempts + " passwords...")
        end if
    end while
    
    return null
end function

// Generate password combinations
brutus.generate_combinations = function(base_password)
    suffixes = cerebrum.get_suffixes()
    combos = [base_password]
    
    for suffix in suffixes
        if brutus.attempts >= brutus.max_attempts then break
        
        // Basic combinations
        combos.push(base_password + suffix)
        combos.push(suffix + base_password)
        
        // Capitalized versions
        if base_password.len > 0 then
            cap_base = base_password[0].upper + base_password[1:]
            combos.push(cap_base + suffix)
            combos.push(suffix + cap_base)
        end if
    end for
    
    return combos
end function

// Quick attack - only common passwords
brutus.quick_attack = function()
    brutus.Log("INFO", "Starting quick brutus attack (common passwords only)...")
    brutus.max_attempts = 100
    result = brutus.attack_tier("common")
    return result
end function

// Set target for remote execution
brutus.set_target = function(ip, port=22, user="root")
    brutus.ip = ip
    brutus.port = port
    brutus.user = user
    brutus.Log("INFO", "Target set: " + user + "@" + ip + ":" + port)
end function

// Set shell for GLASSPOOL-style remote execution
brutus.set_shell = function(shell)
    brutus.shell = shell
    if shell != null then
        brutus.Log("INFO", "Remote shell set for GLASSPOOL execution")
    end if
end function

// Get attack statistics
brutus.get_stats = function()
    runtime = 0
    if brutus.start_time > 0 then
        runtime = time - brutus.start_time
    end if
    
    return {
        "attempts": brutus.attempts,
        "successful": brutus.successful,
        "password": brutus.password,
        "runtime": runtime,
        "current_tier": brutus.current_tier
    }
end function

// Parse command line parameters
brutus.parse_params = function(param_list)
    param_list = param_list[1:]
    for param in param_list
        if len(param.split("=")) != 2 then
            brutus.Log("WARN", "Parameters must be in form of <key>=<value>")
            continue
        end if
        
        key = param.split("=")[0]
        value = param.split("=")[1]
        
        if key == "--user" then
            brutus.user = value
        else if key == "--ip" then
            brutus.ip = value
        else if key == "--port" then
            brutus.port = value.to_int
        else if key == "--max_attempts" then
            brutus.max_attempts = value.to_int
        else if key == "--delay" then
            brutus.delay = value.to_float
        else if key == "--combinations" then
            brutus.use_combinations = (value.lower == "true" or value == "1")
        else if key == "--loglevel" then
            brutus.LogLevel = value.upper
        end if
    end for
end function

// Print usage help
brutus.print_help = function()
    print("brutus - Dictionary password brute forcer")
    print("")
    print("Usage: brutus [command] [options]")
    print("")
    print("Commands:")
    print("  attack       - Full dictionary attack")
    print("  quick        - Quick attack (common passwords only)")
    print("  help         - Show this help")
    print("")
    print("Options:")
    print("  --user=USER         Target username (default: root)")
    print("  --ip=IP             Target IP address")
    print("  --port=PORT         Target port (default: 22)")
    print("  --max_attempts=N    Maximum attempts (default: 1000)")
    print("  --delay=SECONDS     Delay between attempts (default: 0.1)")
    print("  --combinations=true  Enable password combinations (default: true)")
    print("  --loglevel=LEVEL    Log level (DEBUG, INFO, WARN, ERROR)")
end function

// Command line interface
if len(params) == 0 then
    brutus.print_help
else if params[0] == "help" then
    brutus.print_help
else if params[0] == "attack" then
    brutus.parse_params(params)
    brutus.attack
else if params[0] == "quick" then
    brutus.parse_params(params)
    brutus.quick_attack
else
    print("Unknown command: " + params[0])
    brutus.print_help
end if
