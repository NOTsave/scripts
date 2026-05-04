// ChainSaw v2 - Enhanced with pre-computed pwgen tables
// by NitroCynic (enhanced for botnet toolkit with 5hell pwgen integration)
import_code("/scripts/utils/pwgen.gs")
import_code("/lib/lib_common.gs")

version = "2.0.0"

in_script = false
if get_custom_object.hasIndex("in_script") then
    in_script = get_custom_object.in_script
end if

// Minimal header for headless bot execution - keeps author attribution
logo_str = "ChainSaw v" + version + " by NitroCynic" + char(10)

testing = false
testing_pass = "Dessnap"
unit_test = false

ChainSaw = {}

ChainSaw.user = "root"
ChainSaw.ip = ""
ChainSaw.port = 22
ChainSaw.password = ""
ChainSaw.shell = null
ChainSaw.use_tables = true  // Use pre-computed tables by default

ChainSaw.LogLevel = "INFO"
ChainSaw.version = version
ChainSaw.attempts = 0
ChainSaw._logLevels = { "DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3 }

// Loaded tables cache
ChainSaw.loaded_tables = {}
ChainSaw.current_table_idx = 0

ChainSaw.Log = function(level, message)
    if ChainSaw._logLevels[level] >= ChainSaw._logLevels[ChainSaw.LogLevel] then
        out_str = "[ChainSaw] [" + level + "] " + message
        if level == "ERROR" then
            print("<color=red>" + out_str + "</color>")
        else if level == "WARN" then
            print("<color=yellow>" + out_str + "</color>")
        else
            print(out_str)
        end if
    end if
end function

// Load pwgen tables for faster cracking
ChainSaw.load_tables = function()
    if not ChainSaw.use_tables then return
    
    ChainSaw.Log("INFO", "Loading pre-computed pwgen tables...")
    
    // Load available table indices
    comp = get_shell.host_computer
    tp_dir = comp.File("/data/tp")
    if not tp_dir then
        ChainSaw.Log("WARN", "No pwgen tables found, falling back to chain generation")
        ChainSaw.use_tables = false
        return
    end if
    
    table_files = tp_dir.get_files
    if table_files == null then
        ChainSaw.Log("WARN", "No table files found, falling back to chain generation")
        ChainSaw.use_tables = false
        return
    end if
    
    // Extract table IDs from filenames
    for file in table_files
        if file.name.startswith("table_") and file.name.endswith(".txt") then
            table_id = file.name[6:9]  // Extract XXX from table_XXX.txt
            ChainSaw.loaded_tables[table_id] = null  // Will load on demand
        end if
    end for
    
    ChainSaw.Log("INFO", "Found " + len(ChainSaw.loaded_tables) + " table files")
end function

// Get passwords from a specific table
ChainSaw.get_table_passwords = function(table_id)
    if ChainSaw.loaded_tables.hasIndex(table_id) and ChainSaw.loaded_tables[table_id] != null then
        return ChainSaw.loaded_tables[table_id]
    end if
    
    passwords = pwgen.load_table(table_id, "plain")
    if passwords != null then
        ChainSaw.loaded_tables[table_id] = passwords
        ChainSaw.Log("DEBUG", "Loaded table " + table_id + " with " + passwords.len + " passwords")
    end if
    
    return passwords
end function

ChainSaw.connect = function(password)
    if testing then
        if password == testing_pass then
            return "shell"
        else
            return null
        end if
    end if
    if ChainSaw.ip != "" and ChainSaw.port != null then
        return get_shell.connect_service(ChainSaw.ip, ChainSaw.port, ChainSaw.user, password)
    else
        return get_shell(ChainSaw.user, password)
    end if
    return null
end function

// Table-based attack using pre-computed passwords
ChainSaw.table_attack = function()
    if not ChainSaw.use_tables then return null
    
    ChainSaw.Log("INFO", "Attacking with pre-computed pwgen tables...")
    
    table_ids = ChainSaw.loaded_tables.indexes
    if table_ids.len == 0 then
        ChainSaw.Log("WARN", "No tables loaded for table attack")
        return null
    end if
    
    // Try each table in sequence
    for table_id in table_ids
        passwords = ChainSaw.get_table_passwords(table_id)
        if passwords == null then continue
        
        ChainSaw.Log("INFO", "Trying table " + table_id + " (" + passwords.len + " passwords)...")
        
        for password in passwords
            if password == "" then continue
            
            result = ChainSaw.connect(password)
            ChainSaw.attempts = ChainSaw.attempts + 1
            if result != null then
                print("<b>[ChainSaw] Password found: " + password + "</b>")
                ChainSaw.set_password(password)
                return result
            else
                // Try capitalizing first letter
                upper_first = password[0].upper + password[1:]
                result = ChainSaw.connect(upper_first)
                ChainSaw.attempts = ChainSaw.attempts + 1
                if result != null then
                    print("<b>[ChainSaw] Password found: " + upper_first + "</b>")
                    ChainSaw.set_password(upper_first)
                    return result
                end if
            end if
        end for
    end for
    
    return null
end function

// Fallback to original chain-based generation if tables fail
ChainSaw.init_chains = function()
    ChainSaw.Log("INFO", "Initializing fallback Markov chains...")
    import_code("data/samples.src")
    import_code("data/pregens.src")
    
    ChainSaw.samples = samples
    ChainSaw.pregens = pregens
    ChainSaw.chains = {}
    ChainSaw.order = 3
    ChainSaw.min_length = 3
    ChainSaw.max_length = 9
    
    // Build chains from samples (simplified version)
    for text in ChainSaw.samples
        if len(text) >= ChainSaw.order + 1 then
            text = text.upper
            for i in range(0, len(text) - ChainSaw.order - 1)
                sub_text = text[i : i + ChainSaw.order]
                if not ChainSaw.chains.hasIndex(sub_text) then 
                    ChainSaw.chains[sub_text] = []
                end if
                next_char = text[i + ChainSaw.order]
                if ChainSaw.chains[sub_text].indexOf(next_char) == null then
                    ChainSaw.chains[sub_text].push(next_char)
                end if
            end for
        end if
    end for
    
    ChainSaw.Log("INFO", "Built " + len(ChainSaw.chains) + " fallback chains")
end function

ChainSaw.chain_attack = function()
    if ChainSaw.chains == null then ChainSaw.init_chains
    
    ChainSaw.Log("INFO", "Attacking with Markov chain generation...")
    
    // Try pre-generated passwords first
    if ChainSaw.pregens != null then
        for password in ChainSaw.pregens
            result = ChainSaw.connect(password)
            ChainSaw.attempts = ChainSaw.attempts + 1
            if result != null then
                print("<b>[ChainSaw] Password found: " + password + "</b>")
                ChainSaw.set_password(password)
                return result
            end if
        end for
    end if
    
    // Generate and try passwords from chains
    tokens = ChainSaw.chains.indexes
    for i in range(0, 999)  // Limit to exactly 1000 attempts (0-999) to prevent infinite loops
        if tokens.len == 0 then break
        
        token = tokens[floor(rnd * tokens.len)]
        password = ChainSaw.generate_from_token(token)
        if password == null then continue
        
        result = ChainSaw.connect(password)
        ChainSaw.attempts = ChainSaw.attempts + 1
        if result != null then
            print("<b>[ChainSaw] Password found: " + password + "</b>")
            ChainSaw.set_password(password)
            return result
        end if
    end for
    
    return null
end function

ChainSaw.generate_from_token = function(token)
    if not ChainSaw.chains.hasIndex(token) then return null
    
    text = token.lower
    desired_len = 3 + floor(rnd * 6)  // 3-8 characters
    
    while len(text) < desired_len
        start_idx = len(text) - ChainSaw.order
        if start_idx < 0 then break
        sub_text = text[start_idx : start_idx + ChainSaw.order]
        if not ChainSaw.chains.hasIndex(sub_text) then break
        next_chars = ChainSaw.chains[sub_text]
        next_char = next_chars[floor(rnd * len(next_chars))]
        text = text + next_char.lower
    end while
    
    return text
end function

ChainSaw.crack = function(show_logo = true)
    if show_logo then
        ChainSaw.Log("INFO", logo_str)
        ChainSaw.Log("INFO", "VROOM!....")
    end if
    
    start_time = time
    
    // Try table attack first (much faster)
    result = ChainSaw.table_attack
    if result != null then
        ChainSaw.set_result(result)
        ChainSaw.Log("DEBUG", "Evaluated " + ChainSaw.attempts + " passwords.")
        ChainSaw.Log("DEBUG", "Execution time: " + (time - start_time) + " seconds")
        return result
    end if
    
    // Fallback to chain generation
    ChainSaw.Log("INFO", "Table attack failed, falling back to chain generation...")
    result = ChainSaw.chain_attack
    if result != null then
        ChainSaw.set_result(result)
        ChainSaw.Log("DEBUG", "Evaluated " + ChainSaw.attempts + " passwords.")
        ChainSaw.Log("DEBUG", "Execution time: " + time - start_time + " seconds")
        return result
    end if
    
    ChainSaw.Log("WARN", "Password not found after " + ChainSaw.attempts + " attempts")
    return null
end function

ChainSaw.set_result = function(result)
    ChainSaw.shell = result
end function

ChainSaw.set_password = function(password)
    ChainSaw.password = password
end function

ChainSaw.parse_params = function(param_list)
    param_list = param_list[1:]
    ChainSaw.Log("DEBUG", "Parsing parameters...")
    ChainSaw.Log("DEBUG", "Parameters: " + join(param_list, ", "))
    for param in param_list
        if len(param.split("=")) != 2 then
            ChainSaw.Log("WARN", "Parameters must be in form of <key>=<value>")
            exit
        end if
        key = param.split("=")[0]
        value = param.split("=")[1]
        if key == "--loglevel" then
            ChainSaw.LogLevel = value.upper
            if not ChainSaw._logLevels.hasIndex(ChainSaw.LogLevel) then
                print("Invalid log level: " + value)
                ChainSaw.print_help
                return null
            end if
        else if key == "--user" then
            ChainSaw.user = value
        else if key == "--ip" then
            ChainSaw.ip = value
        else if key == "--port" then
            ChainSaw.port = value.to_int
        else if key == "--use_tables" then
            ChainSaw.use_tables = (value.lower == "true" or value == "1")
        else if key == "--test_pass" then
            testing_pass = value
        else if key == "--help" or key == "-h" then
            ChainSaw.print_help
            return null
        end if
    end for
end function

ChainSaw.print_help = function
    print("Commands:")
    print("  help  - Display this help")
    print("  run   - Run script (outputs password)")
    print("  test  - Test against a known password")
    print("  load  - Load into GCO")
    print("Parameters:")
    print("  --user=USER               (default root)")
    print("  --ip=IP                   (remote IP)")
    print("  --port=PORT               (default 22)")
    print("  --use_tables=true/false    (default true)")
    print("  --loglevel=LEVEL          (INFO, DEBUG, WARN, ERROR)")
end function

ChainSaw.load = function
    get_custom_object.chainsaw = ChainSaw
    if len(params) > 1 then ChainSaw.parse_params(params[1:])
    ChainSaw.load_tables
    ChainSaw.Log("INFO", "ChainSaw v2 loaded into GCO as 'chainsaw'.")
    ChainSaw.Log("INFO", "Use 'chainsaw.crack()' to run script.")
end function

if unit_test then
    exit(0)
end if

if len(params) == 0 and not in_script then
    print("Usage: chainsaw_v2 [command] [options]")
    print("Commands:")
    print("  help  - Display this help")
    print("  run   - Run script")
    print("  test  - Test mode")
    print("  load  - Load into GCO")
    return
end if

if len(params) > 0 and not in_script then
    if params[0] == "help" then
        print(logo_str)
        ChainSaw.print_help
        return
    else if params[0] == "run" then
        ChainSaw.parse_params(params)
        ChainSaw.load_tables
        ChainSaw.crack
        return
    else if params[0] == "test" then
        testing = true
        ChainSaw.parse_params(params)
        ChainSaw.load_tables
        ChainSaw.crack
        return
    else if params[0] == "load" then
        ChainSaw.load
        return
    end if
end if
