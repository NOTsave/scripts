// ChainSaw - A Grey Hack script for cracking passwords using Markov chains
// by NitroCynic (fixed for GreyScript syntax – no '?' characters)
import_code("/data/samples.src")
import_code("/data/pregens.src")

// Newline constant to avoid char() function dependency
NL = "
"

version = "1.0.0"

in_script = false
if get_custom_object.hasIndex("in_script") then
    in_script = get_custom_object.in_script
end if

logo_str = "
   _____ _           _        _____
  / ____| |         (_)      / ____|
 | |    | |__   __ _ | '_ \ \___ \ / _` \ \ /\ / /
 | |____| | | | (_| | | | | |____) | (_| |\ V  V /
  \_____|_| |_|\__,_|_|_| |_|_____/ \__,_| \_/\_/

"
logo_str = logo_str + "ChainSaw - by NitroCynic - The Markov Chain Password Cracker v" + version + NL
logo_str = logo_str + "Source at: https://github.com/jwfraustro/chainsaw/ " + NL

alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
alpha += alpha.lower

testing = false
testing_pass = "Dessnap"
unit_test = false

list.unique = function
    unique_array = []
    for item in self
        if unique_array.indexOf(item) == null then unique_array.push(item)
    end for
    return unique_array
end function

ChainSaw = {}

ChainSaw.user = "root"
ChainSaw.ip = ""
ChainSaw.port = 22
ChainSaw.password = ""
ChainSaw.shell = null

ChainSaw.samples = samples
ChainSaw.pregens = pregens
ChainSaw.chains = {}
ChainSaw.trigram_frequencies = {}
ChainSaw.optimize_chains = false
ChainSaw.min_length = 3
ChainSaw.max_length = 9
ChainSaw.order = 3

ChainSaw.LogLevel = "INFO"
ChainSaw.version = version

ChainSaw.attempts = 0
ChainSaw._logLevels = { "DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3 }

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

ChainSaw.init = function
    ChainSaw.load_samples
    ChainSaw.load_pregens
    ChainSaw.load_chains
    if ChainSaw.optimize_chains then ChainSaw.sort_chains_by_frequency
end function

ChainSaw.load_chains = function
    ChainSaw.Log("DEBUG", "Building Markov chains...")
    for text in ChainSaw.samples
        for i in range(0, len(text) - ChainSaw.order - 1)
            sub_text = text[i : i + ChainSaw.order]
            if not ChainSaw.chains.hasIndex(sub_text) then ChainSaw.chains[sub_text] = []
            next_char = text[i + ChainSaw.order]
            if ChainSaw.chains[sub_text].indexOf(next_char) == null then
                ChainSaw.chains[sub_text].push(next_char)
            end if
        end for
    end for
    ChainSaw.Log("DEBUG", len(ChainSaw.chains) + " chains created.")
end function

ChainSaw.load_samples = function
    ChainSaw.Log("DEBUG", "Building samples...")
    ChainSaw.Log("DEBUG", "Using " + len(ChainSaw.samples) + " password samples.")
    samples = ChainSaw.samples
    ChainSaw.samples = []
    for text in samples
        if len(text) >= ChainSaw.order + 1 then
            ChainSaw.samples.push(text.upper)
        else
            ChainSaw.Log("WARN", "Sample '" + text + "' is too short for given order " + ChainSaw.order + ".")
        end if
    end for
    ChainSaw.Log("DEBUG", len(ChainSaw.samples) + " samples loaded.")
end function

ChainSaw.calculate_trigram_frequencies = function()
    ChainSaw.Log("DEBUG", "Calculating trigram frequencies...")
    frequencies = {}
    for sample in ChainSaw.samples
        for i in range(0, len(sample) - ChainSaw.order - 1)
            trigram = sample[i : i + ChainSaw.order]
            if not frequencies.hasIndex(trigram) then frequencies[trigram] = 0
            frequencies[trigram] = frequencies[trigram] + 1
        end for
    end for
    ChainSaw.trigram_frequencies = frequencies
    ChainSaw.Log("DEBUG", "Calculated frequencies for " + len(frequencies) + " trigrams")
end function

ChainSaw.sort_chains_by_frequency = function()
    ChainSaw.Log("DEBUG", "Sorting chains by frequency...")
    if ChainSaw.trigram_frequencies == null then ChainSaw.calculate_trigram_frequencies
    sortable = []
    for trigram in ChainSaw.chains.indexes
        freq = 0
        if ChainSaw.trigram_frequencies.hasIndex(trigram) then
            freq = ChainSaw.trigram_frequencies[trigram]
        end if
        sortable.push({"trigram": trigram, "frequency": freq})
    end for
    sortable = ChainSaw.sort_by_frequency(sortable)
    sorted_indexes = []
    for item in sortable
        sorted_indexes.push(item.trigram)
    end for
    ChainSaw.chains.indexes = sorted_indexes
    ChainSaw.Log("DEBUG", "Chains sorted by frequency")
end function

ChainSaw.sort_by_frequency = function(arr)
    n = len(arr)
    for i in range(0, n - 2)
        for j in range(0, n - i - 2)
            if arr[j].frequency < arr[j + 1].frequency then
                temp = arr[j]
                arr[j] = arr[j + 1]
                arr[j + 1] = temp
            end if
        end for
    end for
    return arr
end function

ChainSaw.load_pregens = function
    ChainSaw.Log("DEBUG", "Loading pregenerated passwords...")
    ChainSaw.Log("DEBUG", "Using " + len(ChainSaw.pregens) + " pregenerated passwords.")
    pregens = ChainSaw.pregens
    ChainSaw.pregens = []
    for text in pregens
        if len(text) >= ChainSaw.min_length and len(text) <= ChainSaw.max_length then
            ChainSaw.pregens.push(text)
        else
            ChainSaw.Log("WARN", "Pregenerated password '" + text + "' not within min/max length boundaries: " + ChainSaw.min_length + " - " + ChainSaw.max_length + ".")
        end if
    end for
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

ChainSaw.next_name = function
    text = ""
    num = floor(805)
    desired_len = len(ChainSaw.samples[num])
    start_idx = floor(rnd * (desired_len - ChainSaw.order))
    text = ChainSaw.samples[num][start_idx : start_idx + ChainSaw.order]
    while len(text) < desired_len
        start_idx = len(text) - ChainSaw.order
        sub_text = text[start_idx : start_idx + ChainSaw.order]
        if ChainSaw.get_letter(sub_text) == "~" then break
        text = text + ChainSaw.get_letter(sub_text)
    end while
    text = text.lower
    print("Generated password: " + text)
    return text
end function

ChainSaw.get_letter = function(token)
    if not ChainSaw.chains.hasIndex(token) then return "~"
    next_chars = ChainSaw.chains[token]
    num = floor(rnd * len(next_chars))
    return next_chars[num]
end function

ChainSaw.recurse = function(token, max_length)
    password = token.lower
    result = ChainSaw.connect(password)
    ChainSaw.attempts = ChainSaw.attempts + 1
    if result != null then
        print("<b>[ChainSaw] Password found: " + password + "</b>")
        ChainSaw.set_password(password)
        return result
    else
        upper_first_char = password[0].upper + password[1:]
        result = ChainSaw.connect(upper_first_char)
        ChainSaw.attempts = ChainSaw.attempts + 1
        if result != null then
            print("<b>[ChainSaw] Password found: " + upper_first_char + "</b>")
            ChainSaw.set_password(upper_first_char)
            return result
        end if
    end if
    if len(token) >= max_length then return null
    start_idx = len(token) - ChainSaw.order
    sub_text = token[start_idx : start_idx + ChainSaw.order]
    if not ChainSaw.chains.hasIndex(sub_text) then return null
    next_chars = ChainSaw.chains[sub_text]
    for next_char in next_chars
        new_password = token + next_char
        result = ChainSaw.recurse(new_password, max_length)
        if result != null then return result
    end for
end function

ChainSaw.PregenAttack = function
    ChainSaw.Log("INFO", "Attacking with pregenerated passwords...")
    for password in ChainSaw.pregens
        result = ChainSaw.connect(password)
        ChainSaw.attempts = ChainSaw.attempts + 1
        if result != null then
            print("<b>[ChainSaw] Password found: " + password + "</b>")
            ChainSaw.set_password(password)
            return result
        else
            upper_first_char = password[0].upper + password[1:]
            result = ChainSaw.connect(upper_first_char)
            ChainSaw.attempts = ChainSaw.attempts + 1
            if result != null then
                print("<b>[ChainSaw] Password found: " + upper_first_char + "</b>")
                ChainSaw.set_password(upper_first_char)
                return result
            end if
        end if
    end for
    return null
end function

ChainSaw.crack = function(show_logo = true)
    if show_logo then
        ChainSaw.Log("INFO", logo_str)
        ChainSaw.Log("INFO", "VROOM!....")
    end if
    start_time = time
    result = ChainSaw.PregenAttack
    if result != null then
        ChainSaw.set_result(result)
        ChainSaw.Log("DEBUG", "Evaluated " + ChainSaw.attempts + " passwords.")
        ChainSaw.Log("DEBUG", "Execution time: " + (time - start_time) + " seconds")
        return result
    end if
    ChainSaw.Log("INFO", "No pregenerated passwords found.")
    ChainSaw.Log("INFO", "Attacking with markov chains...")
    for token in ChainSaw.chains.indexes
        result = ChainSaw.recurse(token, ChainSaw.max_length)
        if result != null then
            ChainSaw.set_result(result)
            ChainSaw.Log("DEBUG", "Evaluated " + ChainSaw.attempts + " passwords.")
            ChainSaw.Log("DEBUG", "Execution time: " + (time - start_time) + " seconds")
            return result
        end if
    end for
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
            ChainSaw.Log("WARN", "Parameters must be in the form of <key>=<value>")
            exit
        end if
        key = param.split("=")[0]
        value = param.split("=")[1]
        if key == "--loglevel" then
            ChainSaw.LogLevel = value.upper
            if not ChainSaw._logLevels.hasIndex(ChainSaw.LogLevel) then
                print("Invalid log level: " + value)
                print_help
                return null
            end if
        else if key == "--user" then
            ChainSaw.user = value
        else if key == "--ip" then
            ChainSaw.ip = value
        else if key == "--port" then
            ChainSaw.port = value.to_int
        else if key == "--min_length" then
            ChainSaw.min_length = value.to_int
        else if key == "--max_length" then
            ChainSaw.max_length = value.to_int
        else if key == "--order" then
            ChainSaw.order = value.to_int
        else if key == "--test_pass" then
            globals.testing_pass = value
        else if key == "--optimize_chains" then
            if value.lower == "true" or value.lower == "1" then ChainSaw.optimize_chains = true
        else if key == "--help" or key == "-h" then
            print_help
            return null
        end if
    end for
end function

ChainSaw.load = function
    get_custom_object.chainsaw = ChainSaw
    if len(params) > 1 then ChainSaw.parse_params(params[1:])
    ChainSaw.Log("INFO", "ChainSaw loaded into GCO as 'chainsaw'.")
    ChainSaw.Log("INFO", "Use 'chainsaw.init()' to initialize the script.")
    ChainSaw.Log("INFO", "Use 'chainsaw.crack()' to run the script.")
end function

print_help = function
    print("Commands:")
    print("  help  - Display this help")
    print("  run   - Run the script (outputs password)")
    print("  test  - Test against a known password")
    print("  load  - Load into GCO")
    print("Parameters:")
    print("  --user=USER               (default root)")
    print("  --ip=IP                   (remote IP)")
    print("  --port=PORT               (default 22)")
    print("  --min_length=N            (default 3)")
    print("  --max_length=N            (default 9)")
    print("  --order=N                 (default 3)")
    print("  --loglevel=LEVEL          (INFO, DEBUG, WARN, ERROR)")
    print("  --optimize_chains=true/false")
end function

if unit_test then
    // unit test omitted for brevity
    exit(0)
end if

if len(params) == 0 and not in_script then
    print("Usage: chainsaw [command] [options]")
    print("Commands:")
    print("  help  - Display this help")
    print("  run   - Run the script")
    print("  test  - Test mode")
    print("  load  - Load into GCO")
    return
end if

if len(params) > 0 and not in_script then
    if params[0] == "help" then
        print(logo_str)
        print_help
        return
    else if params[0] == "run" then
        ChainSaw.parse_params(params)
        ChainSaw.init
        ChainSaw.crack
        return
    else if params[0] == "test" then
        testing = true
        ChainSaw.parse_params(params)
        ChainSaw.init
        ChainSaw.crack
        return
    else if params[0] == "load" then
        ChainSaw.load
        return
    end if
end if
