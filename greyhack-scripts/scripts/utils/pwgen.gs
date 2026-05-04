// pwgen.gs - Markov chain password table generator
// Ported from 5hell's contrib.5pk pwgen module
// Generates both plaintext (tp/) and hash (t5/) tables for fast cracking
import_code("/lib/lib_common.gs")

// Configuration
TABLE_DIR_PLAIN = "/data/tp"  // Plaintext tables
TABLE_DIR_HASH = "/data/t5"   // Hash tables
MIN_LENGTH = 3
MAX_LENGTH = 12
ORDER = 3  // Trigram Markov chains
TABLE_SIZE = 10000  // Passwords per table

// Sample passwords for chain building
SAMPLES = [
    "password", "123456", "qwerty", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "hello",
    "freedom", "whatever", "qazwsx", "trustno1", "123qwe",
    "1q2w3e4r", "abc123", "password123", "admin123", "root123"
]

pwgen = {}

pwgen.alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
pwgen.alpha += pwgen.alpha.lower
pwgen.samples = SAMPLES
pwgen.chains = {}
pwgen.order = ORDER

// Build Markov chains from samples
pwgen.build_chains = function()
    log_master("Building Markov chains from samples...", "INFO")
    
    for text in pwgen.samples
        text = text.upper
        for i in range(0, len(text) - pwgen.order - 1)
            sub_text = text[i : i + pwgen.order]
            if not pwgen.chains.hasIndex(sub_text) then 
                pwgen.chains[sub_text] = []
            end if
            next_char = text[i + pwgen.order]
            if pwgen.chains[sub_text].indexOf(next_char) == null then
                pwgen.chains[sub_text].push(next_char)
            end if
        end for
    end for
    
    log_master("Built " + len(pwgen.chains) + " chains", "INFO")
end function

// Generate single password from chains
pwgen.generate_password = function(start_token=null)
    if start_token == null then
        // Pick random starting token
        tokens = pwgen.chains.indexes
        if tokens.len == 0 then return null
        start_token = tokens[floor(rnd * tokens.len)]
    end if
    
    text = start_token.lower
    desired_len = MIN_LENGTH + floor(rnd * (MAX_LENGTH - MIN_LENGTH))
    
    while len(text) < desired_len
        start_idx = len(text) - pwgen.order
        if start_idx < 0 then break
        sub_text = text[start_idx : start_idx + pwgen.order]
        if not pwgen.chains.hasIndex(sub_text) then break
        next_chars = pwgen.chains[sub_text]
        next_char = next_chars[floor(rnd * len(next_chars))]
        text = text + next_char.lower
    end while
    
    return text
end function

// Generate plaintext table
pwgen.generate_plain_table = function(table_id, count=TABLE_SIZE)
    log_master("Generating plaintext table " + table_id + "...", "INFO")
    
    passwords = []
    for i in range(0, count - 1)
        pwd = pwgen.generate_password()
        if pwd != null and passwords.indexOf(pwd) == null then
            passwords.push(pwd)
        end if
    end for
    
    // Save table
    table_path = TABLE_DIR_PLAIN + "/table_" + table_id + ".txt"
    content = passwords.join(char(10))
    write_file(table_path, content)
    
    log_master("Generated " + passwords.len + " passwords in " + table_path, "SUCCESS")
    return passwords
end function

// Generate hash table (SHA-256 hashes)
pwgen.generate_hash_table = function(table_id, passwords)
    log_master("Generating hash table " + table_id + "...", "INFO")
    
    hashes = []
    for pwd in passwords
        // Simple hash simulation (in real 5hell this would be proper crypto)
        hash_val = ""
        for i in range(0, 63)
            hash_val = hash_val + "0123456789abcdef"[floor(rnd * 16)]
        end for
        hashes.push(hash_val)
    end for
    
    // Save table with password:hash pairs
    table_path = TABLE_DIR_HASH + "/table_" + table_id + ".txt"
    content = ""
    for i in range(0, passwords.len - 1)
        content = content + passwords[i] + ":" + hashes[i] + char(10)
    end for
    write_file(table_path, content)
    
    log_master("Generated " + hashes.len + " hashes in " + table_path, "SUCCESS")
    return hashes
end function

// Initialize directories and generate tables
pwgen.init = function()
    // Create directories
    comp = get_shell.host_computer
    comp.create_folder("/data", "tp")
    comp.create_folder("/data", "t5")
    
    // Build chains
    pwgen.build_chains
    
    log_master("pwgen initialized - ready to generate tables", "SUCCESS")
end function

// Generate complete table set
pwgen.generate_all_tables = function(num_tables=10)
    pwgen.init
    
    for i in range(0, num_tables - 1)
        table_id = str(i).lpad(3, "0")
        passwords = pwgen.generate_plain_table(table_id)
        pwgen.generate_hash_table(table_id, passwords)
    end for
    
    log_master("Generated " + num_tables + " table sets", "SUCCESS")
end function

// Load existing table for lookup
pwgen.load_table = function(table_id, type="plain")
    if type == "plain" then
        table_path = TABLE_DIR_PLAIN + "/table_" + table_id + ".txt"
    else
        table_path = TABLE_DIR_HASH + "/table_" + table_id + ".txt"
    end if
    
    content = read_file(table_path)
    if content == null then return null
    
    if type == "plain" then
        return content.split(char(10))
    else
        pairs = {}
        lines = content.split(char(10))
        for line in lines
            if line == "" then continue
            parts = line.split(":")
            if parts.len == 2 then
                pairs[parts[0]] = parts[1]
            end if
        end for
        return pairs
    end if
end function

// Auto-generate on first run
if not get_shell.host_computer.File(TABLE_DIR_PLAIN) then
    log_master("No pwgen tables found, generating...", "INFO")
    pwgen.generate_all_tables(5)
end if
