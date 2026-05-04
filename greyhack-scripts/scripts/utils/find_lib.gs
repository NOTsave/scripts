// find_lib.gs - Recursive best-version library finder
// Ported from 5hell's super_import pattern
// Usage: mx = find_lib("metaxploit.so")
//        cr = find_lib("crypto.so")

extract_version_string = function(file_obj)
    // Parse version from file, return as string "1.2.3"
    // Falls back to modification time if no version detectable
    if file_obj == null then return null
    content = file_obj.get_content
    if content == null then return "0.0.0"
    // Look for version pattern: v1.2.3 or 1.2.3
    v_idx = content.indexOf("version")
    if v_idx != null then
        after = content[v_idx + 7:]
        nums = ""
        for c in after
            if c == "." or (c.code >= 48 and c.code <= 57) then
                nums = nums + c
            else
                break
            end if
        end for
        parts = nums.split(".")
        if parts.len >= 2 then
            return nums
        end if
    end if
    // Fallback: use file size as version proxy
    return "0.0." + str(file_obj.size)
end function

compare_versions = function(ver_a, ver_b)
    if ver_a == null and ver_b == null then return 0
    if ver_a == null then return -1
    if ver_b == null then return 1
    
    parts_a = ver_a.split(".")
    parts_b = ver_b.split(".")
    max_len = parts_a.len
    if parts_b.len > max_len then max_len = parts_b.len
    
    for i in range(0, max_len - 1)
        num_a = 0
        num_b = 0
        if i < parts_a.len then num_a = parts_a[i].to_int
        if i < parts_b.len then num_b = parts_b[i].to_int
        if typeof(num_a) != "number" then num_a = 0
        if typeof(num_b) != "number" then num_b = 0
        
        if num_a > num_b then return 1
        if num_a < num_b then return -1
    end for
    
    return 0
end function

find_lib = function(name)
    comp = get_shell.host_computer
    root = comp.File("/")
    if root == null then return null
    
    best = null
    best_ver_str = "0.0.0"
    
    search_dirs = [root]
    visited = {}
    depth = 0
    max_depth = 8
    
    while search_dirs.len > 0 and depth < max_depth
        next_dirs = []
        for dir in search_dirs
            if dir == null then continue
            dir_path = dir.path
            if visited.hasIndex(dir_path) then continue
            visited[dir_path] = true
            
            // Check files in this directory
            files = dir.get_files
            if files != null then
                for f in files
                    if f == null then continue
                    if f.name == name then
                        ver_str = extract_version_string(f)
                        if compare_versions(ver_str, best_ver_str) > 0 then
                            best = f
                            best_ver_str = ver_str
                        end if
                    end if
                end for
            end if
            
            // Queue subdirectories
            folders = dir.get_folders
            if folders != null then
                for sub in folders
                    if sub != null then next_dirs.push(sub)
                end for
            end if
        end for
        search_dirs = next_dirs
        depth = depth + 1
    end while
    
    if best != null then
        result = include_lib(best.path)
        return result
    end if
    
    // Fallback: try standard locations
    standard_paths = ["/lib/" + name, "/usr/lib/" + name, "/home/guest/" + name]
    for path in standard_paths
        f = comp.File(path)
        if f != null then
            result = include_lib(path)
            if result != null then return result
        end if
    end for
    
    return null
end function

// Convenience wrappers
get_metaxploit = function()
    mx = find_lib("metaxploit.so")
    if mx == null then exit("ERROR: metaxploit.so not found anywhere on system")
    return mx
end function

get_crypto = function()
    cr = find_lib("crypto.so")
    if cr == null then exit("ERROR: crypto.so not found anywhere on system")
    return cr
end function
