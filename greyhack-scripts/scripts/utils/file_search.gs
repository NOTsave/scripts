// file_search.gs - Recursive file search with flags (botnet compatible)
// Usage: file_search.gs <pattern> <flags>
// Returns: List of matching file paths
// Flags: b=binary only, f=folders only, t=text only

if params.len < 2 then exit("Usage: file_search.gs <pattern> <flags>")

pattern = params[0]
flags = params[1]

comp = get_shell.host_computer
root = comp.File("/")
if root == null then exit("Cannot access root directory")

// Parse flags
binaryOnly = flags.indexOf("b") != null   // binary files only
foldersOnly = flags.indexOf("f") != null  // folders only
textOnly = flags.indexOf("t") != null     // text files only

results = []

// Wildcard pattern matching helper
is_match = function(name, pattern)
    if pattern.indexOf("*") == null then
        return name.indexOf(pattern) != null
    else
        // Basic wildcard: * matches anything
        parts = pattern.split("*")
        if parts.len == 0 then return true
        pos = 0
        for part in parts
            if part == "" then continue
            idx = name.indexOf(part, pos)
            if idx == null then return false
            pos = idx + part.len
        end for
        return true
    end if
end function

find_files = function(file, currentPath, pattern, depth)
    if file == null then return
    if depth > 10 then return  // Prevent infinite recursion
    
    fullPath = currentPath + "/" + file.name
    if currentPath == "" then fullPath = "/" + file.name
    
    if file.is_folder then
        if foldersOnly then
            if is_match(file.name, pattern) then
                results.push(fullPath)
            end if
        end if
        
        // Recurse into subfolders
        subfolders = file.get_folders
        if subfolders != null then
            for sub in subfolders
                if sub == null then continue
                find_files(sub, fullPath, pattern, depth + 1)
            end for
        end if
        
        // Process files in folder
        if not foldersOnly then
            files = file.get_files
            if files != null then
                for f in files
                    if f == null then continue
                    find_files(f, fullPath, pattern, depth + 1)
                end for
            end if
        end if
    else
        // It's a file
        if not foldersOnly then
            if is_match(file.name, pattern) then
                include = true
                if binaryOnly and not file.is_binary then include = false
                if textOnly and file.is_binary then include = false
                
                if include then
                    results.push(fullPath)
                end if
            end if
        end if
    end if
end function

// Start search from root
root = comp.File("/")
if root == null then exit("Cannot access root directory")
root_folders = root.get_folders
if root_folders != null then
    for f in root_folders
        if f == null then continue
        find_files(f, "", pattern, 0)
    end for
end if
root_files = root.get_files
if root_files != null then
    for f in root_files
        if f == null then continue
        find_files(f, "", pattern, 0)
    end for
end if

// Output results
print(results.join(char(10)))
