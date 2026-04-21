// file_search.gs - Recursive file search on remote system
// Assumes remote shell is already connected, passed as context

// Get search keyword from user input
keyword = user_input("Enter search keyword: ")
if keyword == "" then
    exit("No keyword provided")
end if

print("Searching for keyword: " + keyword)
print("Starting from root directory...")

// Recursive search function with depth limit
searchFolder = function(folder, path, depth)
    if folder == null then
        return
    end if
    
    // Prevent infinite recursion
    if depth > 10 then
        print("  [MAX DEPTH REACHED] " + path)
        return
    end if
    
    print("Searching in: " + path + " (depth " + str(depth) + ")")
    
    // Get files in current folder
    files = folder.get_files
    if files != null then
        for file in files
            if file == null then continue
            
            // Check if filename contains keyword
            if file.name.indexOf(keyword) != null then
                print("MATCH (filename): " + path + "/" + file.name)
            end if
            
            // Check file content if not binary and has read permission
            if not file.is_binary and file.has_permission("r") then
                content = file.content
                if content != null and content.indexOf(keyword) != null then
                    print("MATCH (content): " + path + "/" + file.name)
                end if
            end if
        end for
    end if
    
    // Get subfolders and recurse
    folders = folder.get_folders
    if folders != null then
        for subfolder in folders
            if subfolder == null then continue
            
            subPath = path + "/" + subfolder.name
            searchFolder(subfolder, subPath, depth + 1)
        end for
    end if
end function

// Get remote computer (assume remoteShell is available)
remoteComp = remoteShell.host_computer
if remoteComp == null then
    exit("No remote shell available")
end if

// Start search from root
rootFolder = remoteComp.File("/")
if rootFolder == null then
    exit("Cannot access root directory")
end if

searchFolder(rootFolder, "", 0)

print("Search complete.")
