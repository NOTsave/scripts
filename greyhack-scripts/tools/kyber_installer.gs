// kyber_installer.gs - fixed without backslashes
import_code("/lib/kyber_lib.gs")

print("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
print("|                                                                   |")
print(":  _______                         __  __         __                :")
print("| |     __|.----.-----.--.--.     |  |/  |.--.--.|  |--.-----.----. |")
print(": |    |  ||   _|  -__|  |  |     |     < |  |  ||  _  |  -__|   _| :")
print("| |_______||__| |_____|___  |     |__|\__||___  ||_____|_____|__|   |")
print(":                    |_____|             |_____|                    :")
print("|                                                                   |")
print(":       Securing SSH passwords with post-quantum cryptography       :")
print("|                                                       by Arlin143 |")
print("-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")

print("Generating a fresh keypair")
key = Kyber.keygen()

comp = get_shell.host_computer
comp.create_folder("/", "server")
comp.create_folder("/server", "conf")
comp.touch("/server/conf", "sshd.conf")
nl = char(10)
dq = char(34)

// Build JSON config without backslashes
sshdconf = "{" + nl
sshdconf = sshdconf + "  " + dq + "encryption_enabled" + dq + ": true," + nl
sshdconf = sshdconf + "  " + dq + "message_encrypted_conn" + dq + ": true," + nl
sshdconf = sshdconf + "  " + dq + "path_enc" + dq + ": " + dq + "/server/encode.src" + dq + "," + nl
sshdconf = sshdconf + "  " + dq + "path_dec" + dq + ": " + dq + "/server/decode.bin" + dq + nl
sshdconf = sshdconf + "}"

if comp.File("/server/conf/sshd.conf").set_content(sshdconf) then 
    print("Successfully written sshd config file!") 
else 
    exit("Could not write sshd config file!")
end if

// Read kyber library content
kyber_file = comp.File("/lib/kyber_lib.gs")
if not kyber_file then exit("kyber_lib.gs not found in /lib/")
kyber_code = kyber_file.get_content
if kyber_code == null then exit("Failed to read kyber_lib.gs")

// Encoding script (public key)
encoding = nl + "Encode = function(input)" + nl + "  return Kyber.encrypt(" + dq + key.public + dq + ", input)" + nl + "end function"
comp.touch("/server", "encode.src")
if comp.File("/server/encode.src").set_content(kyber_code + nl + encoding) then 
    print("Successfully written encoding source code!") 
else 
    exit("Could not write encoding source code!")
end if

// Decoding script (private key)
decoding = nl + "Decode = function(ciphertext)" + nl + "  return Kyber.decrypt(" + dq + key.private + dq + ", ciphertext)" + nl + "end function"
comp.touch("/server", "decode.bin.src")
comp.touch("/server", "decode.bin")
if comp.File("/server/decode.bin.src").set_content(kyber_code + nl + decoding) then 
    print("Successfully written decoding source code!") 
else 
    exit("Could not write decode source file!")
end if

// Build decode binary
if get_shell.build("/server/decode.bin.src", "/server", false) == "" then 
    print("Successfully built decoding script!") 
else 
    exit("Could not build decoding script from source!")
end if

// Delete source for security
src_file = comp.File("/server/decode.bin.src")
if src_file then
    if src_file.delete == "" then 
        print("Successfully deleted decoding source code!") 
    else 
        exit("Could not delete decoding source code! (Leaks private key!)")
    end if
end if

print("<color=green>Done installing encoding/decoding scripts!</color>")
