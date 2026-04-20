# Grey Hack Scripts

A collection of GreyScript tools for the game [Grey Hack](https://store.steampowered.com/app/605230/Grey_Hack/).

## Repository Structure

```
scripts/          # Full-featured versions with verbose output and error handling
├── exploit/      # Exploitation tools
├── post-exploit/ # Post-exploitation utilities
├── recon/        # Reconnaissance tools
├── utils/        # Shared utility libraries
└── wifi/         # WiFi cracking tools

mini/             # Compact versions optimized for size
├── exploit/
├── post-exploit/
├── recon/
└── wifi/
```

## Scripts Overview

### Exploitation
| Script | Description | Usage |
|--------|-------------|-------|
| `exploit_payload.gs` | Auto-exploit: net_use → dump_lib → scan → overflow | `exploit_payload.gs [targetIp] [targetPort]` |
| `exploit_payload_mini.gs` | Compact version (~1.1KB) | Same as above |

### Reconnaissance
| Script | Description | Usage |
|--------|-------------|-------|
| `recon_ports.gs` | Scan router ports and LAN devices | `recon_ports.gs [targetIp]` |
| `recon_ports_mini.gs` | Compact version (~784 chars) | Same as above |

### WiFi Cracking
| Script | Description | Usage |
|--------|-------------|-------|
| `wifi_crack.gs` | Full WiFi crack: airmon + aireplay + aircrack | `wifi_crack.gs [targetBssid] [targetEssid]` |
| `wifi_crack_mini.gs` | Compact version (~1.1KB) | Same as above |

### Post-Exploitation
| Script | Description | Usage |
|--------|-------------|-------|
| `passwd_grab.gs` | Extract password hashes from /etc/passwd | `passwd_grab.gs [targetIp] [port] [user] [pass]` |
| `passwd_grab_mini.gs` | Compact version | Same as above |

### Utilities (utils/)
These are shared libraries imported by other scripts:

- `wipe_logs.gs` — `wipeLogs(targetComputer)` clears auth, syslog, kern logs
- `sanitize_ip.gs` — `sanitize(text, myIp)` strips your IP from output strings

## Installation

Since Grey Hack computers cannot access external Git repositories, you must manually add these scripts:

### Method 1: Code Editor (Recommended)
1. Open the **Code Editor** app in-game
2. Create a new file and copy-paste the script content
3. Save to `/home/player/scripts/` (full) or `/home/player/mini/` (mini)
4. Maintain the subdirectory structure (exploit/, recon/, etc.)

### Method 2: In-Game Terminal
```bash
mkdir /home/player/scripts /home/player/mini
cd /home/player/scripts
mkdir exploit post-exploit recon utils wifi
cd /home/player/mini
mkdir exploit post-exploit recon wifi
```

## Dependencies

| Script | Required Libraries |
|--------|-------------------|
| `exploit_payload.gs` | `/lib/metaxploit.so` |
| `wifi_crack.gs` | `/lib/crypto.so` |
| `passwd_grab.gs` | `/lib/crypto.so` (optional) |
| `recon_ports.gs` | None (native functions) |

## Mini vs Full Versions

| Feature | Full Version | Mini Version |
|---------|-------------|--------------|
| Size | ~2-3KB | ~700-1200 chars |
| Output | Verbose with `[*]`, `[+]`, `[-]` prefixes | Minimal |
| Error Handling | Detailed error messages | Basic exit codes |
| Comments | Extensive inline comments | Minimal |
| Best For | Learning, debugging, reliability | Speed, stealth, size constraints |

## Security Features

All scripts implement:
- **Log wiping** — Automatically clears `/var/log/auth.log`, `syslog`, `kern.log` after execution
- **IP sanitization** — Strips your LAN IP from any output before printing
- **No hardcoded credentials** — Uses `user_input()` for all sensitive data
- **Type checking** — Validates shell connections and file handles before use

## Quick Reference

```bash
# Port scan
./scripts/recon/recon_ports.gs 192.168.1.1

# WiFi crack
./scripts/wifi/wifi_crack.gs AA:BB:CC:DD:EE:FF MyNetwork

# Exploit
./scripts/exploit/exploit_payload.gs 203.0.113.5 8080

# Password grab
./scripts/post-exploit/passwd_grab.gs 203.0.113.5 22 root hunter2
```

## Size Limits

| Limit | Value | Context |
|-------|-------|---------|
| **Source files** | 160,000 characters | Code Editor in-game |
| **Compiled binaries** | 80,000 characters | After `build` command |

The mini versions are optimized with minification + obfuscation to fit comfortably within these limits.

## Greybel Extension Setup

This repository is configured for use with the **Greybel** VS Code extension:

1. Install the Greybel extension in Windsurf/VS Code
2. Configure settings (`Ctrl+,` → search "Greybel"):
   - **Transpiler › Minify**: Enable
   - **Transpiler › Obfuscation**: Enable  
   - **Transpiler › Uglify**: Enable
   - **Language › Version**: "Latest"
3. Use `Ctrl+Shift+B` to build/minify scripts before copying to game

See `.windsurf/GREYBEL_CONFIG.md` for complete configuration details.

## License

These scripts are provided as-is for educational and gameplay purposes within Grey Hack.

---

**Note**: GreyScript is a fork of MiniScript. It is NOT Python or JavaScript — see [GreyScript documentation](https://codedocs.ghtools.xyz) for language reference.
