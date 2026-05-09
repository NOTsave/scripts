# Configuration Guide

## Overview
The botnet reads configuration from `botnet_config.gs`. Key parameters are defined there.

## Critical Parameters

### `hard_depth_cap` (default: 5)
Absolute maximum propagation depth. **Worms MUST stop at this depth regardless of settings.**

- Higher = wider infection, higher detection risk
- Must be ≥ `default_max_depth` 
- Prevents runaway propagation and resource exhaustion

**Change:** Edit `botnet_config.gs`, restart all bots

### `default_max_depth` (default: 3)
Recommended propagation depth. Worms stop here unless deployment specifies otherwise.

- Balances coverage and detection risk
- Typical settings: 2 (stealth) to 5 (aggressive)

### `spread_delay` (default: 30 seconds)
Delay between exploitation attempts on a single bot.

- Lower = faster propagation, higher detection risk
- Higher = slower spread, lower network noise
- Typical: 10-60 seconds

### `hard_depth_cap` vs `default_max_depth` 
`hard_depth_cap` is a hard limit: worms WILL STOP here
`default_max_depth` is a soft target: deployment can override
Example:

```
hard_depth_cap = 5 (absolute max)
default_max_depth = 3 (typical deployment)

Worm A started with depth 3: stops at depth 3 (respects default)
Worm B started with depth 4: continues to depth 5 (respects hard cap)
Worm C somehow at depth 5: stops, refuses to propagate (respects hard cap)
```

## Security Parameters

### `max_retries` (default: 3)
Number of connection attempts before giving up.

- Higher = more reliable but more detectable
- Set 2-5 typically

### `base_delay` (default: 1 second)
Initial exponential backoff delay for retries.

- Actual delays: 1s, 2s, 4s, 8s, 16s, ...
- Capped at 30s max (see `backoff_max`)

## Allowed Scripts

The `allowed_scripts` list whitelists scripts that bots can execute:

```greyscript
allowed_scripts = [
    "/bin/slave.gs",
    "/bin/worm.gs",
    "/scripts/utils/forensics/wipe_logs.gs",
    "/scripts/utils/file_search.gs",
    "/scripts/utils/find_lib.gs",
    "/scripts/utils/accessLevel.gs"
]
```

To add a new script:
1. Add full path to `allowed_scripts` in `botnet_config.gs` 
2. Restart all bots
3. Master can now send `run <new_script> [args]` 

## Changing Configuration

### Manual (simple)
1. Edit `botnet_config.gs` 
2. Restart slave: `kill /bin/slave.gs` on target
3. Changes take effect immediately

### Automated (future)
1. Master sends `update` command with new config
2. Bots download and apply (not yet implemented)

## Security Settings

### Path Whitelist
Only these directories are accessible to bot operations:
- `/root/.botnet/` - Botnet data and state
- `/scripts/utils/` - Utility scripts
- `/scripts/tools/` - Utility tools  
- `/bin/` - Executable binaries
- `/lib/` - Shared libraries
- `/tmp/` - Temporary files

### Command Validation
All commands are validated before execution:
- Must be in allowed command list
- Script paths must be whitelisted
- No shell metacharacters allowed
- Maximum command length enforced

### Encryption Settings
- C2 communication uses CRYSTALS-Kyber-512 (post-quantum)
- Passwords stored with Kyber encryption (XOR deprecated)
- Depth markers encrypted with master's public key

## Troubleshooting

### Worms not propagating far
Check `default_max_depth` and `hard_depth_cap`:
```greyscript
if depth >= max_depth then
    log_master("Max depth reached, sleeping", "INFO")
    while true; wait(60); end while
end if
```

If bots are stuck at depth < 3, increase `default_max_depth`.

### Bots being detected quickly
Reduce `spread_delay` (more cautious exploitation) and `hard_depth_cap` (limit overall spread).

### Network congestion
Increase `spread_delay` and `base_delay` to space out connection attempts.

### Commands failing validation
Check that:
- Script is in `allowed_scripts` list
- Path uses only whitelisted directories
- No special characters like `; | & $ ` < >`
- Command length under 1024 bytes

### Migration issues
If Kyber migration fails:
- Check backup file: `/root/.botnet/backdoor_pass.xor.bak`
- Verify master public key exists
- Check log files for specific error messages

## Performance Tuning

### For Stealth Operations
```
hard_depth_cap = 2
default_max_depth = 2
spread_delay = 60  # 1 minute between attempts
max_retries = 2
```

### For Rapid Propagation
```
hard_depth_cap = 5
default_max_depth = 4
spread_delay = 10  # 10 seconds between attempts
max_retries = 5
```

### For Testing/Development
```
hard_depth_cap = 1
default_max_depth = 1
spread_delay = 5
max_retries = 1
```

## File Locations

### Configuration Files
- `/root/.botnet/botnet_config.gs` - Main configuration
- `/root/.botnet/master.pub` - Master public key
- `/root/.botnet/slave.priv` - Slave private key
- `/root/.botnet/slave.pub` - Slave public key

### Runtime Data
- `/root/.botnet/infected.txt` - List of infected IPs
- `/root/.botnet/depth_markers/` - Worm depth tracking
- `/root/.botnet/commands/` - Incoming encrypted commands
- `/root/.botnet/responses/` - Outgoing encrypted responses
- `/root/.botnet/log.txt` - Botnet activity log

### Security Files
- `/root/.botnet/backdoor_pass.enc` - Encrypted backdoor password
- `/root/.botnet/backdoor_pass.xor.bak` - Migration backup
- `/root/.botnet/slave.pid` - Process ID file
