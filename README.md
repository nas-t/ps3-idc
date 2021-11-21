# ps3-idc
A collection of old PS3 IDC scripts for IDA which been collecting dust

## Usage
Load your elf or dump, then excute a script. Dumps need to be rebased to proper address.
* ps3_analyze_ldr.idc -> Secure LDRs
* ps3_analyze_self.idc -> Userland Executables, e.g. decrypted game SELFs
* ps3_analyze_fw_prx.idc -> VSH modules
* ps3_analyze_game_sprx.idc -> Game Modules
* ps3_analyze_lv2_dump.idc -> analyze a LV2 dump, put a proper base on load or rebase before running
