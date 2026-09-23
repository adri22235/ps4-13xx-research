# PS4 13.xx / 14.00 Security Research

Joint research by Adrián García Casado (@adri22235) and H4SS9M

## Status

- **2026-09-24**: FW 14.00 kernel offsets added from Al-Azif (Scene-Collective)
- **2026-09-21**: PS4 13.04 jailbroken with GoldHEN v2.4b18.12
- **2026-09-19**: PS4 13.04 jailbroken with HEN 2.2.0
- **2026-09-16**: Sony releases FW 14.00

## Research Areas

### MP4 Heap Overflow (H4SS9M)
- SHAREfactory/Media Player crash via malformed MP4
- COVR handler overflow in ffmepg_prx.prx (FFmpeg 2018)
- Full report: SHAREFactory.pdf

### WebKit (Jordy)
- Arbitrary r/w confirmed on FW 13.04 and 13.52
- SSV UAF chain: SSV build → addrof leak → fake cell → R/W → sysent hijack → ucred patch → rootvnode

### Kernel Offsets (Adrián)
- Full 13.04 offsets: https://github.com/adri22235/ps4-suid-scanner
- Full 14.00 offsets: `1400_offsets.txt` (source: Al-Azif, Scene-Collective/ps4-hen)

### 14.00 Key Offsets
```
PRISON0    = 0x0111FA18  (unchanged since 13.00)
ROOTVNODE  = 0x02136E90  (unchanged since 13.00)
SYSENT     = 0x01102B70  (same as 13.04)
ALLPROC    = 0x01B28538  (same as 13.04)
```
Data addresses stable across 13.00–14.00. Function offsets shifted (memcpy, copyin/copyout, etc).

### exFAThax v2
- Kernel panic confirmed on FW 13.04
- Build script: `build_exfathax_v2_image.py`

### IPMI 0-day (H4SS9M)
- Use-After-Scope in syscall 622 (sys_ipmimgr_call)
- Present in: 11.50, 13.02, 13.04, 13.50, 13.52
- Status: Pending MasterMaind HackerOne disclosure

## Credits
- Adrián García Casado — offsets, gadgets, analysis
- H4SS9M — MP4 exploit research, IPMI 0-day discovery
- Al-Azif — 14.00 kernel offsets
- SiSTRo — GoldHEN v2.4b18.12
- zecoxao — kernel dumps
- Pharaoh2k — offset verification
- MasterMaind (@ASaudidos) — BD-J escape confirmation
