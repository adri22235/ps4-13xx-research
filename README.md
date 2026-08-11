# PS4 13.xx Security Research

Joint research by Adrián García Casado (@adri22235) and H4SS9M

## Research Areas

### MP4 Heap Overflow (H4SS9M)
- SHAREfactory/Media Player crash via malformed MP4
- COVR handler overflow in ffmepg_prx.prx (FFmpeg 2018)
- Full report: SHAREFactory.pdf

### WebKit (Jordy)
- Arbitrary r/w confirmed on FW 13.04 and 13.52
- Stage 2 in progress

### Kernel Offsets (Adrián)
- Full 13.04 offsets: https://github.com/adri22235/ps4-suid-scanner

## Credits
- Adrián García Casado — offsets, gadgets, analysis
- H4SS9M — MP4 exploit research
- zecoxao — kernel dumps
- Pharaoh2k — offset verification
