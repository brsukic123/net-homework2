#!/usr/bin/env python
from pwn import *
sh = process('./ret2system')

sh.sendline()
sh.interactive()
