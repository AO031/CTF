#!/usr/bin/env python3

'''
    author: GeekCmore
    time: 2025-10-05 09:14:38
'''
from pwn import *

filename = "expect_number_patched"
libcname = "/home/a0m1ghty/.config/cpwn/pkgs/2.35-0ubuntu3/amd64/libc6_2.35-0ubuntu3_amd64/lib/x86_64-linux-gnu/libc.so.6"
host = "127.0.0.1"
port = 1337
container_id = ""
proc_name = ""
elf = context.binary = ELF(filename)
if libcname:
    libc = ELF(libcname)
gs = '''
b main
set debug-file-directory /home/a0m1ghty/.config/cpwn/pkgs/2.35-0ubuntu3/amd64/libc6-dbg_2.35-0ubuntu3_amd64/usr/lib/debug
set directories /home/a0m1ghty/.config/cpwn/pkgs/2.35-0ubuntu3/amd64/glibc-source_2.35-0ubuntu3_all/usr/src/glibc/glibc-2.35
'''
'''alternation
python
import gdb
output = gdb.execute("info proc mappings", to_string=True)
for line in output.split('\\n'):
    if 'libc.so.6' in line:
        base_addr = int(line.split()[0], 16)
        cmd = "add-symbol-file /home/a0m1ghty/.config/cpwn/pkgs/2.35-0ubuntu3.7/amd64/libc6-dbg_2.35-0ubuntu3.7_amd64/usr/lib/debug/.build-id/96/2015aa9d133c6cbcfb31ec300596d7f44d3348.debug -o {}".format(hex(base_addr))
        gdb.execute(cmd)
        break
end
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript = gs)
    elif args.REMOTE:
        return remote(host, port)
    elif args.DOCKER:
        import docker
        from os import path
        p = remote(host, port)
        client = docker.from_env()
        container = client.containers.get(container_id=container_id)
        processes_info = container.top()
        titles = processes_info['Titles']
        processes = [dict(zip(titles, proc)) for proc in processes_info['Processes']]
        target_proc = []
        for proc in processes:
            cmd = proc.get('CMD', '')
            exe_path = cmd.split()[0] if cmd else ''
            exe_name = path.basename(exe_path)
            if exe_name == proc_name:
                target_proc.append(proc)
        idx = 0
        if len(target_proc) > 1:
            for i, v in enumerate(target_proc):
                print(f"{i} => {v}")
            idx = int(input(f"Which one:"))
        import tempfile
        with tempfile.NamedTemporaryFile(prefix = 'cpwn-gdbscript-', delete=False, suffix = '.gdb', mode = 'w') as tmp:
            tmp.write(f'shell rm {tmp.name}\n{gs}')
        print(tmp.name)
        run_in_new_terminal(["sudo", "gdb", "-p", target_proc[idx]['PID'], "-x", tmp.name])
        return p
    else:
        return process(elf.path)

p = start()

# Your exploit here

p.interactive()