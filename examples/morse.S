.section .text
.global main
main:
  pushl %ebp
  movl %esp, %ebp

  # Caller-saved are %eax, %ecx, %edx. Anything else must be preserved by us

  movl $input, %esi   # esi will contain input position
  movl $output, %edi  # edi will contain output position

  loop:
    xorl %eax, %eax
    movb (%esi), %al    # Read byte from input to eax

    test %al, %al       # If it's a null byte - finish
    jz finish

    # TODO: Special symbols
    cmpb $'A, %al
    jb special_char

    subb $'A, %al      # Convert character byte to the alphabet index

    # Call encode_char(char *table, int letter, int *out_pos)
    pushl %edi
    pushl %eax
    pushl $morse_letters
    call encode_char
    add $8, %esp
    popl %edi

    incl %esi
    jmp loop             # Continue reading

  special_char:
    subb $' , %al
    pushl %edi
    pushl %eax
    pushl $space_char
    call encode_char
    add $8, %esp
    popl %edi

    incl %esi
    jmp loop

  finish:
    # Write output to stdout
    movl $4, %eax  # syscall 4
    # Syscall arguments
    movl $1, %ebx       # fd = 1 (stdout)
    movl $output, %ecx  # Pointer to output buffer
    movl $64, %edx      # Size of output buffer
    int $0x80

    # exit(0)
    movl $1, %eax
    movl $0, %ebx
    int $0x80

# void encode_char(int letter, int *out_pos)
encode_char:
  pushl %ebp
  movl %esp, %ebp

  xorl %eax, %eax
  movl 8(%ebp), %ecx  # Get start of the table
  movl 12(%ebp), %eax # Move letter to eax (eax is caller-saved) 
  movl 16(%ebp), %edi # Move output position to edi

  copy_char:
    movb (%ecx, %eax, 8), %dl  # Read the next character to the %dl
                                # %dl = *(%eax * 8 + %ecx)
    cmpb $' , %dl
    je done

    movb %dl, (%edi)
    incl %edi
    incl %ecx
    jmp copy_char

  done:
    # Write space to separate encoded chars
    movb $' , (%edi)
    incl %edi
    incl %ecx

    # copy new output position to 8(%ebp)
    # *out_pos = %edi
    movl %edi, 16(%ebp)
    leave
    ret

.section .rodata
  # Morse code lookup table
  morse_letters:
  .ascii ".-      ", "-...    ", "-.-.    ", "-..     " # A, B, C, D
  .ascii ".       ", "..-.    ", "--.     ", "....    " # E, F, G, H
  .ascii "..      ", ".---    ", "-.-     ", ".-..    " # I, J, K, L
  .ascii "--      ", "-.      ", "---     ", ".--.    " # M, N, O, P
  .ascii "--.-    ", ".-.     ", "...     ", "-       " # Q, R, S, T
  .ascii "..-     ", "...-    ", ".--     ", "-..-    " # U, V, W, X
  .ascii "-.--    ", "--..    "                         # Y, Z

  space_char:
  .ascii "..--.-  "

.section .data
  # Input storage
  input: .ascii "HELLO WORLD\0"

.section .bss
  # Output Morse code storage
  .comm output, 64

