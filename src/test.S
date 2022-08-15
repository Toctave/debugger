        .text
        .globl _start
_start:
        mov $13, %edx            ;; length
        mov hello, %ecx
        mov $1, %ebx
        mov 4, %eax

        int 0x80
        ret

        .data
hello:
        .ascii "Hello, world\n"
