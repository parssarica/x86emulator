str2int:
endbr64
push rbp
mov rbp, rsp
push r8
mov r8, rax
xor rax, rax
conversion_loop0:
sub [r8], 48
add rax, [r8]
lea rax, [rax*10]
inc r8
cmp [r8], rbx
jne conversion_loop0
lea rax, [rax/10]
pop r8
leave
ret
main:
.store pi "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679\x00"
mov rax, pi
mov rbx, 0
call str2int
mov rax, 60
xor rdi, rdi
syscall
