multiply:
push rbp
mov rbp, rsp
push rsi
mov rsi, 1
multiply_loop:
add rax, rax
inc rsi
cmp rsi, rbx
jne multiply_loop
pop rsi
leave
ret
main:
mov rax, 123131
mov rbx, 237
call multiply
mov rax, 6486468468
mov rbx, 4644848864
lea rax, [rax*rbx+314]
mov rax, 25
jmp rax
exit:
mov rax, 60
mov rdi, 0
syscall
endbr64
jmp multiplication
nop
nop
nop
multiplication:
mov rax, 0x2
mov rbx, 0x4
mul rbx
mov rcx, 0x4
div rcx
test rax, rax
.store waitstr "Waiting...\x0a"
mov rcx, 0xffff
mov rax, 1
mov rsi, waitstr
mov rdx, 11
syscall
loop $
jmp exit
