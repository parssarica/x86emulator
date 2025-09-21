.store txt "Hello, you there"
mov rax, 9
mov rsi, 100
syscall
push rax
mov r8, rax
mov rax, 0
mov rbx, txt
write_loop:
mov [r8], [rbx]
cmp rax, 16
inc rax
inc r8
inc rbx
jne write_loop
pop r8
mov rdi, r8
mov rsi, 100
mov rax, 11
syscall
xor rdi, rdi
mov rsi, 16
syscall

mov rax, 60
xor rdi, rdi
syscall
