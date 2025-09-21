mov rax, 1
test rax, rax
xor rax, rax
test rax, rax
mov rax, 2
test rax, rax
inc rax, rax
test rax, rax
mov rax, 0x7f
test rax, rax
mov rax, 0x80
test rax, rax
mov rax, 0xff
test rax, rax
mov rax, 0x100
test rax, rax
mov rax, 60
syscall
