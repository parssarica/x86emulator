.store mystr "123\x0a"
mov rax, 1
mov rdi, mystr
mov rsi, 4
syscall
mov rax, 60
mov rdi, 314
syscall
