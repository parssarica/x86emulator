jmp overflow2
prg_loop:
mov rax, 9
mov rsi, 3064
syscall
mov rdx, rcx
inc rdx
write_loop:
mov [rcx], rdx
inc rcx
inc rdx
cmp rcx, rsi
jne write_loop
push 0xabcdefabcdefabcd
push 0xabcdefabcdefabcd
mov rax, 60
syscall
overflow2:
cmp rsp, 0
je prg_loop
push 0xabcdefabcdefabcd
jmp overflow2
