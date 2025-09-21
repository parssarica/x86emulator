mov rax, 0x100
loop:
dec rax
cmp rax, 0
jne loop
mov rbx, 0x314
mov rcx, rbx
mov rdx, rbx
hlt
