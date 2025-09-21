int2str:
endbr64
push rbp
mov rbp, rsp
push rcx
push rsi
push rax
push rbx
mov rcx, 10
xor rsi, rsi
conversion_loop_int2str:
xor rdx, rdx
div rcx
push rdx
cmp rax, 0
inc rsi
jne conversion_loop_int2str
dec rsi
conversion_loop_int2str2:
pop rax
add rax, 48
mov [rbx], rax
cmp rsi, 0
dec rsi
inc rbx
jne conversion_loop_int2str2
pop rbx
pop rax
pop rsi
pop rcx
leave
ret
