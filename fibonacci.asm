jmp main
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
int2str:
endbr64
push rbp
mov rbp, rsp
push rcx
push rsi
push rax
push rbx
push 0
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
main:
.store limittxt "Enter limit: "
.store limit "0\x00\x00\x00\x00\x00\x00\x00\x00\x00"
.store findtxt "Calculated fibonacci sequence sum: "
.store sum "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
.store enter "\x0a"
mov rax, 1
mov rsi, limittxt
mov rdx, 13
syscall
xor rax, rax
mov rsi, limit
mov rdx, 10
syscall
mov rax, rsi
mov rbx, 0xa
call str2int
mov rdx, rax
xor rax, rax
mov rbx, 1
xor rsi, rsi
xor rdi, rdi
fibonacci_loop:
push rax
add rax, rbx
pop rcx
mov rbx, rcx
inc rsi
cmp rsi, rdx
add rdi, rax
jne fibonacci_loop
mov rax, 1
mov rsi, findtxt
mov rdx, 35
syscall
mov rax, rdi
mov rbx, sum
call int2str
mov rax, 1
mov rsi, sum
mov rdx, 144
syscall
mov rdx, 1
mov rsi, enter
syscall
mov rax, 60
xor rdi, rdi
syscall
