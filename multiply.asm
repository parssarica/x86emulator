get_length_int:
endbr64
push rbp
mov rbp, rsp
push rax
push rbx
mov rcx, -1
mov rbx, 10
fnc_loop:
inc rcx
lea rax, [rax/(rbx*10)]
cmp rax, 10
jl fnc_loop
pop rbx
pop rax
leave
ret
.store input1 "                                                                                                                                                                                                                                                                "
.store input2 "                                                                                                                                                                                                                                                                "
.store result "Result: "
.store q1 "Enter first number: "
.store q2 "Enter second number: "
.store res "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
.store enter_character "\x0a"
mov rax, 1
xor rdi, rdi
mov rsi, q1
mov rdx, 20
syscall
xor rax, rax
inc rdi
mov rsi, input1
mov rdx, 256
syscall
mov rax, 1
xor rdi, rdi
mov rsi, q2
mov rdx, 21
syscall
xor rax, rax
inc rdi
mov rsi, input2
mov rdx, 256
syscall
xor rax, rax
mov r8, input1
conversion_loop0:
sub [r8], 48
add rax, [r8]
lea rax, [rax*10]
inc r8
cmp [r8], 0xa
jne conversion_loop0
lea rax, [rax/10]
xor rbx, rbx
mov r8, input2
conversion_loop1:
sub [r8], 48
add rbx, [r8]
lea rbx, [rbx*10]
inc r8
cmp [r8], 0xa
jne conversion_loop1
lea rbx, [rbx/10]
lea rax, [rax*rbx]
push rax
mov rax, 1
mov rsi, result
mov rdi, 1
mov rdx, 8
syscall
pop rax
mov r8, rax
call get_length_int
convert_loop:
mov rax, 1
mov rsi, res
mov rdi, 1
mov rdx, 256
syscall
exit:
mov rax, 60
xor rdi, rdi
syscall
