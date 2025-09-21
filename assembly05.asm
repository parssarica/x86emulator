waitsec:
push rax
mov rax, 0xff
waitsecloop:
dec rax
cmp rax, 0
jne waitsecloop
pop rax
pop rbx
add rbx, 1
cmp rsi, rcx
jmp rbx
main:
.store agenttxt "Hello Agent 1337\x0a1337 billion dollars has been captured by bad people.\x0aYou should recover that 1337 billion dollars. Enter the password, get it\x0a\x0aEnter the password: \x00"
mov rax, 0xa6
mov rcx, rax
mov rax, 1
mov rsi, agenttxt
mov rdx, 1
mov rdi, 1
print_loop:
syscall
inc rsi
cmp rsi, rcx
push rip
jmp waitsec
jne print_loop
.store buffer "                                                                                                                                                                                                                                                                "
xor rax, rax
mov rsi, buffer
mov rdx, 128
syscall
.store password "CTF{S33CR3T_P0SSW0RD_1337_3L1T3}\x0a"
mov rcx, 0
mov rax, password
mov rbx, buffer
compare_loop:
cmp [rax], [rbx]
jne wrong_password
inc rax
inc rbx
inc rcx
cmp rcx, 33
jne compare_loop
.store correct "Correct password!\x0a"
mov rax, 1
mov rdx, 18
mov rsi, correct
mov rdi, 1
jmp exit
wrong_password:
.store correct "Wrong password! Try again.\x0a"
mov rax, 1
mov rdx, 0x1b
mov rsi, correct
mov rdi, 1
exit:
syscall
nop
nop
mov rax, 60
mov rdi, 1
syscall
