waitsec:
endbr64
push rbp
mov rbp, rsp
push rcx
mov rcx, 0xfff
loop $
pop rcx
leave
ret
strlen:
endbr64
push rbp
mov rbp, rsp
mov rbx, rax
strlenloop:
cmp [rax], 0
inc rax
inc rbx
jne strlenloop
leave
ret
print_slow:
endbr64
push rbp
mov rbp, rsp
push rax
push rdi
push rdx
push rsi
mov rax, rsi
call strlen
mov rax, 1
mov rdi, 0
mov rdx, 1
print_loop:
syscall
inc rsi
cmp rsi, rbx
call waitsec
jne print_loop
pop rsi
pop rdx
pop rdi
pop rax
leave
ret
main:
.store agenttxt "Hello Agent 1337\x0a1337 billion dollars has been captured by bad people.\x0aYou should recover that 1337 billion dollars. Enter the password, get it\x0a\x0aEnter the password: \x00"
.store password "CTF{S33CR3T_P0SSW0RD_1337_3L1T3}\x0a\x00"
.store fail "Wrong password. Try again.\x0a\x00"
.store win "Correct password!\x0a\x00"
.store input "                                                                                                                                                                                                                                                                "
mov rsi, agenttxt
call print_slow
xor rax, rax
mov rsi, input
mov rdx, 0x100
xor rdi, rdi
syscall
mov rcx, password
cmp_loop:
cmp [rcx], [rsi]
inc rcx
inc rsi
jne wrong_password
correct_password:
mov rsi, win
jmp exit
wrong_password:
mov rsi, fail
exit:
call print_slow
mov rax, 60
mov rdi, 0
syscall
