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
main:
.store welcometxt "Welcome to number guessing game!\x0a\x0a"
.store rangemin "Enter min range: "
.store rangemax "Enter max range: "
.store minrange "0\x00\x00\x00\x00\x00\x00\x00\x00\x00"
.store maxrange "0\x00\x00\x00\x00\x00\x00\x00\x00\x00"
.store numreq "Enter a number: "
.store num "0\x00\x00\x00\x00\x00\x00\x00\x00\x00"
.store randnum "\x00"
.store equal "Well done! It's same.\x0a"
.store wrong "Wrong. Maybe next time.\x0a"
.store notsame "Min and max range can't be same. Exiting...\x0a"
mov rax, 1
mov rdx, 34
mov rsi, welcometxt
syscall
mov rsi, rangemin
mov rdx, 17
syscall
xor rax, rax
mov rsi, minrange
mov rdx, 10
syscall
mov rax, rsi
mov rbx, 0xa
call str2int
mov r8, rax
mov rax, 1
mov rdx, 17
mov rsi, rangemax
syscall
xor rax, rax
mov rsi, maxrange
mov rdx, 10
syscall
mov rax, maxrange
call str2int
mov r9, rax
cmp r8, r9
je same_exit
mov rax, 1
mov rdx, 0x10
mov rsi, numreq
syscall
xor rax, rax
mov rdx, 10
mov rsi, num
syscall
mov rax, rsi
call str2int
mov r10, rax
mov rax, 318
mov rdi, randnum
mov rsi, 1
xor rdx, rdx
syscall
push r9
sub r9, r8
mov rcx, r9
pop r9
mov rax, [randnum]
lea rax, [rax%rcx]
add rax, r8
cmp rax, r10
mov rax, 1
jne notequal
equal:
mov rsi, equal
mov rdx, 22
jmp exit
notequal:
mov rsi, wrong
mov rdx, 24
exit:
syscall
mov rax, 60
xor rdi, rdi
syscall
same_exit:
mov rax, 1
mov rsi, notsame
mov rdx, 45
jmp exit
