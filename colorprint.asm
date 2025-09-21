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
.store black "\x1b[90m1 - BLACK\x0a\x1b[00m"
.store red "\x1b[91m2 - RED\x0a\x1b[00m"
.store green "\x1b[92m3 - GREEN\x0a\x1b[00m"
.store yellow "\x1b[93m4 - YELLOW\x0a\x1b[00m"
.store blue "\x1b[94m5 - BLUE\x0a\x1b[00m"
.store purple "\x1b[95m6 - PURPLE\x0a\x1b[00m"
.store turquoise "\x1b[96m7 - TURQUOISE\x0a\x1b[00m"
.store white "\x1b[97m8 - WHITE\x0a\x1b[00m"
.store txt "Enter color: "
.store inputreq "Enter text: "
.store colorchoosen "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
.store textinput "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
.store unknowncolor "Unknown color ID taken. Exiting...\x0a"
main:
mov rax, 1
mov rsi, black
mov rdx, 20
syscall
mov rsi, red
mov rdx, 18
syscall
mov rsi, green
mov rdx, 20
syscall
mov rsi, yellow
mov rdx, 21
syscall
mov rsi, blue
mov rdx, 19
syscall
mov rsi, purple
mov rdx, 21
syscall
mov rsi, turquoise
mov rdx, 24
syscall
mov rsi, white
mov rdx, 20
syscall
mov rsi, txt
mov rdx, 13
syscall
xor rax, rax
mov rsi, colorchoosen
mov rdx, 15
syscall
mov rax, rsi
mov rbx, 0xa
call str2int
mov rcx, rax
mov rax, 1
mov rsi, inputreq
mov rdx, 12
syscall
xor rax, rax
mov rsi, textinput
mov rdx, 70
syscall
mov rdx, 5
cmp rcx, 1
je black_txt
cmp rcx, 2
je red_txt
cmp rcx, 3
je green_txt
cmp rcx, 4
je yellow_txt
cmp rcx, 5
je blue_txt
cmp rcx, 6
je purple_txt
cmp rcx, 7
je turquoise_txt
cmp rcx, 8
je white_txt
jmp unknown_color
black_txt:
mov rsi, black
jmp print
red_txt:
mov rsi, red
jmp print
green_txt:
mov rsi, green
jmp print
yellow_txt:
mov rsi, yellow
jmp print
blue_txt:
mov rsi, blue
jmp print
purple_txt:
mov rsi, purple
jmp print
turquoise_txt:
mov rsi, turquoise
jmp print
white_txt:
mov rsi, white
print:
mov rax, 1
syscall
mov rsi, textinput
mov rdx, 69
syscall
mov rsi, red
add rsi, 13
mov rdx, 5
syscall
exit:
mov rax, 60
xor rdi, rdi
syscall
unknown_color:
mov rax, 1
mov rsi, unknowncolor
mov rdx, 35
syscall
jmp exit
