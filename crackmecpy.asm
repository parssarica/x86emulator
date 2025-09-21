jmp main
print:
mov rdx, rsi
mov rsi, rdi
mov rax, 1
mov rdi, 1
syscall
ret
copy:
xor rcx, rcx
loc_401143:
inc rcx
lea rdx, [rdi+rcx]
test rdx, rdx
jnz loc_401143
mov rax, rcx
ret
.store aYouLikeFlagsIL "You like flags? I like flags! Can I have a zero one please: \x00"
.store aIDonTThinkThat "I don\x27t think that\x27s the flag I was looking for...\x0a"
.store aThanksThatSPer "Thanks, that\x27s perfect!\x0a\x00"
.store inputstr "\x00\x00\x00\x00\x00\x00\x00\x00"
main:
mov rdi, aYouLikeFlagsIL 
call copy
mov rdi, aYouLikeFlagsIL 
mov rsi, rax        
call print
mov rax, 0
mov rdi, 0          
mov rsi, inputstr 
mov rdx, 8          
syscall                 
mov rax, 7
sub rax, 0xA
mov rbx, 3
add rax, rbx
pushfq
pop r10
and r10, 0xF0
lea rax, inputstr
mov rcx, 5
xor rdi, rdi
loc_401067:                           
cmp rcx, 0
jz loc_401084
xor rbx, rbx
or rbx, [rax]
shl rbx, rcx
and r10, rbx
push r10
inc rax
dec rcx
popfq
jz loc_401067
jmp loc_401089
loc_401084:                           
push r10
popfq
jz loc_4010B6
loc_401089:                           
mov rdi, aIDonTThinkThat 
call copy
mov rdi, aIDonTThinkThat 
mov rsi, rax        
call print
mov rax, 3Ch 
mov rdi, 0          
syscall                 
loc_4010B6:                           
mov rdi, aThanksThatSPer 
call copy
mov rdi, aThanksThatSPer 
mov rsi, rax        
call print
mov rax, 0x3c 
mov rdi, 0          
syscall                 
