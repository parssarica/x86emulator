.store msg1 "Enter your password: \x00"
.store wrong "Wrong!\x0a"
.store correct "Correct!\x0a"
.store passwd "supersecret"
.store input "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
correct_func:
mov rax, 1
mov rdi, 1         
mov rsi, correct
mov rdx, 9         
syscall                
mov rax, 0x3C
mov rdi, 0         
syscall
mov rax, 1
mov rdi, 1          
mov rsi, msg1 
mov rdx, 0x16       
syscall                 
mov rax, 0
mov rdi, 0          
mov rsi, input    
mov rdx, 0x10        
syscall                 
mov rdi, passwd
mov rsi, input
mov rcx, 0x0B
repe cmpsb
jz correct_func
mov rax, 1
mov rdi, 1          
mov rsi, wrong 
mov rdx, 7          
syscall
mov rax, 0x3C 
mov rdi, 0          
syscall         
