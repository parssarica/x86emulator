#!/usr/bin/python3

import operator
import tomllib
import random
import time
import ast
import sys
import os
import re

class Register:
    def __init__(self, name, value, bits, parent=None):
        self.name = name
        self.value = value
        self.bits = bits
        self.parent = parent

registers = [Register("rax", 0, 64), Register("rbx", 0, 64), Register("rcx", 0, 64), Register("rdx", 0, 64), Register("rsi", 0, 64), Register("rdi", 0, 64), Register("rbp", 0, 64), Register("rsp", 0, 64), Register("r8", 0, 64), Register("r9", 0, 64), Register("r10", 0, 64), Register("r11", 0, 64), Register("r12", 0, 64), Register("r13", 0, 64), Register("r14", 0, 64), Register("r15", 0, 64), Register("rip", 0, 64), Register("rflags", 0, 64)]
registers += [Register("eax", 0, 32, parent=registers[0]), Register("ebx", 0, 32, parent=registers[1]), Register("ecx", 0, 32, parent=registers[2]), Register("edx", 0, 32, parent=registers[3]), Register("esi", 0, 32, parent=registers[4]), Register("edi", 0, 32, parent=registers[5]), Register("ebp", 0, 32, parent=registers[6]), Register("esp", 0, 32, parent=registers[7]), Register("r8d", 0, 32, parent=registers[8]), Register("r9d", 0, 32, parent=registers[9]), Register("r10d", 0, 32, parent=registers[10]), Register("r11d", 0, 32, parent=registers[11]), Register("r12d", 0, 32, parent=registers[12]), Register("r13d", 0, 32, parent=registers[13]), Register("r14d", 0, 32, parent=registers[14]), Register("r15d", 0, 32, parent=registers[15])]
registers += [Register("ax", 0, 16, parent=registers[0]), Register("bx", 0, 16, parent=registers[1]), Register("cx", 0, 16, parent=registers[2]), Register("dx", 0, 16, parent=registers[3]), Register("si", 0, 16, parent=registers[4]), Register("di", 0, 16, parent=registers[5]), Register("bp", 0, 16, parent=registers[6]), Register("sp", 0, 16, parent=registers[7]), Register("r8w", 0, 16, parent=registers[8]), Register("r9w", 0, 16, parent=registers[9]), Register("r10w", 0, 16, parent=registers[10]), Register("r11w", 0, 16, parent=registers[11]), Register("r12w", 0, 16, parent=registers[12]), Register("r13w", 0, 16, parent=registers[13]), Register("r14w", 0, 16, parent=registers[14]), Register("r15w", 0, 16, parent=registers[15])]
registers += [Register("al", 0, 8, parent=registers[0]), Register("bl", 0, 8, parent=registers[1]), Register("cl", 0, 8, parent=registers[2]), Register("dl", 0, 8, parent=registers[3]), Register("sil", 0, 8, parent=registers[4]), Register("dil", 0, 8, parent=registers[5]), Register("bpl", 0, 8, parent=registers[6]), Register("spl", 0, 8, parent=registers[7]), Register("r8b", 0, 8, parent=registers[8]), Register("r9b", 0, 8, parent=registers[9]), Register("r10b", 0, 8, parent=registers[10]), Register("r11b", 0, 8, parent=registers[11]), Register("r12b", 0, 8, parent=registers[12]), Register("r13b", 0, 8, parent=registers[13]), Register("r14b", 0, 8, parent=registers[14]), Register("r15b", 0, 8, parent=registers[15])]
registers += [Register("ah", 0, 8, parent=registers[0]), Register("bh", 0, 8, parent=registers[1]), Register("ch", 0, 8, parent=registers[2]), Register("dh", 0, 8, parent=registers[3])]
reg_list = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", "ah", "bh", "ch", "dh"]
reg_list_64bit = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags"]
reg_list_tmp = []
for i in reg_list:
    reg_list_tmp.append("[" + i + "]")
reg_list = reg_list + reg_list_tmp
labels = {}
strings = {}
breakpoints = []
code_file = ""
memory_size = 0
entrypoint = 0x0
base_address = 0x555555554000
debug_mode = False
heap_pointer = 0
last_command_exec = ""

def size_check(reg, val):
    if reg.bits == 64:
        if val > 18446744073709551615:
            raise Exception(f"Error: Can't move value higher than 18446744073709551615 to 64-bit register \"{reg.name}\".")
    elif reg.bits == 32:
        if val > 4294967295:
            raise Exception(f"Error: Can't move value higher than 4294967295 to 32-bit register \"{reg.name}\".")
    elif reg.bits == 16:
        if val > 65535:
            raise Exception(f"Error: Can't move value higher than 65535 to 16-bit register \"{reg.name}\".")
    elif reg.bits == 8:
        if val > 255:
            raise Exception(f"Error: Can't move value higher than 255 to 8-bit register \"{reg.name}\".")
    else:
        raise Exception(f"Unknown register bits: {reg.bits}. Register name: {reg.name}")

    return val

def set_register_value(reg, val):
    global registers, memory
    found = False
    j = 0
    for i in registers:
        if i.name == reg:
            found = True
            if i.parent == None:
                registers[j].value = val
            else:
                registers[j].parent.value = val

            if i.parent != None and i.bits == 8 and i.name.endswith("h"):
                registers[j].parent.value -= val
                registers[j].parent.value += 0x100 * val
            return

        j += 1
        
    j = 0
    for i in registers:
        if i.name == reg.replace("[", "").replace("]", ""):
            found = True
            if registers[j].name.endswith("h"):
                memory[registers[j].value * 0x100] = val
            else:
                memory[registers[j].value] = val
            return

        j += 1

    if not found:
        raise Exception("Unknown register:", reg)
    
def get_register_value(reg):
    for i in registers:
        if i.name == reg:
            if i.name.endswith("h"):
                return i.parent.value * 0x100
            else:
                if i.bits == 64:
                    return i.value
                else:
                    return i.parent.value

    for i in registers:
        if i.name == reg.replace("[", "").replace("]", ""):
            if i.name.endswith("h"):
                return memory[i.parent.value * 0x100]
            else:
                if i.bits == 64:
                    return memory[i.value]
                else:
                    return memory[i.parent.value]

    raise Exception("Unknown register:", reg)

def debug(instruction):
    def print_msg(msg):
        columns = os.get_terminal_size().columns
        print("\033[92m" + "─" * ((columns - len(msg))//2) + msg + "─" * ((columns - len(msg))//2) + "\033[00m")

    global breakpoints, debug_mode, last_command_exec
    print("\033c")
    ins = instruction.replace(",", "")
    ins_org = ins
    print_msg(" [ INSTRUCTIONS ] ")
    print(hex(get_register_value("rip") + base_address) + ":\t", end="")
    print("\033[96m" + ins.split(" ")[0] + "\033[00m " + ", ".join(ins.split(" ")[1:]).replace("[", "\033[90m[\033[00m").replace("]", "\033[90m]\033[00m") + "\t\t\033[101mRIP\033[0m")
    try:
        ins = instructions[get_register_value("rip") + 1].replace(",", "")
        print(hex(get_register_value("rip") + base_address + 1) + ":\t", end="")
        print("\033[96m" + ins.split(" ")[0] + "\033[00m " + ", ".join(ins.split(" ")[1:]).replace("[", "\033[90m[\033[00m").replace("]", "\033[90m]\033[00m"))
    except:
        pass
    try:
        ins = instructions[get_register_value("rip") + 2].replace(",", "")
        print(hex(get_register_value("rip") + base_address + 2) + ":\t", end="")
        print("\033[96m" + ins.split(" ")[0] + "\033[00m " + ", ".join(ins.split(" ")[1:]).replace("[", "\033[90m[\033[00m").replace("]", "\033[90m]\033[00m"))
    except:
        pass
    
    print_msg(" [ REGISTERS ] ")
    for i in reg_list_64bit + ["rip"]:
        if "[" not in i and "]" not in i:
            print("\033[91m$\033[00m" + i + "\t", get_register_value(i), "\t" + hex(get_register_value(i)), end="")
            if i == "rflags":
                print(" [", end="")
                for j in get_rflags():
                    if get_rflags()[j] == 1:
                        print("\033[92m", j, end="")
                    else:
                        print("\033[91m", j, end="")
                print("\033[00m ]")
            else:
                if get_register_value(i) >= 32 and get_register_value(i) <= 126:
                    print(" \033[93m\"" + chr(get_register_value(i)) + "\"\033[00m")
                else:
                    print()

    print_msg(" [ STACK ] ")
    i = 0
    j = 0
    while i <= memory_size - get_register_value("rsp"):
        if i >= memory_size - get_register_value("rbp"):
            print(hex(get_register_value("rsp") - j) + ":", str(memory[get_register_value("rsp") - 1 + i]) + "\t" + hex(memory[get_register_value("rsp") - 1 + i]), end="")
        else:
            i += 1
            j += 1
            continue
        if memory[get_register_value("rsp") - 1 + i] >= 32 and memory[get_register_value("rsp") - 1 + i] <= 126:
            print(" \033[93m\"" + chr(memory[get_register_value("rsp") - 1 + i]) + "\"\033[00m", end="")
        if i == memory_size - get_register_value("rbp"):
            print("\t\033[101mRBP\033[0m", end="")
        if i == memory_size - get_register_value("rsp"):
            print("\t\033[101mRSP\033[0m", end="")
        if i % 8 != 0:
            print("\t" , end="")
        else:
            print()
        i += 1
        j += 1

    print_msg(" [ HEAP ] ")
    i = 0
    while i < heap_pointer:
        if memory[i] >= 32 and memory[i] <= 126:
            print("\033[93m\"" + chr(memory[i]) + "\"\033[00m", end=" ")
        else:
            print(hex(memory[i]), end=" ")
        i += 1
    print()

    while True:
        command = input("\033[94m" + sys.argv[0] + ">" + "\033[00m ")
        if command == "":
            command = last_command_exec

        last_command_exec = command
        if command == "si":
            debug_mode = True
            break
        elif command == "c":
            debug_mode = False
            break
        elif command.startswith("br"):               
            if "0x" in command.split(" ")[1]:
                if int(command.split(" ")[1], 16) - base_address <= 0:
                    print("\033[91mERROR: \033[00mAddress doesn't exist. Perhaps you forgot adding base address?")
                    continue
                breakpoints.append(int(command.split(" ")[1], 16) - base_address)
            else:
                if int(command.split(" ")[1], 16) - base_address <= 0:
                    print("\033[91mERROR: \033[00mAddress doesn't exist. Perhaps you forgot adding base address?")
                    continue
                breakpoints.append(int(command.split(" ")[1]) - base_address)
        elif command.startswith("ci"):
            if len(command.split(" ")) < 2:
                print("\033[91mERROR: \033[00mInvalid use of command \"ci\"")
                continue

            ins_org = command.split(" ", maxsplit=1)[1]
        elif command.startswith("cr"):               
            if len(command.split(" ")) < 3:
                print("\033[91mERROR: \033[00mInvalid use of command \"cr\"")
                continue

            if command.split()[1].replace("$", "") not in reg_list:
                print("\033[91mERROR: \033[00mRegister \"" + command.split()[1] + "\" doesn't exist.")
                continue

            if "0x" in command.split()[2]:
                set_register_value(command.split()[1].replace("$", ""), int(command.split()[2], 16))
            else:
                set_register_value(command.split()[1].replace("$", ""), int(command.split()[2]))
        elif command.startswith("v"):
            if len(command.split(" ")) == 1 or (len(command.split(" ")) != 1 and not command.split(" ")[1].strip().isdigit()):
                print("\033[91mERROR: \033[00mAddress not specified for command \"v\"")
                continue
            
            if command.split(" ")[0] == "v":
                amount = 40
            else:   
                amount = int(command.split(" ")[0][1:])
            if "0x" in command.split(" ")[1]:
                addr = int(command.split(" ")[1], 16)
            else:
                addr = int(command.split(" ")[1])
            i = 0
            j = 0
            end = False
            while not end:
                if i*12 + j + addr - 1 > memory_size:
                    end = True

                print("\033[92m0x" + hex(addr + i * 12).replace("0x", "").zfill(12) + ":\033[00m\t", end="")
                    
                for j in range(12):
                    if i*12 + j <= amount and not end:
                        print("\033[01m\033[93m" + hex(memory[i * 12 + j + addr]).replace("0x", "").zfill(2) + "\033[00m", end=" ")
                    else:
                        print("   " * (12 - j), end="")
                        break
                print("\033[02m\t\t\t\t|", end="")
                for j in range(12):
                    if i*12 + j <= amount and not end:
                        if memory[i*12 + j + addr] >= 32 and memory[i*12 + j + addr] <= 126 and memory[i*12 + j + addr] != 46:
                            print(chr(memory[i*12 + j + addr]), end="")
                        elif memory[i*12 + j + addr] == 46:
                            print("\033[91m.\033[0m", end="")
                        else:
                            print(".", end="")
                    else:
                        print(" " * (12 - j), end="")
                        end = True
                        break
                print("|\033[00m")
                i += 1
        elif command == "q":
            sys.exit(0)
        elif command.startswith("disasm"):
            try:
                if len(command.split(" ")) == 1 or (len(command.split(" ")) != 1 and (command.split(" ")[1].isdigit() or not int(command.split(" ")[1], 16))):
                    print("\033[91mERROR: \033[00mAddress not specified for command \"disasm\"")
                    continue
            except:
                print("\033[91mERROR: \033[00mAddress not specified for command \"disasm\"")
                continue

            if command.split(" ")[0] == "disasm":
                amount = 5
            else:
                amount = int(command.split(" ")[0][6:])

            try:
                address = int(command.split(" ")[1]) - base_address
            except:
                address = int(command.split(" ")[1], 16) - base_address
            if address < 0:
                print("\033[91mERROR: \033[00mAddress doesn't exist. Perhaps you forgot adding base address?")
                continue

            for i in range(amount):
                try:
                    print(hex(address + i + base_address) + ":\t", end="")
                    print("\033[96m" + instructions[address + i].replace(",", "").split(" ")[0] + "\033[00m " + ", ".join(instructions[address + i].replace(",", "").split(" ")[1:]).replace("[", "\033[90m[\033[00m").replace("]", "\033[90m]\033[00m"))
                except:
                    break
            
        elif command == "help":
            print("Commands:")
            print("\tsi\t\tForwards one instruction")
            print("\tc\t\tContinues until a breakpoint")
            print("\tbr\t\tSets a breakpoint")
            print("\tv\t\tShows a memory region")
            print("\tci\t\tChanges instruction")
            print("\tcr\t\tChanges register")
            print("\tdisasm\t\tShows instructions at an address")
            print("\tq\t\tExits emulation")
            print("\thelp\t\tShows this help message")
        else:
            print("\033[91mERROR: \033[00mUnknown command:", command.split(" ")[0])
            
    return ins_org.replace(",", "")

def set_rflags(flag: str, value: int):
    bits = {"CF": 0, "PF": 2, "AF": 4, "ZF": 6, "SF": 7, "TF": 8, "IF": 9, "DF": 10, "OF": 11}
    flags = get_rflags()
    flags[flag] = value
    val = 0
    for flg, bit in bits.items():
        if flags.get(flg, 0):
            val |= (1 << bit)

    set_register_value("rflags", val)

def get_rflags():
    result = {}
    bits = {"CF": 0, "PF": 2, "AF": 4, "ZF": 6, "SF": 7, "TF": 8, "IF": 9, "DF": 10, "OF": 11}
    for flag, bit in bits.items():
        result[flag] = (get_register_value("rflags") >> bit) & 1

    return result

def divide_str(div_str):
    j = 0
    buf = ""
    arr = []
    for i in div_str:
        if j == 0:
            buf += i
            j = 1
        else:
            buf += i
            j = 0
            arr.append(buf)
            buf = ""

    if buf != "":
        arr.append(buf)
        
    return arr

with open("config.toml", "rt") as f:
    data = tomllib.loads(f.read())
    if "code" in data["config"]:
        code_file = data["config"]["code"]
        
    if "entrypoint" in data["config"]:
        entrypoint = data["config"]["entrypoint"]
        
    if "baseaddress" in data["config"]:
        baseaddress = data["config"]["baseaddress"]
        
    if "memory" in data["config"]:
        memory_size = data["config"]["memory"]
        
    if "debugmode" in data["config"]:
        debug_mode = data["config"]["debugmode"]

    if "tscticks" in data["config"]:
        tscticks = data["config"]["tscticks"]
        
    if "breakpoints" in data:
        breakpoints = data["breakpoints"]["breakpoints"]
        
    if "KB" in memory_size:
        memory_size = int(memory_size.replace("KB", "")) * 1024
    elif "MB" in memory_size:
        memory_size = int(memory_size.replace("MB", "")) * 1048576
    elif "GB" in memory_size:
        memory_size = int(memory_size.replace("GB", "")) * 1073741824

    if "KHz" in tscticks:
        tscticks = int(tscticks.replace("KHz", "")) * 1024
    elif "MHz" in tscticks:
        tscticks = int(tscticks.replace("MHz", "")) * 1048576
    elif "GHz" in tscticks:
        tscticks = int(tscticks.replace("GHz", "")) * 1073741824
                    
            
memory = [0] * memory_size
instructions = []

with open(code_file, "rt") as f:
    for line in f.readlines():
        instructions.append(line.strip())

return_code = 1
set_register_value("rip", entrypoint - 1)
j = 0
for i in instructions:
    if bool(re.fullmatch(r"[A-Za-z0-9_]+:", i)):
            labels[i.replace(":", "")] = j
    j += 1

for i in instructions:
    if i.replace(",", "").split(" ")[0] == ".store":
        heap_string = "b" + i.split(" ", maxsplit=2)[2]
        strings[i.split(" ")[1]] = heap_pointer
        for byte in ast.literal_eval(heap_string):
            memory[heap_pointer] = byte
            heap_pointer += 1

beginning = int(time.time())
indirectjumperror = 0
arg1 = ""
arg2 = ""
arg3 = ""
arg4 = ""
set_register_value("rsp", memory_size)
set_register_value("rbp", memory_size)
while True:
    try:
        if instructions[get_register_value("rip")].replace(":", "") in labels:
            set_register_value("rip", get_register_value("rip") + 1)
            continue
        elif instructions[get_register_value("rip")].replace(",", "").split(" ")[0] == ".store":
            set_register_value("rip", get_register_value("rip") + 1)
            continue
        else:
            instruction = instructions[get_register_value("rip")].replace(",", "")
    except:
        raise Exception("Error: No halt function or exit syscall")
    if debug_mode or get_register_value("rip") in breakpoints:
        instruction = debug(instruction)
    ins = instruction.split(" ")[0]
    try:
        arg1 = instruction.split(" ")[1]
    except:
        pass
    
    try:
        arg2 = instruction.split(" ")[2]
    except:
        pass
    
    try:
        arg3 = instruction.split(" ")[3]
    except:
        pass
    
    try:
        arg4 = instruction.split(" ")[4]
    except:
        pass

    if arg1 == "$":
        arg1 = get_register_value("rip")
        
    if arg2 == "$":
        arg2 = get_register_value("rip")
        
    if arg3 == "$":
        arg3 = get_register_value("rip")
        
    if arg4 == "$":
        arg4 = get_register_value("rip")
    
    match(ins):
        case "mov":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a register / number to a number")

            if arg2 not in reg_list:
                if arg2 in strings:
                    set_register_value(arg1, strings[arg2])
                elif arg2.replace("[", "").replace("]", "") in strings:
                    set_register_value(arg1, memory[strings[arg2.replace("[", "").replace("]", "")]])
                elif "0x" not in arg2:
                    set_register_value(arg1, int(arg2))
                else:
                    set_register_value(arg1, int(arg2, 16))
            else:
                set_register_value(arg1, get_register_value(arg2))
        case "nop":
            pass
        case "add":
            if arg1 not in reg_list:
                 raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")
            
            if arg2 not in reg_list:
                if "0x" not in arg2:
                    set_register_value(arg1, get_register_value(arg1) + int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg1) + int(arg2, 16))
            else:
                set_register_value(arg1, get_register_value(arg1) + get_register_value(arg2))
        case "sub":
            if arg1 not in reg_list:
                 raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")
            
            if arg2 not in reg_list:
                if "0x" not in arg2:
                    set_register_value(arg1, get_register_value(arg1) - int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg1) - int(arg2, 16))
            else:
                set_register_value(arg1, get_register_value(arg1) - get_register_value(arg2))
        case "inc":
            if arg1 not in reg_list:
                 raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")

            set_register_value(arg1, get_register_value(arg1) + 1)
        case "dec":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")

            set_register_value(arg1, get_register_value(arg1) - 1)
        case "cmp":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. CMP first argument must be a register.")

            temp = 0
            if arg2 in reg_list:
                if get_register_value(arg1) < get_register_value(arg2):
                    set_rflags("CF", 1)
                else:
                    set_rflags("CF", 0)
                arg2 = get_register_value(arg2)
                temp = get_register_value(arg1) - arg2
            else:
                if "0x" in arg2:
                    if get_register_value(arg1) < int(arg2, 16):
                        set_rflags("CF", 1)
                    else:
                        set_rflags("CF", 0)

                    arg2 = int(arg2, 16)
                    temp = get_register_value(arg1) - arg2
                else:
                    if get_register_value(arg1) < int(arg2):
                        set_rflags("CF", 1)
                    else:
                        set_rflags("CF", 0)
                    arg2 = int(arg2)
                    temp = get_register_value(arg1) - arg2

            if temp == 0:
                set_rflags("ZF", 1)
            else:
                set_rflags("ZF", 0)

            arg1 = get_register_value(arg1)

            sign = lambda x: x < 0
            if (sign(arg1) != sign(arg2)) and (sign(temp) != sign(arg1)):
                set_rflags("OF", 1)
            else:
                set_rflags("OF", 0)
        case "jmp":
            if arg1 not in labels:
                if arg1 in reg_list:
                    set_register_value("rip", get_register_value(arg1))
                    indirectjumperror = 2
                else:
                    if "0x" in arg1:
                        set_register_value("rip", int(arg1, 16) - 1)
                    else:
                        set_register_value("rip", int(arg1) - 1)
            else:
                set_register_value("rip", labels[arg1])
        case "je":
            if get_rflags()["ZF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                        indirectjumperror = 2
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jne":
            if not get_rflags()["ZF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                        indirectjumperror = 2
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jz":
            if get_rflags()["ZF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                        indirectjumperror = 2
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jnz":
            if not get_rflags()["ZF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                        indirectjumperror = 2
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jl":
            if not get_rflags()["ZF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                        indirectjumperror = 2
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "push":
            if get_register_value("rsp") - 8 < heap_pointer:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Stack overflow. Optimize assembly code or increase memory size.")
            
            if arg1 in reg_list:
                data_to_push = get_register_value(arg1)
            else:
                if "0x" in arg1:
                    data_to_push = int(arg1, 16)
                else:
                    data_to_push = int(arg1)
                    
            while data_to_push > 18446744073709551615:
                data_to_push -= 18446744073709551615

            data_to_push_arr = divide_str(hex(data_to_push).replace("0x", "").zfill(16))
            data_to_push_arr.reverse()
            set_register_value("rsp", get_register_value("rsp") - 8)
            
            for i in range(8):
                if data_to_push_arr[i][0] == "0":
                    memory[get_register_value("rsp") + i] = int(data_to_push_arr[i][1], 16)
                else:
                    memory[get_register_value("rsp") + i] = int(data_to_push_arr[i], 16)
        case "pop":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number.")

            if get_register_value("rbp") == get_register_value("rsp") and get_register_value("rbp") == memory_size:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't pop something from an empty stack.")

            popped_val = ""
            for i in range(8):
                popped_val = hex(memory[get_register_value("rsp") + i]).replace("0x", "") + popped_val

            set_register_value(arg1, int(popped_val, 16))
            set_register_value("rsp", get_register_value("rsp") + 8)
        case "xor":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number.")

            if arg2 not in reg_list:
                if "0x" in arg2:
                    set_register_value(arg1, get_register_value(arg1) ^ int(arg2, 16))
                else:
                    set_register_value(arg1, get_register_value(arg1) ^ int(arg2))
            else:
                    set_register_value(arg1, get_register_value(arg1) ^ get_register_value(arg2))
        case "and":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number.")

            if arg2 not in reg_list:
                if "0x" in arg2:
                    set_register_value(arg1, get_register_value(arg1) & int(arg2, 16))
                else:
                    set_register_value(arg1, get_register_value(arg1) & int(arg2))
            else:
                    set_register_value(arg1, get_register_value(arg1) & get_register_value(arg2))
        case "or":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number.")

            if arg2 not in reg_list:
                if "0x" in arg2:
                    set_register_value(arg1, get_register_value(arg1) | int(arg2, 16))
                else:
                    set_register_value(arg1, get_register_value(arg1) | int(arg2))
            else:
                    set_register_value(arg1, get_register_value(arg1) | get_register_value(arg2))
        case "not":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number.")

            set_register_value(arg1, ~get_register_value(arg1))
        case "hlt":
            break
        case "syscall":
            syscall_id = get_register_value("rax")
            if syscall_id == 0:
                str_to_write = next(iter(sys.stdin))
                i = get_register_value("rsi")
                j = 0
                try:
                    while j < get_register_value("rdx"):
                        memory[i] = ord(str_to_write[j])
                        j += 1
                        i += 1
                except IndexError:
                    pass
            elif syscall_id == 1:
                j = 0
                for i in memory[get_register_value("rsi"):]:
                    if j < get_register_value("rdx"):
                        sys.stdout.write(chr(memory[get_register_value("rsi") + j]))
                        sys.stdout.flush()
                    else:
                        break
                    j += 1
            elif syscall_id == 9:
                set_register_value("rax", heap_pointer)
                heap_pointer += get_register_value("rsi")
            elif syscall_id == 11:
                heap_pointer -= get_register_value("rsi")
            elif syscall_id == 60:
                return_code = get_register_value("rdi")
                break
            elif syscall_id == 318:
                for i in range(get_register_value("rsi")):
                    memory[get_register_value("rdi") + i] = random.randint(0, 255)
        case "call":
            if get_register_value("rsp") - 8 < heap_pointer:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Stack overflow. Optimize assembly code or increase memory size.")
            data_to_push = get_register_value("rip")
            data_to_push_arr = divide_str(hex(data_to_push).replace("0x", "").zfill(16))
            data_to_push_arr.reverse()
            set_register_value("rsp", get_register_value("rsp") - 8)
            
            for i in range(8):
                if data_to_push_arr[i][0] == "0":
                    memory[get_register_value("rsp") + i] = int(data_to_push_arr[i][1], 16)
                else:
                    memory[get_register_value("rsp") + i] = int(data_to_push_arr[i], 16)

            set_register_value("rip", labels[arg1])
        case "leave":
            set_register_value("rsp", get_register_value("rbp"))
            popped_val = ""
            for i in range(8):
                popped_val = hex(memory[get_register_value("rsp") + i]).replace("0x", "") + popped_val

            set_register_value("rbp", int(popped_val, 16))
            set_register_value("rsp", get_register_value("rsp") + 8)
        case "ret":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number.")

            popped_val = ""
            for i in range(8):
                popped_val = hex(memory[get_register_value("rsp") + i]).replace("0x", "") + popped_val

            set_register_value("rip", int(popped_val, 16))
            set_register_value("rsp", get_register_value("rsp") + 8)
        case "lea":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number.")

            eval_string = arg2.replace("[", "").replace("]", "").replace("/", "//")
            if not any(arg1 in group for group in re.findall(r'\((.*?)\)', eval_string)):
                eval_string = eval_string.replace(arg1, "get_register_xxxxxx(\"" + arg1 + "\")")

            for string in strings:
                eval_string = eval_string.replace(string, str(strings[string]))
            
            set_register_value(arg1, int(eval(eval_string.replace("xxxxxx", "value"))))
        case "endbr64":
            indirectjumperror = 0
        case "mul":
            set_register_value("rax", (get_register_value("rax") * get_register_value(arg1)) & 0xFFFFFFFFFFFFFFFF)
            set_register_value("rdx", (get_register_value("rax") * get_register_value(arg1)) >> 64)
        case "div":
            try:
                set_register_value("rdx", get_register_value("rax") % get_register_value(arg1))
                set_register_value("rax", get_register_value("rax") // get_register_value(arg1))
            except ZeroDivisionError:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't divide by zero.")
        case "test":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a register / number to a number")

            if (get_register_value("rax") & (1 << 64) - 1) == 0:
                set_rflags("ZF", 1)
            else:
                set_rflags("ZF", 0)

            set_rflags("SF", ((get_register_value("rax") & (1 << 64) - 1) >> 63) & 1)

            if bin((get_register_value("rax") & (1 << 64) - 1) & 0xff).count("1") % 2 == 0:
                set_rflags("PF", 1)
            else:
                set_rflags("PF", 0)
                
            set_rflags("CF", 0)
            set_rflags("OF", 0)
        case "loop":
            if get_register_value("rcx") != 0:
                set_register_value("rcx", get_register_value("rcx") - 1)
                set_register_value("rip", get_register_value("rip") - 1)
        case "stc":
            set_rflags("CF", 1)
        case "clc":
            set_rflags("CF", 0)
        case "cmc":
            set_rflags("CF", abs(get_rflags()["CF"]-1))
        case "std":
            set_rflags("DF", 1)
        case "cld":
            set_rflags("DF", 0)
        case "sti":
            set_rflags("IF", 1)
        case "cli":
            set_rflags("IF", 0)
        case "pushfq":
            if get_register_value("rsp") - 8 < heap_pointer:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Stack overflow. Optimize assembly code or increase memory size.")
            
            data_to_push = get_register_value("rflags")
                    
            while data_to_push > 18446744073709551615:
                data_to_push -= 18446744073709551615

            data_to_push_arr = divide_str(hex(data_to_push).replace("0x", "").zfill(16))
            data_to_push_arr.reverse()
            set_register_value("rsp", get_register_value("rsp") - 8)
            
            for i in range(8):
                if data_to_push_arr[i][0] == "0":
                    memory[get_register_value("rsp") + i] = int(data_to_push_arr[i][1], 16)
                else:
                    memory[get_register_value("rsp") + i] = int(data_to_push_arr[i], 16)
        case "popfq":
            if get_register_value("rbp") == get_register_value("rsp") and get_register_value("rbp") == memory_size:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't pop something from an empty stack.")

            popped_val = ""
            for i in range(8):
                popped_val = hex(memory[get_register_value("rsp") + i]).replace("0x", "") + popped_val

            set_register_value("rflags", int(popped_val, 16))
            set_register_value("rsp", get_register_value("rsp") + 8)
        case "repe":
            set_rflags("ZF", 1)
            set_register_value("rsi", get_register_value("rsi") - 1)
            set_register_value("rdi", get_register_value("rdi") - 1)
            while get_register_value("rcx") != 0:
                if get_rflags()["DF"] == 1:
                    set_register_value("rsi", get_register_value("rsi") - 1)
                    set_register_value("rdi", get_register_value("rdi") - 1)
                else:
                    set_register_value("rsi", get_register_value("rsi") + 1)
                    set_register_value("rdi", get_register_value("rdi") + 1)

                if memory[get_register_value("rsi")] != memory[get_register_value("rdi")]:
                    set_rflags("ZF", 0)
                    
                set_register_value("rcx", get_register_value("rcx") - 1)
        case "shl":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")

            if arg2 in reg_list:
                set_register_value(arg1, get_register_value(arg1) << get_register_value(arg2))
            else:
                if "0x" in arg2:
                    set_register_value(arg1, get_register_value(arg1) << int(arg2, 16))
                else:
                    set_register_value(arg1, get_register_value(arg1) << int(arg2))
        case "shr":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")

            if arg2 in reg_list:
                set_register_value(arg1, get_register_value(arg1) >> get_register_value(arg2))
            else:
                if "0x" in arg2:
                    set_register_value(arg1, get_register_value(arg1) >> int(arg2, 16))
                else:
                    set_register_value(arg1, get_register_value(arg1) >> int(arg2))
        case "rol":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")

            if arg2 in reg_list and arg2 != "cl":
                raise Exception(f"Error: Can't use rol with any register other than \"cl\".")

            bits = 0

            for reg in registers:
                if reg.name == arg1:
                    bits = reg.bits

            if arg2 == "cl":
                if get_register_value(arg2) == "1":
                    set_rflags("OF", 1)
                set_register_value(arg1, ((get_register_value(arg1) << get_register_value(arg2)) | (get_register_value(arg2) >> (8 - bits))) & int("0x" + (str(bits) * "f")), 16)
            else:
                if arg2 == "1":
                    set_rflags("OF", 1)
                set_register_value(arg1, ((get_register_value(arg1) << int(arg2)) | (get_register_value(arg1) >> (8 - int(arg2)))) & int("0x" + ((bits // 4) * "f"), 16))

            set_rflags("CF", bin(get_register_value(arg1))[-1])
        case "ror":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")

            if arg2 in reg_list and arg2 != "cl":
                raise Exception(f"Error: Can't use ror with any register other than \"cl\".")

            bits = 0

            for reg in registers:
                if reg.name == arg1:
                    bits = reg.bits

            if arg2 == "cl":
                if get_register_value(arg2) == "1":
                    set_rflags("OF", 1)
                set_register_value(arg1, ((get_register_value(arg1) >> get_register_value(arg2)) | (get_register_value(arg2) << (8 - bits))) & int("0x" + (str(bits) * "f")), 16)
            else:
                if arg2 == "1":
                    set_rflags("OF", 1)
                set_register_value(arg1, ((get_register_value(arg1) >> int(arg2)) | (get_register_value(arg1) << (8 - int(arg2)))) & int("0x" + ((bits // 4) * "f"), 16))

            set_rflags("CF", bin(get_register_value(arg1))[-1])
        case "rdtsc":
            set_register_value("eax", ((int(time.time()) - beginning) * tscticks) & 0xFFFFFFFF)
            set_register_value("edx", (((int(time.time()) - beginning) * tscticks) >> 32) & 0xFFFFFFFF)
        case "":
            pass
        case _:
            raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Unknown instruction: {ins}")

    if indirectjumperror == 1:
        raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Instruction must be \"endbr64\" after jumping to register value.")
    else:
        indirectjumperror -= 1
        
    set_register_value("rip", get_register_value("rip") + 1)

sys.exit(return_code)
