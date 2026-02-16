#!/usr/bin/python3

import operator
import tomllib
import random
import numpy
import blosc
import time
import json
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

class File:
    def __init__(self, name, content):
        self.name = name
        self.content = content

class Directory:
    def __init__(self, name):
        self.name = name

registers = [Register("rax", 0, 64), Register("rbx", 0, 64), Register("rcx", 0, 64), Register("rdx", 0, 64), Register("rsi", 0, 64), Register("rdi", 0, 64), Register("rbp", 0, 64), Register("rsp", 0, 64), Register("r8", 0, 64), Register("r9", 0, 64), Register("r10", 0, 64), Register("r11", 0, 64), Register("r12", 0, 64), Register("r13", 0, 64), Register("r14", 0, 64), Register("r15", 0, 64), Register("rip", 0, 64), Register("rflags", 0x200, 64)]
registers += [Register("eax", 0, 32, parent=registers[0]), Register("ebx", 0, 32, parent=registers[1]), Register("ecx", 0, 32, parent=registers[2]), Register("edx", 0, 32, parent=registers[3]), Register("esi", 0, 32, parent=registers[4]), Register("edi", 0, 32, parent=registers[5]), Register("ebp", 0, 32, parent=registers[6]), Register("esp", 0, 32, parent=registers[7]), Register("r8d", 0, 32, parent=registers[8]), Register("r9d", 0, 32, parent=registers[9]), Register("r10d", 0, 32, parent=registers[10]), Register("r11d", 0, 32, parent=registers[11]), Register("r12d", 0, 32, parent=registers[12]), Register("r13d", 0, 32, parent=registers[13]), Register("r14d", 0, 32, parent=registers[14]), Register("r15d", 0, 32, parent=registers[15])]
registers += [Register("ax", 0, 16, parent=registers[0]), Register("bx", 0, 16, parent=registers[1]), Register("cx", 0, 16, parent=registers[2]), Register("dx", 0, 16, parent=registers[3]), Register("si", 0, 16, parent=registers[4]), Register("di", 0, 16, parent=registers[5]), Register("bp", 0, 16, parent=registers[6]), Register("sp", 0, 16, parent=registers[7]), Register("r8w", 0, 16, parent=registers[8]), Register("r9w", 0, 16, parent=registers[9]), Register("r10w", 0, 16, parent=registers[10]), Register("r11w", 0, 16, parent=registers[11]), Register("r12w", 0, 16, parent=registers[12]), Register("r13w", 0, 16, parent=registers[13]), Register("r14w", 0, 16, parent=registers[14]), Register("r15w", 0, 16, parent=registers[15])]
registers += [Register("al", 0, 8, parent=registers[0]), Register("bl", 0, 8, parent=registers[1]), Register("cl", 0, 8, parent=registers[2]), Register("dl", 0, 8, parent=registers[3]), Register("sil", 0, 8, parent=registers[4]), Register("dil", 0, 8, parent=registers[5]), Register("bpl", 0, 8, parent=registers[6]), Register("spl", 0, 8, parent=registers[7]), Register("r8b", 0, 8, parent=registers[8]), Register("r9b", 0, 8, parent=registers[9]), Register("r10b", 0, 8, parent=registers[10]), Register("r11b", 0, 8, parent=registers[11]), Register("r12b", 0, 8, parent=registers[12]), Register("r13b", 0, 8, parent=registers[13]), Register("r14b", 0, 8, parent=registers[14]), Register("r15b", 0, 8, parent=registers[15])]
registers += [Register("ah", 0, 8, parent=registers[0]), Register("bh", 0, 8, parent=registers[1]), Register("ch", 0, 8, parent=registers[2]), Register("dh", 0, 8, parent=registers[3])]
registers += [Register("xmm0", 0, 128), Register("xmm1", 0, 128), Register("xmm2", 0, 128), Register("xmm3", 0, 128), Register("xmm4", 0, 128), Register("xmm5", 0, 128), Register("xmm6", 0, 128), Register("xmm7", 0, 128), Register("xmm8", 0, 128), Register("xmm9", 0, 128), Register("xmm10", 0, 128), Register("xmm11", 0, 128), Register("xmm12", 0, 128), Register("xmm13", 0, 128), Register("xmm14", 0, 128), Register("xmm15", 0, 128)]
registers += [Register("ymm0", 0, 256), Register("ymm1", 0, 256), Register("ymm2", 0, 256), Register("ymm3", 0, 256), Register("ymm4", 0, 256), Register("ymm5", 0, 256), Register("ymm6", 0, 256), Register("ymm7", 0, 256), Register("ymm8", 0, 256), Register("ymm9", 0, 256), Register("ymm10", 0,256), Register("ymm11", 0,256), Register("ymm12", 0,256), Register("ymm13", 0,256),  Register("ymm14", 0,256), Register("ymm15", 0,256)]
registers += [Register("zmm0", 0, 512), Register("zmm1", 0, 512), Register("zmm2", 0, 512), Register("zmm3", 0, 512), Register("zmm4", 0, 512), Register("zmm5", 0, 512), Register("zmm6", 0, 512), Register("zmm7", 0, 512), Register("zmm8", 0, 512), Register("zmm9", 0, 512), Register("zmm10", 0, 512), Register("zmm11", 0, 512), Register("zmm12", 0, 512), Register("zmm13", 0, 512), Register("zmm14", 0, 512), Register("zmm15", 0, 512)]
reg_list = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", "ah", "bh", "ch", "dh"]
reg_list_simd = ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15"]
reg_list_64bit = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rflags"]
reg_list_tmp = []
tld_snapshots = []
fds = {0: "STDIN", 1: "STDOUT", 2: "STDERR"}
cursors = {0: 0, 1: 0, 2: 0}
perms = {0: 0, 1: 0, 2: 0}
fs = {}


for i in range(16):
    registers[70 + i].parent = registers[86 + i]

for i in range(16):
    registers[86 + i].parent = registers[102 + i]
    
for i in reg_list:
    reg_list_tmp.append("[" + i + "]")
    reg_list_tmp.append("byte [" + i + "]")
    reg_list_tmp.append("word [" + i + "]")
    reg_list_tmp.append("dword [" + i + "]")
    reg_list_tmp.append("qword [" + i + "]")
    
reg_list_simd_tmp = []
for i in reg_list_simd:
    reg_list_simd_tmp.append("[" + i + "]")
    if "xmm" in i:
        reg_list_simd_tmp.append("xmmword [" + i + "]")
    elif "ymm" in i:
        reg_list_simd_tmp.append("ymmword [" + i + "]")
    elif "zmm" in i:
        reg_list_simd_tmp.append("zmmword [" + i + "]")

reg_list += reg_list_tmp
reg_list_simd += reg_list_simd_tmp
labels = {}
strings = {}
breakpoints = []
code_file = ""
binary = ""
binary_file = ""
ep_difference = 0
memory_size = 0
base_address = 0x400000
entrypoint = base_address
debug_mode = False
timelessdebugging = False
continuing_backwards = False
heap_pointer = 0
last_command_exec = ""
showsimd = False
showstack = True
showheap = True
showregisters = True
clearscreen = True

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

def to_little_endian(num, bits):
    x = divide_str(hex(num).replace("0x", "").zfill(bits//4))
    x.reverse()
    return x

def isrelative(address):
    if "byte" in address or "word" in address or "dword" in address or "qword" in address or "xmmword" in address or "ymmword" in address or "zmmword" in address:
        if address.split()[1][0] != "[" or address[-1] != "]":
            return False
    else:
        if address[0] != "[" or address[-1] != "]":
            return False

    return True

def calc_relative(addr):
    eval_string = addr
    replace_arr = []
    for i in registers:
        replace_arr.append(i.name)

    for string in strings:
        replace_arr.append(string)

    eval_string = re.sub(f"({"|".join(replace_arr)})", "get_register_xxxxxx(\"\\1\")", eval_string)

    eval_string = eval_string.replace("byte ", "")
    eval_string = eval_string.replace("dword ", "")
    eval_string = eval_string.replace("qword ", "")
    eval_string = eval_string.replace("xmmword ", "")
    eval_string = eval_string.replace("ymmword ", "")
    eval_string = eval_string.replace("zmmword ", "")
    eval_string = eval_string.replace("word ", "")
    eval_string = eval_string.replace("rel ", "")
    eval_string = eval_string.replace("[", "")
    eval_string = eval_string.replace("]", "")
    i = 1
    while instructions[get_register_value("rip") - base_address - ep_difference + i] == "morethanonebyte":
        i += 1

    eval_string = eval_string.replace("get_register_xxxxxx(\"rip\")", str(get_register_value("rip") + i))
    
    return eval(eval_string.replace("xxxxxx", "value"))
    
def size_check(bits, val):
    if val > 2 ** bits - 1:
        raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move value higher than {str(2 ** bits - 1)} to a {str(bits)}-bit register.")

    return val

def get_register_bits(reg):
    if "byte" in reg:
        return 8
    elif "qword" in reg:
        return 64
    elif "dword" in reg:
        return 32
    elif "xmmword" in reg:
        return 128
    elif "ymmword" in reg:
        return 256
    elif "zmmword" in reg:
        return 512
    elif "word" in reg:
        return 16

    for i in registers:
        if i.name == reg:
            return i.bits

def set_register_value(reg, val):
    global registers, memory
    if isrelative(reg):
        addr = calc_relative(reg)
        if "byte" in reg:
            memory[addr] = val
        elif "qword" in reg:
            bytes_to_set = to_little_endian(val, 64)
            for i in range(8):
                memory[addr + i] = int(bytes_to_set[i], 16)
        elif "dword" in reg:
            bytes_to_set = to_little_endian(val, 32)
            for i in range(4):
                memory[addr + i] = int(bytes_to_set[i], 16)
        elif "xmmword" in reg:
            bytes_to_set = to_little_endian(val, 128)
            for i in range(16):
                memory[addr + i] = int(bytes_to_set[i], 16)
        elif "ymmword" in reg:
            bytes_to_set = to_little_endian(val, 256)
            for i in range(32):
                memory[addr + i] = int(bytes_to_set[i], 16)
        elif "zmmword" in reg:
            bytes_to_set = to_little_endian(val, 512)
            for i in range(64):
                memory[addr + i] = int(bytes_to_set[i], 16)
        elif "word" in reg:
            bytes_to_set = to_little_endian(val, 16)
            for i in range(2):
                memory[addr + i] = int(bytes_to_set[i], 16)
        return
    
    found = False
    j = 0
    for i in registers:
        if i.name == reg:
            found = True
            if i.parent == None:
                registers[j].value = size_check(registers[j].bits, val)
            else:
                registers[j].parent.value = size_check(registers[j].bits, val)

            if i.parent != None and i.bits == 8 and i.name.endswith("h"):
                registers[j].parent.value -= val
                registers[j].parent.value += 0x100 * val
            return

        j += 1
        
    j = 0
    for i in registers:
        if i.name == reg.replace("[", "").replace("]", "").replace("byte", "").replace("qword", "").replace("dword", "").replace("word", "").replace(" ", ""):
            found = True
            if registers[j].name.endswith("h"):
                memory[registers[j].value * 0x100] = val
            else:
                if len(arg1.split()) != 1:
                    if arg1.split()[0] == "byte":
                        if val > 255:
                            raise Exception(f"Error: Can't fit value higher than 255 to \"byte\".")
                        
                        memory[registers[j].value] = val
                    elif arg1.split()[0] == "word":
                        if val > 65535:
                            raise Exception(f"Error: Can't fit value higher than 65535 to \"word\".")                      

                        memory[registers[j].value] = int(to_little_endian(val, 16)[0], 16)
                        memory[registers[j].value + 1] = int(to_little_endian(val, 16)[1], 16)
                    elif arg1.split()[0] == "dword":
                        if val > 4294967295:
                            raise Exception(f"Error: Can't fit value higher than 4294967295 to \"dword\".")
                        memory[registers[j].value] = int(to_little_endian(val, 32)[0], 16)
                        memory[registers[j].value + 1] = int(to_little_endian(val, 32)[1], 16)
                        memory[registers[j].value + 2] = int(to_little_endian(val, 32)[2], 16)
                        memory[registers[j].value + 3] = int(to_little_endian(val, 32)[3], 16)
                    elif arg1.split()[0] == "qword":
                        if val > 18446744073709551615:
                            raise Exception(f"Error: Can't fit value higher than 18446744073709551615 to \"qword\".")
                        memory[registers[j].value] = int(to_little_endian(val, 64)[0], 16)
                        memory[registers[j].value + 1] = int(to_little_endian(val, 64)[1], 16)
                        memory[registers[j].value + 2] = int(to_little_endian(val, 64)[2], 16)
                        memory[registers[j].value + 3] = int(to_little_endian(val, 64)[3], 16)
                        memory[registers[j].value + 4] = int(to_little_endian(val, 64)[4], 16)
                        memory[registers[j].value + 5] = int(to_little_endian(val, 64)[5], 16)
                        memory[registers[j].value + 6] = int(to_little_endian(val, 64)[6], 16)
                        memory[registers[j].value + 7] = int(to_little_endian(val, 64)[7], 16)
                    elif arg1.split()[0] == "xmmword":
                        if val > 340282366920938463463374607431768211455:
                            raise Exception(f"Error: Can't fit value higher than 340282366920938463463374607431768211455 to \"xmmword\".")
                        for k in range(16):
                            memory[registers[j].value + k] = int(to_little_endian(val, 128)[k], 16)
                    elif arg1.split()[0] == "ymmword":
                        if val > 115792089237316195423570985008687907853269984665640564039457584007913129639935:
                            raise Exception(f"Error: Can't fit value higher than 115792089237316195423570985008687907853269984665640564039457584007913129639935 to \"ymmword\".")
                        for k in range(32):
                            memory[registers[j].value + k] = int(to_little_endian(val, 256)[k], 16)
                    elif arg1.split()[0] == "zmmword":
                        if val > 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084095:
                            raise Exception(f"Error: Can't fit value higher than 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084095 to \"zmmword\".")
                        for k in range(32):
                            memory[registers[j].value + k] = int(to_little_endian(val, 512)[k], 16)
                    else:
                        raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Unknown memory size specifier \"{arg1.split()[0]}\".")
                else:
                    memory[registers[j].value] = val
            return

        j += 1
    
def get_register_value(reg):
    if isrelative(reg):
        bytes_to_ret = []
        calced_addr = calc_relative(reg)
        try:
            if "byte" in reg:
                return memory[calced_addr]
            elif "qword" in reg:
                for i in range(8):
                    bytes_to_ret.append(memory[calced_addr + i])
            elif "dword" in reg:
                for i in range(4):
                    bytes_to_ret.append(memory[calced_addr + i])
            elif "xmmword" in reg:
                for i in range(16):
                    bytes_to_ret.append(memory[calced_addr + i])
            elif "ymmword" in reg:
                for i in range(32):
                    bytes_to_ret.append(memory[calced_addr + i])
            elif "zmmword" in reg:
                for i in range(64):
                    bytes_to_ret.append(memory[calced_addr + i])
            elif "word" in reg:
                for i in range(2):
                    bytes_to_ret.append(memory[calced_addr + i])

            for i in range(len(bytes_to_ret)):
                bytes_to_ret[i] = hex(bytes_to_ret[i]).replace("0x", "").zfill(2)

            bytes_to_ret.reverse()
            return int("".join(bytes_to_ret), 16)
        except:
            raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Cannot access further than end of memory.")

    for i in registers:
        if i.name == reg:
            if i.name.endswith("h"):
                return i.parent.value * 0x100
            else:
                if i.bits == 64 or i.bits == 512:
                    return i.value
                else:
                    return i.parent.value

    for i in registers:
        if i.name == reg.replace("[", "").replace("]", "").replace("byte", "").replace("qword", "").replace("dword", "").replace("word", "").replace(" ", ""):
            if i.name.endswith("h"):
                return memory[i.parent.value * 0x100]
            else:
                if "byte" in reg:
                    if i.bits == 64 or i.bits == 512:
                        return memory[i.value]
                    else:
                        return memory[i.parent.value]
                elif "qword" in reg:
                    popped_val = ""

                    if i.bits == 64 or i.bits == 512:
                        addr = i.value
                    else:
                        addr = i.parent.value
                        
                    for i in range(8):
                        popped_val = (hex(memory[addr + i]).replace("0x", "")).zfill(2) + popped_val

                    return int(popped_val, 16)
                elif "dword" in reg:
                    popped_val = ""

                    if i.bits == 64 or i.bits == 512:
                        addr = i.value
                    else:
                        addr = i.parent.value
                        
                    for i in range(4):
                        popped_val = (hex(memory[addr + i]).replace("0x", "")).zfill(2) + popped_val

                    return int(popped_val, 16)
                elif "word" in reg:
                    popped_val = ""

                    if i.bits == 64 or i.bits == 512:
                        addr = i.value
                    else:
                        addr = i.parent.value
                        
                    for i in range(2):
                        popped_val = (hex(memory[addr + i]).replace("0x", "")).zfill(2) + popped_val

                    return int(popped_val, 16)

    raise Exception("Unknown register: " + reg)

def ishexedecimal(string):
    if string.startswith("0x"):
        string = string.replace("0x", "")

    for i in string:
        if i not in "0123456789abcdef":
            return False

    return True

def debug(instruction):
    def print_msg(msg):
        columns = os.get_terminal_size().columns
        print("\033[92m" + "─" * ((columns - len(msg))//2) + msg + "─" * ((columns - len(msg))//2) + "\033[00m", end="")
        if (columns - len(msg)) % 2 != 0:
            print("\033[92m─\033[00m", end="")
        print()

    global breakpoints, debug_mode, last_command_exec, showsimd, clearscreen, continuing_backwards, showregisters, showstack, showheap, memory
    continuing_backwards = False
    if clearscreen:
        print("\033c")
    ins = instruction.replace(",", "")
    ins_org = ins
    print_msg(" [ INSTRUCTIONS ] ")
    print(hex(get_register_value("rip")) + ":\t", end="")
    print("\033[96m" + magicsplit(ins, " ", ["byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword"])[0] + "\033[00m " + ", ".join(magicsplit(ins, " ", ["byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword"])[1:]).replace("[", "\033[90m[\033[00m").replace("]", "\033[90m]\033[00m") + "\t\t\033[101mRIP\033[0m")
    try:
        i = 0
        while instructions[get_register_value("rip") - base_address + 1 + i - ep_difference] == "morethanonebyte":
            i += 1

        ins = instructions[get_register_value("rip") - base_address + 1 + i - ep_difference].replace(",", "")
        print(hex(get_register_value("rip") + 1 + i) + ":\t", end="")
        print("\033[96m" + magicsplit(ins, " ", ["byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword"])[0] + "\033[00m " + ", ".join(magicsplit(ins, " ", ["byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword"])[1:]).replace("[", "\033[90m[\033[00m").replace("]", "\033[90m]\033[00m"))
    except:
        pass
    try:
        while instructions[get_register_value("rip") - base_address + 2 + i - ep_difference] == "morethanonebyte":
            i += 1
            
        ins = instructions[get_register_value("rip") - base_address + 2 + i - ep_difference].replace(",", "")
        print(hex(get_register_value("rip") + 2 + i) + ":\t", end="")
        print("\033[96m" + magicsplit(ins, " ", ["byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword"])[0] + "\033[00m " + ", ".join(magicsplit(ins, " ", ["byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword"])[1:]).replace("[", "\033[90m[\033[00m").replace("]", "\033[90m]\033[00m"))
    except:
        pass
    
    if showregisters:
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

        if showsimd:
            for i in reg_list_simd:
                if "[" not in i and "]" not in i:
                    print("\033[91m$\033[00m" + i + "\t", get_register_value(i), "\t" + hex(get_register_value(i)), end="")
                    if get_register_value(i) >= 32 and get_register_value(i) <= 126:
                        print(" \033[93m\"" + chr(get_register_value(i)) + "\"\033[00m")
                    else:
                        print()

    if showstack:
        print_msg(" [ STACK ] ")
        for i in range((get_register_value("rbp") - get_register_value("rsp")) // 8):
            print("\033[93m" + hex(get_register_value("rbp") + (i * 8)) + ": \033[00m", end="")
            data_read = []
            for j in range(8):
                data_read.append(hex(memory[get_register_value("rsp") + (i * 8) + j]).replace("0x", "").zfill(2))

            data_read.reverse()
            data_read = int("".join(data_read), 16)
            if data_read > 0x1000:
                print("0x" + hex(data_read).replace("0x", "").zfill(16))
            else:
                print(data_read)

    if showheap:
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

        command_tmp = str(command)
        for i in command_tmp.split():
            if i.startswith("$"):
                command = command.replace(i, str(get_register_value(i[1:])))
        if command == "si":
            debug_mode = True
            break
        elif command == "bi":
            if not timelessdebugging:
                print("\033[91mERROR: \033[00mTime less debugging is disabled. You can enable it from config.toml file.")
                continue

            if len(tld_snapshots) == 0:
                print("\033[91mERROR: \033[00mNot enough snapshots.")
                continue

            snapshot_id = 0
            while tld_snapshots[snapshot_id]["addr"] != get_register_value("rip"):
                snapshot_id += 1

            snapshot_id -= 2
            
            debug_mode = True
            for reg in tld_snapshots[snapshot_id]["registers"]:
                for k in registers:
                    if k.name == reg.name:
                        k.value = reg.value
            set_register_value("rip", tld_snapshots[snapshot_id]["addr"])
            memory = blosc.unpack_array(tld_snapshots[snapshot_id]["memory"])
            return tld_snapshots[snapshot_id]["instruction"].replace(",", "")
        elif command == "c":
            debug_mode = False
            break
        elif command == "bc":
            if len(tld_snapshots) == 0:
                print("\033[91mERROR: \033[00mNot enough snapshots.")
                continue

            snapshot_id = 0
            while tld_snapshots[snapshot_id]["addr"] != get_register_value("rip"):
                snapshot_id += 1

            snapshot_id -= 2
            
            for reg in tld_snapshots[snapshot_id]["registers"]:
                for k in registers:
                    if k.name == reg.name:
                        k.value = reg.value
            set_register_value("rip", tld_snapshots[snapshot_id]["addr"])
            memory = blosc.unpack_array(tld_snapshots[snapshot_id]["memory"])
            debug_mode = False
            continuing_backwards = True
            return tld_snapshots[snapshot_id]["instruction"].replace(",", "")
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

            if command.split()[1].replace("$", "") not in reg_list and command.split()[1].replace("$", "") not in reg_list_simd:
                print("\033[91mERROR: \033[00mRegister \"" + command.split()[1] + "\" doesn't exist.")
                continue

            if "0x" in command.split()[2]:
                set_register_value(command.split()[1].replace("$", ""), int(command.split()[2], 16))
            else:
                set_register_value(command.split()[1].replace("$", ""), int(command.split()[2]))
        elif command.startswith("v"):
            if len(command.split(" ")) == 1 or (len(command.split(" ")) != 1 and not ishexedecimal(command.split(" ")[1].strip().lower())):
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
            bytes_shown = 0
            while not end:
                if i*12 + j + addr - 1 > memory_size or bytes_shown == amount:
                    break

                print("\033[92m0x" + hex(addr + i * 12).replace("0x", "").zfill(12) + ":\033[00m\t", end="")
                    
                for j in range(12):
                    if i*12 + j <= amount and not end:
                        print("\033[01m\033[93m" + hex(memory[i * 12 + j + addr]).replace("0x", "").zfill(2) + "\033[00m", end=" ")
                        bytes_shown += 1
                    else:
                        print("   " * (12 - j), end="")
                        break
                print("\033[02m\t\t\t\t|", end="")
                for j in range(12):
                    if i*12 + j <= amount and not end:
                        if memory[i*12 + j + addr] >= 32 and memory[i*12 + j + addr] <= 126 and memory[i*12 + j + addr] != 46:
                            print(chr(memory[i*12 + j + addr]), end="")
                        elif memory[i*12 + j + addr] == 46:
                            print("\033[91m.\033[00m\033[02m", end="")
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
        elif command == "rf":
            return debug(ins_org.replace(",", ""))
        elif command.startswith("disasm"):
            try:
                if len(command.split(" ")) == 1 or (len(command.split(" ")) != 1 and not (command.split(" ")[1].isdigit() or not int(command.split(" ")[1], 16))):
                    print("\033[91mERROR: \033[00mAddress not specified for command \"disasm\"")
                    continue
            except:
                print("\033[91mERROR: \033[00mAddress not specified for command \"disasm\"")
                continue

            if command.split(" ")[0] == "disasm":
                amount = 20
            else:
                amount = int(command.split(" ")[0][6:])

            try:
                address = int(command.split(" ")[1]) - base_address - ep_difference
            except:
                address = int(command.split(" ")[1], 16) - base_address - ep_difference
            if address < 0:
                print("\033[91mERROR: \033[00mAddress doesn't exist. Perhaps you forgot adding base address?")
                continue

            i = address
            ins_shown = 0
            while ins_shown < amount:
                try:
                    if instructions[i] == "morethanonebyte":
                        i += 1
                        continue

                    print(hex(i + base_address + ep_difference) + ":\t", end="")
                    print("\033[96m" + magicsplit(instructions[i].replace(",", ""), " ", ["byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword"])[0] + "\033[00m " + ", ".join(magicsplit(instructions[i].replace(",", ""), " ", ["byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword"])[1:]).replace("[", "\033[90m[\033[00m").replace("]", "\033[90m]\033[00m"))
                    # print(instructions[i])
                    ins_shown += 1
                    i += 1
                except:
                    break
        elif command.startswith("toggle"):
            if command.split()[1].lower() == "simd":
                showsimd = not showsimd
            elif command.split()[1].lower() == "clearscreen":
                clearscreen = not clearscreen
            elif command.split()[1].lower() == "stack":
                showstack = not showstack
            elif command.split()[1].lower() == "heap":
                showheap = not showheap
            elif command.split()[1].lower() == "registers":
                showregisters = not showregisters
        elif command.startswith("help"):
            if "toggle" in command:
                print("Toggle commands:")
                print("\tsimd\t\tToggles showing SIMD registers.")
                print("\tclearscreen\tToggles clearing screen.")
                print("\tstack\t\tToggles showing stack.")
                print("\theap\t\tToggles showing heap.")
                print("\tregisters\tToggles showing registers.")
            else:
                print("Commands:")
                print("\tsi\t\tForwards one instruction.")
                print("\tbi\t\tBackwards one instruction (Works if time less debugging is enabled).")
                print("\tc\t\tContinues until a breakpoint.")
                print("\tbc\t\tContinues backwards until a breakpoint.")
                print("\tbr\t\tSets a breakpoint.")
                print("\tv\t\tShows a memory region.")
                print("\tci\t\tChanges instruction.")
                print("\tcr\t\tChanges register.")
                print("\tdisasm\t\tShows instructions at an address.")
                print("\ttoggle ...\tToggles something on the debug view.")
                print("\trf\t\tRefreshes the debug view.")
                print("\tq\t\tExits emulation.")
                print("\thelp\t\tShows this help message.")
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

def magicsplit(s, delim, words):
    parts = s.split(delim)
    result = []
    i_plus = 0
    for i in range(len(parts)):
        if i + i_plus >= len(parts):
            break
        
        if parts[i + i_plus] in words:
            if "[" in parts[i + i_plus + 1] and "]" not in parts[i + i_plus + 1]:
                result.append(parts[i + i_plus])
                while "]" not in parts[i + i_plus]:
                    result[-1] += " " + parts[i + i_plus + 1]
                    i_plus += 1
            elif "[" in parts[i + i_plus + 1] and "]" in parts[i + i_plus + 1]:
                result.append(parts[i + i_plus] + delim + parts[i + i_plus + 1])
                i_plus += 1
            else:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Invalid instruction syntax.")
        else:
            if "[" in parts[i + i_plus] and "]" not in parts[i + i_plus]:
                result.append(parts[i + i_plus])
                while "]" not in parts[i + i_plus]:
                    result[-1] += " " + parts[i + i_plus + 1]
                    i_plus += 1
            else:
                result.append(parts[i + i_plus])

    return result

def take_snapshot():
    global tld_snapshots
    snapshot = {}
    snapshot["addr"] = get_register_value("rip")
    snapshot["registers"] = []
    for reg in registers:
        snapshot["registers"].append(Register(reg.name, reg.value, reg.bits))
    snapshot["instruction"] = instructions[get_register_value("rip") - base_address - ep_difference]
    snapshot["memory"] = blosc.pack_array(memory, cname="zstd", clevel=9)
    tld_snapshots.append(snapshot)

def change_key(dictionary, old_key, new_key):
    if old_key in dictionary:
        dictionary[new_key] = dictionary.pop(old_key)

def parse_fs(run_recursive=False, filesys=None, name=None):
    global fs

    if run_recursive:
        fs_cpy = {}
        for i in filesys:
            fs_cpy[i] = filesys[i]
            
        fs_tmp = filesys
        for i in fs_cpy:
            if isinstance(fs_tmp[i], dict):
                fs_tmp[i] = parse_fs(True, filesys=fs_tmp[i], name=i)
                change_key(fs_tmp, i, Directory(i))
            else:
                content = fs_tmp[i]
                fs_tmp[i] = None
                change_key(fs_tmp, i, File(i, content.encode()))

        return fs_tmp
    else:
        fs_cpy = {}
        for i in fs:
            fs_cpy[i] = fs[i]

        for i in fs_cpy:
            if isinstance(fs[i], dict):
                fs[i] = parse_fs(True, filesys=fs[i], name=i)
                change_key(fs, i, Directory(i))
            else:
                content = fs[i]
                fs[i] = None
                change_key(fs, i, File(i, content.encode()))

def get_file_object(path):    
    found = False
    for fd in fds:
        if get_register_value("rdi") == fd:
            found = True
            if fd < 3:
                break

            splitted = fds[fd].split("/")
            directory = []
            directory_tmp = []
            for i in fs:
                directory.append(i)
                directory_tmp.append(i)

            k = 0
            break_while = False
            while not break_while:
                directory_tmp = []
                for i in directory:
                    directory_tmp.append(i)
                    
                for i in directory_tmp:
                    if i.name == splitted[k]:
                        if isinstance(i, Directory):
                            k += 1
                            directory = []
                            for j in i:
                                directory.append(j)
                        elif isinstance(i, File):
                            return File(i.name, i.content)
                            break_while = True

def get_perm(value):
    return value & 3

base_address_specified = False
try:
    with open("config.toml", "rt") as f:
        data = tomllib.loads(f.read())
        if "code" in data["config"]:
            code_file = data["config"]["code"]
        
        if "binary" in data["config"]:
            binary_file = data["config"]["binary"]
        
        if "entrypoint" in data["config"]:
            entrypoint = data["config"]["entrypoint"]
        
        if "baseaddress" in data["config"]:
            base_address_specified = True
            baseaddress = data["config"]["baseaddress"]
        
        if "memory" in data["config"]:
            memory_size = data["config"]["memory"]
        
        if "tscticks" in data["config"]:
            tscticks = data["config"]["tscticks"]
        
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
            
        if "debug" in data:
            if "debugmode" in data["debug"]:
                debug_mode = data["debug"]["debugmode"]
            if "timelessdebugging" in data["debug"]:
                timelessdebugging = data["debug"]["timelessdebugging"]
            if "breakpoints" in data["debug"]:
                breakpoints = data["debug"]["breakpoints"]

        if "env" in data:
            if "envp" in data["env"]:
                envp = data["env"]["envp"]

        if "files" in data:
            fs = json.loads(data["files"]["files"])
            parse_fs()

except FileNotFoundError:
    raise Exception("Error: config.toml not found.")
            
memory = numpy.zeros(memory_size, dtype=numpy.uint8)
instructions = []

if binary_file == "":
    try:
        with open(code_file, "rt") as f:
            for line in f.readlines():
                instructions.append(line.strip())
    except NameError:
        raise Exception("Error: \"code_file\" argument isn't found in config.toml.")
    except FileNotFoundError:
        raise Exception(f"Error: File \"{code_file}\" doesn't exist.")
else:
    import lief
    import capstone
    if binary_file == "":
        raise Exception("Error: Both \"code_file\" and \"binary_file\" arguments aren't found in config.toml.")
    try:
        with open(binary_file, "rb") as f:
            binary_bytes = f.read()
    except FileNotFoundError:
        raise Exception(f"Error: File \"{binary_file}\" doesn't exist.")
        
    binary = lief.parse(binary_file)
    bin_format = binary.format.name

    if bin_format == "ELF":
        if not base_address_specified:
            base_address = binary.imagebase

        machinecode = bytes(binary.get_section(".text").content)
        if binary.header.identity_class == binary.header.identity_class.ELF64:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif binary.header.identity_class == binary.header.identity_class.ELF32:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:
            raise Exception("Unknown binary class: " + binary.header.identity_class)

        entrypoint = binary.entrypoint
        disasm_base_address = binary.get_section(".text").virtual_address
        ep_difference = binary.get_section(".text").virtual_address - base_address
    elif bin_format == "MACHO":
        machinecode = bytes(binary.get_section("__text").content)
        disasm_base_address = binary.get_section("__text").virtual_address
        # if binary.header.machine == binary.header.machine.AMD64:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        # elif binary.header.machine == binary.header.machine.I386:
            # md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        # else:
            # raise Exception("Unknown binary class: " + binary.header.identity_class)
        entrypoint = binary.entrypoint
    elif bin_format == "PE":
        machinecode = bytes(binary.get_section(".text").content)
        if binary.header.machine == binary.header.machine.AMD64:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif binary.header.machine == binary.header.machine.I386:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:
            raise Exception("Unknown binary class: " + binary.header.identity_class)
        disasm_base_address = binary.get_section(".text").virtual_address
        entrypoint = binary.entrypoint
    
    last_address = -1
    for i in md.disasm(machinecode, disasm_base_address):
        if last_address != -1:
            for j in range(i.address - last_address - 1):
                instructions.append("morethanonebyte")
            last_address = i.address
        instructions.append((i.mnemonic + " " + i.op_str).replace("ptr ", "").replace("fs:", "").strip())
            
        if last_address == -1:
            last_address = i.address

    j = 0
    for i in binary_bytes:
        memory[base_address + j] = i
        j += 1
        
return_code = 1
set_register_value("rip", entrypoint)
j = 0
for i in instructions:
    if bool(re.fullmatch(r"[A-Za-z0-9_]+:", i)):
            labels[i.replace(":", "")] = j + base_address
    j += 1

for i in instructions:
    if i.replace(",", "").split(" ")[0] == ".store":
        heap_string = "b" + i.split(" ", maxsplit=2)[2]
        strings[i.split(" ")[1]] = heap_pointer
        for byte in ast.literal_eval(heap_string):
            memory[heap_pointer] = byte
            heap_pointer += 1
    elif i.startswith("section"):
        raise Exception("Error: Sections aren't supported in file emulation. Use binary emulation.")

beginning = int(time.time())
arg1 = ""
arg2 = ""
arg3 = ""
arg4 = ""
arg_count = 0

set_register_value("rsp", memory_size)

envp = "".join(envp)[::-1]
for i in envp:
    memory[get_register_value("rsp") - 1] = ord(i)
    set_register_value("rsp", get_register_value("rsp") - 1)

while True:
    try:
        if instructions[get_register_value("rip") - base_address - ep_difference].replace(":", "") in labels:
            set_register_value("rip", get_register_value("rip") + 1)
            continue
        elif instructions[get_register_value("rip") - base_address - ep_difference].replace(",", "").split(" ")[0] == ".store":
            set_register_value("rip", get_register_value("rip") + 1)
            continue
        elif instructions[get_register_value("rip") - base_address - ep_difference].replace(",", "").split(" ")[0] == "morethanonebyte":
            set_register_value("rip", get_register_value("rip") + 1)
            continue
        else:
            instruction = instructions[get_register_value("rip") - base_address - ep_difference].replace(",", "")
    except:
        raise Exception("Error: No halt function or exit syscall")

    to_join = []
    for i in instruction.split():
        if i.lower() in ["byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword"]:
            to_join.append(i.lower())
        else:
            to_join.append(i)

    instruction = " ".join(to_join)
    if timelessdebugging:
        take_snapshot()
        
    if (debug_mode or get_register_value("rip") - base_address in breakpoints) and not continuing_backwards:
        instruction = debug(instruction)
    elif continuing_backwards:
        snapshot_id = 0
        while tld_snapshots[snapshot_id]["addr"] != get_register_value("rip"):
            snapshot_id += 1

        snapshot_id -= 2
        
        debug_mode = True
        for reg in tld_snapshots[snapshot_id]["registers"]:
            for k in registers:
                if k.name == reg.name:
                    k.value = reg.value
        set_register_value("rip", tld_snapshots[snapshot_id]["addr"])
        memory = blosc.unpack_array(tld_snapshots[snapshot_id]["memory"])
        instruction = tld_snapshots[snapshot_id]["instruction"].replace(",", "")
        
    splitted = magicsplit(instruction, " ", ["byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword"])
    ins = splitted[0]
    arg1 = ""
    arg2 = ""
    arg3 = ""
    arg4 = ""
    arg_count = None
    try:
        arg1 = splitted[1]
    except:
        arg_count = 0 if arg_count == None else arg_count
    
    try:
        arg2 = splitted[2]
    except:
        arg_count = 1 if arg_count == None else arg_count
    
    try:
        arg3 = splitted[3]
    except:
        arg_count = 2 if arg_count == None else arg_count
    
    try:
        arg4 = splitted[4]
        arg_count = 4
    except:
        arg_count = 3 if arg_count == None else arg_count

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
            if arg1 not in reg_list and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a register / number to a number")

            if arg2 not in reg_list and not isrelative(arg2):
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
        case "add":
            if arg1 not in reg_list and not isrelative(arg1):
                 raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")

            if isrelative(arg2):
                set_register_value(arg1, get_register_value(arg1) + calc_relative(arg2))
            elif arg2 not in reg_list:
                if "0x" not in arg2:
                    set_register_value(arg1, get_register_value(arg1) + int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg1) + int(arg2, 16))
            else:
                set_register_value(arg1, get_register_value(arg1) + get_register_value(arg2))
        case "sub":
            if arg1 not in reg_list and not isrelative(arg1):
                 raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")
            
            if isrelative(arg2):
                set_register_value(arg1, calc_relative(arg2))
            elif arg2 not in reg_list:
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
            if arg1 not in reg_list and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. CMP first argument must be a register.")

            arg1 = get_register_value(arg1)
            if arg2 in reg_list or isrelative(arg2):
                arg2 = get_register_value(arg2)
            elif "0x" in arg2:
                arg2 = int(arg2, 16)
            else:
                arg2 = int(arg2)

            tmp = arg1 - arg2
            if arg1 < arg2:
                set_rflags("CF", 1)
            else:
                set_rflags("CF", 0)

            if tmp == 0:
                set_rflags("ZF", 1)
            else:
                set_rflags("ZF", 0)

            if tmp < 0:
                set_rflags("SF", 1)
            else:
                set_rflags("SF", 0)

            set_rflags("PF", (bin(int(tmp) % 256).count("1") % 2 == 0))
            if (arg1 % 16) < (arg2 % 16):
                set_rflags("AF", 1)
            else:
                set_rflags("AF", 0)
        case "jmp":
            if arg1 not in labels:
                if arg1 in reg_list:
                    set_register_value("rip", get_register_value(arg1))
                else:
                    if "0x" in arg1:
                        set_register_value("rip", int(arg1, 16) - 1)
                    else:
                        set_register_value("rip", int(arg1) - 1)
            else:
                set_register_value("rip", labels[arg1])
        case "je" | "jz":
            if get_rflags()["ZF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jne" | "jnz":
            if not get_rflags()["ZF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
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
            
            if isrelative(arg1):
                data_to_push = calc_relative(arg1)
            elif arg1 in reg_list:
                data_to_push = get_register_value(arg1)
            else:
                if "0x" in arg1:
                    data_to_push = int(arg1, 16)
                else:
                    data_to_push = int(arg1)

                if data_to_push > 4294967295:
                    raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. push imm64 isn't valid.")
                    
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
            if arg1 not in reg_list and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number.")

            if get_register_value("rbp") == get_register_value("rsp") and get_register_value("rbp") == memory_size:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't pop something from an empty stack.")

            popped_val = ""
            for i in range(8):
                popped_val = (hex(memory[get_register_value("rsp") + i]).replace("0x", "")).zfill(2) + popped_val

            if isrelative(arg1):
                j = 0
                for i in divide_str(popped_val):
                    memory[calc_relative(arg1) + j] = int(i, 16)
                    j += 1
            else:
                set_register_value(arg1, int(popped_val, 16))
            set_register_value("rsp", get_register_value("rsp") + 8)
        case "xor":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number.")

            if isrelative(arg2):
                set_register_value(arg1, arg1 ^ calc_relative(arg2))
            elif arg2 not in reg_list:
                if "0x" in arg2:
                    set_register_value(arg1, get_register_value(arg1) ^ int(arg2, 16))
                else:
                    set_register_value(arg1, get_register_value(arg1) ^ int(arg2))
            else:
                    set_register_value(arg1, get_register_value(arg1) ^ get_register_value(arg2))
        case "and":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number.")

            if isrelative(arg2):
                set_register_value(arg1, arg1 & calc_relative(arg2))
            elif arg2 not in reg_list:
                if "0x" in arg2:
                    set_register_value(arg1, get_register_value(arg1) & int(arg2, 16))
                else:
                    set_register_value(arg1, get_register_value(arg1) & int(arg2))
            else:
                    set_register_value(arg1, get_register_value(arg1) & get_register_value(arg2))
        case "or":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number.")

            if isrelative(arg2):
                set_register_value(arg1, arg1 | calc_relative(arg2))
            elif arg2 not in reg_list:
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
                if get_register_value("rdi") == 0:
                    str_to_write = sys.stdin.buffer.readline()
                    i = get_register_value("rsi")
                    j = 0
                    try:
                        while j < get_register_value("rdx"):
                            memory[i] = str_to_write[j]
                            j += 1
                            i += 1
                    except IndexError:
                        pass
                    set_register_value("rax", j)
                else:
                    if get_perm(perms[get_register_value("rdi")]) == 1:
                        set_register_value("rax", -1)
                    else:
                        try:
                            i = get_file_object(fds[get_register_value("rdi")])
                            for j in range(get_register_value("rdx")):
                                memory[get_register_value("rsi") + j] = i.content[j + cursors[get_register_value("rdi")]]
                        except IndexError:
                            pass
                        set_register_value("rax", j)
            elif syscall_id == 1:
                if get_register_value("rdi") == 1 or get_register_value("rdi") == 2:
                    j = 0
                    for i in memory[get_register_value("rsi"):]:
                        if j < get_register_value("rdx"):
                            if get_register_value("rdi") == 1:
                                sys.stdout.write(chr(memory[get_register_value("rsi") + j]))
                            else:
                                sys.stderr.write(chr(memory[get_register_value("rsi") + j]))
                            sys.stdout.flush()
                        else:
                            break
                        j += 1
                else:
                    if get_perm(get_register_value("rdi")) == 2:
                        set_register_value("rax", -1)
                    else:
                        found = False
                        for fd in fds:
                            if get_register_value("rdi") == fd:
                                found = True
                                if fd < 3:
                                    break

                                splitted = fds[fd].split("/")
                                directory = []
                                directory_tmp = []
                                for i in fs:
                                    directory.append(i)
                                    directory_tmp.append(i)

                                k = 0
                                break_while = False
                                while not break_while:
                                    directory_tmp = []
                                    for i in directory:
                                        directory_tmp.append(i)
                                    
                                    for i in directory_tmp:
                                        if i.name == splitted[k]:
                                            if isinstance(i, Directory):
                                                k += 1
                                                directory = []
                                                for j in i:
                                                    directory.append(j)
                                            elif isinstance(i, File):
                                                data_to_write = b""
                                                for j in range(get_register_value("rdx")):
                                                    data_to_write += chr(memory[get_register_value("rsi") + j]).encode()
                                                i.content += data_to_write
                                                break_while = True

                        if not found:
                            set_register_value("rax", -1)
            elif syscall_id == 2:
                file_to_open = ""
                i = 0
                while memory[get_register_value("rdi") + i] != 0:
                    file_to_open += chr(memory[get_register_value("rdi") + i])
                    i += 1

                found = False
                i = 0
                j = 0
                while not found:
                    for i in fds:
                        if j == i:
                            j += 1
                            continue
                    break
                fds[j] = file_to_open
                perms[j] = get_register_value("rsi")
                cursors[j] = 0
                set_register_value("rax", j)
            elif syscall_id == 3:
                try:
                    fds.pop(get_register_value("rdi"))
                except KeyError:
                    set_register_value("rax", -1)
            elif syscall_id == 8:
                if get_register_value("rdx") in [0, 1, 2]:
                    if get_register_value("rdx") == 0:
                        cursors[get_register_value("rdi")] = get_register_value("rsi")
                        set_register_value("rax", cursors[get_register_value("rdi")])
                    elif get_register_value("rdx") == 0:
                        cursors[get_register_value("rdi")] = cursors[get_register_value("rdi")] + get_register_value("rsi")
                        set_register_value("rax", cursors[get_register_value("rdi")])
                    elif get_register_value("rdx") == 0:
                        cursors[get_register_value("rdi")] = len(get_file_object(fds[get_register_value("rdi")]).content) + get_register_value("rsi")
                        set_register_value("rax", cursors[get_register_value("rdi")])
                else:
                    set_register_value("rax", -1)
            elif syscall_id == 9:
                set_register_value("rax", heap_pointer)
                heap_pointer += get_register_value("rsi")
            elif syscall_id == 11:
                heap_pointer -= get_register_value("rsi")
            elif syscall_id == 12:
                if not (get_register_value("rdi") < 0 or get_register_value("rdi") >= memory_size or heap_pointer + get_register_value("rdi") > memory_size):
                    if get_register_value("rdi") != 0:
                        heap_pointer += get_register_value("rdi")
                    set_register_value("rax", heap_pointer)
            elif syscall_id == 35:
                seconds = get_register_value("qword [rdi]")
                nanoseconds = get_register_value("qword [rdi + 8]")
                time.sleep(seconds + nanoseconds/1000000000)
            elif syscall_id == 39:
                set_register_value("rax", os.getpid())
            elif syscall_id == 60:
                return_code = get_register_value("rdi")
                break
            elif syscall_id == 201:
                set_register_value("rax", int(time.time()))
            elif syscall_id == 318:
                for i in range(get_register_value("rsi")):
                    memory[get_register_value("rdi") + i] = random.randint(0, 255)
        case "int":
            if arg1 != "128" and arg1 != "0x80":
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Invalid use of int instruction.")
            
            syscall_id = get_register_value("rax")
            if syscall_id == 3:
                str_to_write = sys.stdin.buffer.readline()
                i = get_register_value("ecx")
                j = 0
                try:
                    while j < get_register_value("edx"):
                        memory[i] = str_to_write[j]
                        j += 1
                        i += 1
                except IndexError:
                    pass
            elif syscall_id == 4:
                j = 0
                for i in memory[get_register_value("ecx"):]:
                    if j < get_register_value("edx"):
                        sys.stdout.write(chr(memory[get_register_value("ecx") + j]))
                        sys.stdout.flush()
                    else:
                        break
                    j += 1
            elif syscall_id == 90:
                set_register_value("rax", heap_pointer)
                heap_pointer += get_register_value("ecx")
            elif syscall_id == 91:
                heap_pointer -= get_register_value("ecx")
            elif syscall_id == 1:
                return_code = get_register_value("ebx")
                break
            elif syscall_id == 355:
                for i in range(get_register_value("ecx")):
                    memory[get_register_value("ebx") + i] = random.randint(0, 255)
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

            if isrelative(arg1):
                popped_val = ""
                j = 0
                for i in range(8):
                    popped_val = hex(memory[calc_relative(arg1) + i]).replace("0x", "")
                set_register_value("rip", popped_val)
            elif arg1 in reg_list:
                set_register_value("rip", get_register_value(arg1) - 1)
            elif arg1 not in labels:
                if "0x" in arg1:
                    set_register_value("rip", int(arg1, 16) - 1)
                else:
                    set_register_value("rip", int(arg1) - 1)
            else:
                set_register_value("rip", labels[arg1] - 1)
        case "leave":
            set_register_value("rsp", get_register_value("rbp"))
            popped_val = ""
            for i in range(8):
                popped_val = (hex(memory[get_register_value("rsp") + i]).replace("0x", "")).zfill(2) + popped_val

            set_register_value("rbp", int("".join(divide_str(popped_val)), 16))
            set_register_value("rsp", get_register_value("rsp") + 8)
        case "ret":
            popped_val = ""
            for i in range(8):
                popped_val = (hex(memory[get_register_value("rsp") + i]).replace("0x", "")).zfill(2) + popped_val

            set_register_value("rip", int("".join(divide_str(popped_val)), 16))
            set_register_value("rsp", get_register_value("rsp") + 8)
        case "lea":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number.")

            if not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Second argument must be an address.")
            
            set_register_value(arg1, calc_relative(arg2))
        case "mul":
            if isrelative(arg1):
                arg1 = calc_relative(arg1)
            set_register_value("rax", (get_register_value("rax") * get_register_value(arg1)) & 0xFFFFFFFFFFFFFFFF)
            set_register_value("rdx", (get_register_value("rax") * get_register_value(arg1)) >> 64)
        case "div":
            try:
                if isrelative(arg1):
                    arg1 = calc_relative(arg1)
                set_register_value("rdx", get_register_value("rax") % get_register_value(arg1))
                set_register_value("rax", get_register_value("rax") // get_register_value(arg1))
            except ZeroDivisionError:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't divide by zero.")
        case "test":
            if arg1 not in reg_list and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a register / number to a number")

            if get_register_bits(arg1) != get_register_bits(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Two registers' bits must be same for test.")

            if isrelative(arg1) and isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Two arguments can't be a memory address for test.")

            set_rflags("CF", 0)
            set_rflags("OF", 0)
            if arg2 in reg_list:
                tmp = get_register_value(arg1) & get_register_value(arg2)
            elif "0x" in arg2:
                tmp = get_register_value(arg1) & int(arg2, 16)
            else:
                tmp = get_register_value(arg1) & int(arg2)

            if tmp == 0:
                set_rflags("ZF", 1)
            else:
                set_rflags("ZF", 0)

            if bin(tmp & 0xff).count("1") % 2 == 0:
                set_rflags("PF", 1)
            else:
                set_rflags("PF", 0)

            set_rflags("SF", (tmp >> (get_register_bits(arg2) - 1)) & 1)
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
                popped_val = (hex(memory[get_register_value("rsp") + i]).replace("0x", "")).zfill(2) + popped_val

            set_register_value("rflags", int("".join(divide_str(popped_val)), 16))
            set_register_value("rsp", get_register_value("rsp") + 8)
        case _ if instruction.startswith("rep"):
            if ins == "rep":
                cond = get_register_value("rcx") != 0
            elif ins == "repe" or ins == "repz":
                cond = get_rflags()["ZF"] == 1 and get_register_value("rcx") != 0
            else:
                cond = get_rflags()["ZF"] == 0 and get_register_value("rcx") != 0
            if ins != "rep":
                set_rflags("ZF", 1)
            if arg1.startswith("cmps"):
                if arg1[-1] == "b":
                    i = 1
                elif arg1[-1] == "w":
                    i = 2
                elif arg1[-1] == "d":
                    i = 4
                elif arg1[-1] == "q":
                    i = 8
                    
                try:
                    set_register_value("rsi", get_register_value("rsi") - i)
                    set_register_value("rdi", get_register_value("rdi") - i)
                    while cond: #while get_register_value("rcx") != 0:
                        if get_rflags()["DF"] == 1:
                            set_register_value("rsi", get_register_value("rsi") - i)
                            set_register_value("rdi", get_register_value("rdi") - i)
                        else:
                            set_register_value("rsi", get_register_value("rsi") + i)
                            set_register_value("rdi", get_register_value("rdi") + i)

                        if memory[get_register_value("rsi")] != memory[get_register_value("rdi")]:
                            set_rflags("ZF", 0)
                    
                        set_register_value("rcx", get_register_value("rcx") - 1)
                        if ins == "rep":
                            cond = get_register_value("rcx") != 0
                        elif ins == "repe" or ins == "repz":
                            cond = get_rflags()["ZF"] == 1 and get_register_value("rcx") != 0
                        else:
                            cond = get_rflags()["ZF"] == 0 and get_register_value("rcx") != 0
                except:                
                    raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Cannot access further than end of memory.")
            elif arg1.startswith("scas"):
                if arg1[-1] == "b":
                    i = 1
                elif arg1[-1] == "w":
                    i = 2
                elif arg1[-1] == "d":
                    i = 4
                elif arg1[-1] == "q":
                    i = 8

                try:
                    while cond:# while get_rflags("ZF") == 1 and get_register_value("rcx") != 0:
                        if i == 1:
                            if get_register_value("al") != memory[get_register_value("byte [rdi]")]:
                                set_rflags("ZF", 0)
                        elif i == 2:
                            if get_register_value("ax") != memory[get_register_value("word [rdi]")]:
                                set_rflags("ZF", 0)
                        elif i == 3:
                            if get_register_value("eax") != memory[get_register_value("dword [rdi]")]:
                                set_rflags("ZF", 0)
                        elif i == 4:
                            if get_register_value("rax") != memory[get_register_value("qword [rdi]")]:
                                set_rflags("ZF", 0)

                        set_register_value("rdi", get_register_value("rdi") + i)
                        set_register_value("rcx", get_register_value("rcx") - 1)
                        if ins == "rep":
                            cond = get_register_value("rcx") != 0
                        elif ins == "repe" or ins == "repz":
                            cond = get_rflags()["ZF"] == 1 and get_register_value("rcx") != 0
                        else:
                            cond = get_rflags()["ZF"] == 0 and get_register_value("rcx") != 0
                except:
                    raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Cannot access further than end of memory.")
            elif arg1.startswith("stos"):
                if arg1[-1] == "b":
                    i = 1
                elif arg1[-1] == "w":
                    i = 2
                elif arg1[-1] == "d":
                    i = 4
                elif arg1[-1] == "q":
                    i = 8

                try:
                    while cond:
                        if i == 1:
                            set_register_value("byte [rdi]", get_register_value("al"))
                        elif i == 2:
                            set_register_value("word [rdi]", get_register_value("ax"))
                        elif i == 4:
                            set_register_value("dword [rdi]", get_register_value("eax"))
                        elif i == 8:
                            set_register_value("qword [rdi]", get_register_value("rax"))

                        set_register_value("rcx", get_register_value("rcx") - 1)
                        set_register_value("rdi", get_register_value("rdi") + i)
                        if ins == "rep":
                            cond = get_register_value("rcx") != 0
                        elif ins == "repe" or ins == "repz":
                            cond = get_rflags()["ZF"] == 1 and get_register_value("rcx") != 0
                        else:
                            cond = get_rflags()["ZF"] == 0 and get_register_value("rcx") != 0
                except:
                    raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Cannot access further than end of memory.")
            else:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Unknown suffix for instruction \"{ins}\": {arg1}.")
        case "shl" | "sal":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")

            if isrelative(arg2):
                arg2 = calc_relative(arg2)

            if arg2 in reg_list:
                set_register_value(arg1, get_register_value(arg1) << get_register_value(arg2))
            else:
                if "0x" in arg2:
                    set_register_value(arg1, get_register_value(arg1) << int(arg2, 16))
                else:
                    set_register_value(arg1, get_register_value(arg1) << int(arg2))
        case "shr" | "sar":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")

            if isrelative(arg2):
                arg2 = calc_relative(arg2)

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
                if isrelative(arg2):
                    arg2 = calc_relative(arg1, arg2, 1)

                if arg2 == "1" or arg2 == 1:
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
                if isrelative(arg2):
                    arg2 = calc_relative(arg1, arg2, 1)

                if arg2 == "1" or arg2 == 1:
                    set_rflags("OF", 1)
                set_register_value(arg1, ((get_register_value(arg1) >> int(arg2)) | (get_register_value(arg1) << (8 - int(arg2)))) & int("0x" + ((bits // 4) * "f"), 16))

            set_rflags("CF", bin(get_register_value(arg1))[-1])
        case "rdtsc":
            set_register_value("eax", ((int(time.time()) - beginning) * tscticks) & 0xFFFFFFFF)
            set_register_value("edx", (((int(time.time()) - beginning) * tscticks) >> 32) & 0xFFFFFFFF)
        case "movq":
            if arg1 not in reg_list_simd:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use movq with non SIMD register.")

            if arg2 not in reg_list_64bit:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use movq with non 64-bit register.")

            set_register_value(arg1, get_register_value(arg2))
        case "movd":
            if arg1 not in reg_list_simd:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use movq with non SIMD register.")

            reg_list_32bit = []
            for i in registers:
                if i.bits == 32:
                    reg_list_32bit.append(i.name)
            if arg2 not in reg_list_32bit:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use movq with non 64-bit register.")

            set_register_value(arg1, get_register_value(arg2))
        case "pxor":
            if arg1 not in reg_list_simd or arg2 not in reg_list_simd:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use pxor with non SIMD registers.")

            set_register_value(arg1, get_register_value(arg1) ^ get_register_value(arg2))
        case "movups" | "movdqu":
            if (arg1 not in reg_list_simd and not isrelative(arg1)) or (arg1 in reg_list_simd and "xmm" not in arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use {ins} with non XMM SIMD registers.")

            if (arg2 not in reg_list_simd and not isrelative(arg2)) or (arg2 in reg_list_simd and "xmm" not in arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use {ins} with non XMM SIMD registers.")

            set_register_value(arg1, get_register_value(arg2))
        case "movaps" | "movdqa":
            if (arg1 not in reg_list_simd and not isrelative(arg1)) or (arg1 in reg_list_simd and "xmm" not in arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use {ins} with non XMM SIMD registers.")

            if (arg2 not in reg_list_simd and not isrelative(arg2)) or (arg2 in reg_list_simd and "xmm" not in arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use {ins} with non XMM SIMD registers.")

            if isrelative(arg1) and get_register_value(arg1.replace("[", "").replace("]", "").replace("byte", "").replace("word", "").replace("dword", "").replace("qword", "").replace("xmmword", "").replace("xmm", "").strip()) % 16 != 0:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Address isn't aligned.")

            if isrelative(arg2) and get_register_value(arg2.replace("[", "").replace("]", "").replace("byte", "").replace("word", "").replace("dword", "").replace("qword", "").replace("xmmword", "").replace("xmm", "").strip()) % 16 != 0:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Address isn't aligned.")

            set_register_value(arg1, get_register_value(arg1))
        case "vmovups" | "vmovdqu":
            if (arg1 not in reg_list_simd and not isrelative(arg1)):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use {ins} with non SIMD registers.")

            if (arg2 not in reg_list_simd and not isrelative(arg2)):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use {ins} with non SIMD registers.")

            set_register_value(arg1, get_register_value(arg2))
        case "vmovaps" | "vmovdqa":
            if (arg1 not in reg_list_simd and not isrelative(arg1)):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use {ins} with non SIMD registers.")

            if (arg2 not in reg_list_simd and not isrelative(arg2)):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use {ins} with non SIMD registers.")

            if get_register_value(arg1) % 16 != 0:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Address isn't aligned.")

            if get_register_value(arg2) % 16 != 0:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Address isn't aligned.")

            set_register_value(arg1, get_register_value(arg1))
        case "vpxor":
            if arg1 not in reg_list_simd or arg2 not in reg_list_simd:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. First and second argument should be a SIMD register for vpxor.")

            if arg1[0] != arg2[0] or ((arg3 in reg_list_simd) and (arg3[0] != arg1[0] or arg3[0] != arg2[0])):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Arguments should be in same size for vpxor.")

            if arg3 in reg_list_simd:
                set_register_value(arg1, get_register_value(arg2) ^ get_register_value(arg3))
            else:
                if "0x" in arg3:
                    set_register_value(arg1, get_register_value(arg2) ^ int(arg3, 16))
                else:
                    set_register_value(arg1, get_register_value(arg2) ^ int(arg3))
        case "movabs":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. First argument must be a register for movabs.")

            if arg2 in reg_list or arg2.replace("[", "").replace("]", "") in reg_list or "[" in arg2:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Second argument must be a constant for movabs.")

            if "0x" in arg2:
                set_register_value(arg1, int(arg2, 16))
            else:
                set_register_value(arg1, int(arg2))
        case "jo":
            if get_rflags()["OF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jno":
            if not get_rflags()["OF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "js":
            if get_rflags()["SF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jns":
            if not get_rflags()["SF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jc" | "jb" | "jnae":
            if get_rflags()["CF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jnc" | "jnb" | "jae":
            if not get_rflags()["CF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jp" | "jpe":
            if get_rflags()["PF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jnp" | "jpo":
            if not get_rflags()["PF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "ja" | "jnbe":
            if not get_rflags()["CF"] and not get_rflags()["ZF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jna" | "jbe":
            if get_rflags()["CF"] or get_rflags()["ZF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jg" | "jnle":
            if not get_rflags()["ZF"] and get_rflags()["SF"] == get_rflags()["OF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jge" | "jnl":
            if get_rflags()["SF"] == get_rflags()["OF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jl" | "jnge":
            if get_rflags()["SF"] != get_rflags()["OF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jle" | "jng":
            if get_rflags()["ZF"] or get_rflags()["SF"] != get_rflags()["OF"]:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "jcxz" | "jecxz" | "jrcxz":
            if get_register_value("rcx") == 0:
                if arg1 not in labels:
                    if arg1 in reg_list:
                        set_register_value("rip", get_register_value(arg1))
                    else:
                        if "0x" in arg1:
                            set_register_value("rip", int(arg1, 16) - 1)
                        else:
                            set_register_value("rip", int(arg1) - 1)
                else:
                    set_register_value("rip", labels[arg1])
        case "xchg":
            if "[" in arg1 and "[" in arg2:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't use xchg for memory to memory operations.")

            if not ((arg1 in reg_list or isrelative(arg1)) and (arg2 in reg_list or isrelative(arg2))):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Instruction xchg's every argument should be a register or a memory address.")

            swap_val = get_register_value(arg1)
            set_register_value(arg1, get_register_value(arg2))
            set_register_value(arg2, swap_val)
        case "imul":
            if arg1 not in reg_list and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. imul's first argument should be a register.")

            if arg_count > 1 and (arg2 not in reg_list and not isrelative(arg1)):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. imul's second argument should be a register.")
            
            if arg_count > 2 and (arg3 in reg_list and isrelative(arg1)):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. imul's third argument should be a constant.")
            
            if arg_count == 1:
                if get_register_value("rax") * get_register_value(arg1) >= 2 ** get_register_bits("rax"):
                    set_rflags("CF", 1)
                    set_rflags("OF", 1)
                set_register_value("rax", (get_register_value("rax") * get_register_value(arg1)) & 0xFFFFFFFFFFFFFFFF)
                set_register_value("rdx", (get_register_value("rax") * get_register_value(arg1)) >> 64)
            elif arg_count == 2:
                if get_register_value(arg1) * get_register_value(arg2) >= 2 ** get_register_bits(arg1):
                    set_rflags("CF", 1)
                    set_rflags("OF", 1)
                    set_register_value(arg1, 2 ** get_register_bits(arg1) - 1)
                else:
                    set_register_value(arg1, get_register_value(arg1) * get_register_value(arg2))
            elif arg_count == 3:
                if "0x" in arg3:
                    if get_register_value(arg2) * int(arg3, 16) >= 2 ** get_register_bits(arg1):
                        set_rflags("CF", 1)
                        set_rflags("OF", 1)
                        set_register_value(arg1, 2 ** get_register_bits(arg1) - 1)
                    else:
                        set_register_value(arg1, get_register_value(arg2) * int(arg3, 16))
                else:
                    if get_register_value(arg2) * int(arg3) >= 2 ** get_register_bits(arg1):
                        set_rflags("CF", 1)
                        set_rflags("OF", 1)
                        set_register_value(arg1, 2 ** get_register_bits(arg1) - 1)
                    else:
                        set_register_value(arg1, get_register_value(arg2) * int(arg3))
        case "movsxd":
            if arg_count != 2:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. movsxd takes two arguments, but {str(arg_count)} given.")

            if arg1 not in reg_list_64bit:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. movsxd's first argument should be a 64-bit register.")

            if arg2 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. movsxd's first argument should be a 64-bit register.")

            set_register_value(arg1, get_register_value(arg2))
        case "cpuid":
            if get_register_value("rax") == 0:
                set_register_value("eax", 0xd)
                set_register_value("ebx", 0x756e6547)
                set_register_value("ecx", 0x6c65746e)
                set_register_value("edx", 0x49656e69)
            elif get_register_value("rax") == 1:
                set_register_value("eax", 0x306e4)
                set_register_value("ebx", 0x28200800)
                set_register_value("edx", 0xbfebfbff)
                set_register_value("ecx", 0x7fbee3ff)
            elif get_register_value("rax") == 2:
                set_register_value("eax", 0x76036301)
                set_register_value("ebx", 0xf0b2ff)
                set_register_value("edx", 0xca0000)
            elif get_register_value("rax") == 4:
                set_register_value("eax", 0x3c004121)
                set_register_value("ebx", 0x1c0003f)
                set_register_value("ecx", 0x3f)
            elif get_register_value("rax") == 7:
                set_register_value("eax", 0)
                set_register_value("ebx", 0x281)
                set_register_value("ecx", 0x9c000400)
        case "setne" | "sentz":
            if arg_count != 1:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. setne and setnz takes one arguments, but {str(arg_count)} given.")

            if arg1 not in reg_list or get_register_bits(arg1) != 8:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. setne and setnz' first argument should be a 8-bit register.")

            if get_rflags()["ZF"] == 1:
                set_register_value(arg1, 0)
            else:
                set_register_value(arg1, 1)
        case "sete" | "setz":
            if arg_count != 1:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins} takes one arguments, but {str(arg_count)} given.")

            if arg1 not in reg_list or get_register_bits(arg1) != 8:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s first argument should be a 8-bit register.")

            set_register_value(arg1, get_rflags()["ZF"])
        case "movsx":
            if arg_count != 2:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. movsx takes two arguments, but {str(arg_count)} given.")

            if arg1 not in reg_list and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. movsx's first argument should be a register or an address.")

            if arg2 not in reg_list and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. movsx's second argument should be a register or an address.")

            msb = bin(get_register_value(arg2)).replace("0b", "").zfill(get_register_bits(arg2))[0]
            extension = msb * (get_register_bits(arg1) - get_register_bits(arg2))
            set_register_value(arg1, int("0" + (extension + bin(get_register_value(arg2)).replace("0b", "")).lstrip("0"), 2))
        case "movzx" | "movzwl":
            if arg_count != 2:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins} takes two arguments, but {str(arg_count)} given.")

            if arg1 not in reg_list and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s first argument should be a register or an address.")

            if arg2 not in reg_list and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s second argument should be a register or an address.")

            set_register_value(arg1, get_register_value(arg2))
        case "cmove" | "cmovz":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s first argument should be a register.")

            if get_rflags()["ZF"] == 1:
                if not (isrelative(arg2) or arg2 in reg_list):
                    if "0x" in arg2:
                        set_register_value(arg1, int(arg2, 16))
                    else:
                        set_register_value(arg1, int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg2))
        case "cmovne" | "cmovnz":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s first argument should be a register.")

            if get_rflags()["ZF"] == 0:
                if not (isrelative(arg2) or arg2 in reg_list):
                    if "0x" in arg2:
                        set_register_value(arg1, int(arg2, 16))
                    else:
                        set_register_value(arg1, int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg2))
        case "cmova" | "cmovnbe":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s first argument should be a register.")

            if get_rflags()["CF"] == 0 and get_rflags()["ZF"] == 0:
                if not (isrelative(arg2) or arg2 in reg_list):
                    if "0x" in arg2:
                        set_register_value(arg1, int(arg2, 16))
                    else:
                        set_register_value(arg1, int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg2))
        case "cmovae" | "cmovnb":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s first argument should be a register.")

            if get_rflags()["CF"] == 0:
                if not (isrelative(arg2) or arg2 in reg_list):
                    if "0x" in arg2:
                        set_register_value(arg1, int(arg2, 16))
                    else:
                        set_register_value(arg1, int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg2))
        case "cmovnae" | "cmovb":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s first argument should be a register.")

            if get_rflags()["CF"] == 1:
                if not (isrelative(arg2) or arg2 in reg_list):
                    if "0x" in arg2:
                        set_register_value(arg1, int(arg2, 16))
                    else:
                        set_register_value(arg1, int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg2))
        case "cmovbe" | "cmovna":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s first argument should be a register.")

            if get_rflags()["CF"] == 1 or get_rflags()["ZF"] == 1:
                if not (isrelative(arg2) or arg2 in reg_list):
                    if "0x" in arg2:
                        set_register_value(arg1, int(arg2, 16))
                    else:
                        set_register_value(arg1, int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg2))
        case "cmovg" | "cmovnle":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s first argument should be a register.")

            if get_rflags()["ZF"] == 0 and get_rflags()["SF"] == get_rflags()["OF"]:
                if not (isrelative(arg2) or arg2 in reg_list):
                    if "0x" in arg2:
                        set_register_value(arg1, int(arg2, 16))
                    else:
                        set_register_value(arg1, int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg2))
        case "cmovge" | "cmovnl":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s first argument should be a register.")

            if get_rflags()["SF"] == get_rflags()["OF"]:
                if not (isrelative(arg2) or arg2 in reg_list):
                    if "0x" in arg2:
                        set_register_value(arg1, int(arg2, 16))
                    else:
                        set_register_value(arg1, int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg2))
        case "cmovnge" | "cmovl":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s first argument should be a register.")

            if get_rflags()["SF"] != get_rflags()["OF"]:
                if not (isrelative(arg2) or arg2 in reg_list):
                    if "0x" in arg2:
                        set_register_value(arg1, int(arg2, 16))
                    else:
                        set_register_value(arg1, int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg2))
        case "cmovng" | "cmovle":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. {ins}'s first argument should be a register.")

            if get_rflags()["ZF"] == 1 or get_rflags()["SF"] != get_rflags()["OF"]:
                if not (isrelative(arg2) or arg2 in reg_list):
                    if "0x" in arg2:
                        set_register_value(arg1, int(arg2, 16))
                    else:
                        set_register_value(arg1, int(arg2))
                else:
                    set_register_value(arg1, get_register_value(arg2))
        case "bt":
            if arg1 not in reg_list and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a register / number to a number.")
            
            if isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a register / number to a number.")

            if arg2 in reg_list:
                arg2 = get_register_value(arg2)
            elif "0x" in arg2:
                arg2 = int(arg2, 16)
            else:
                arg2 = int(arg2)

            arg2 = arg2 % 32
            set_rflags("CF", (get_register_value(arg1) >> arg2) & 1)
        case "rdrand":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. rdrand's first argument should be a register.")

            set_rflags("CF", 1)
            if get_register_bits(arg1) == 64:
                tmp = 0xffffffffffffffff
            elif get_register_bits(arg1) == 32:
                tmp = 0xffffffff
            elif get_register_bits(arg1) == 16:
                tmp = 0xffff

            set_register_value("rax", random.randint(0, tmp))
        case "punpcklqdq":
            if arg1 not in reg_list_simd and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. punpcklqdq's first argument should be a SIMD register or a memory address.")

            if arg2 not in reg_list_simd and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. punpcklqdq's second argument should be a SIMD register or a memory address.")

            tmp = hex(get_register_value(arg1)).replace("0x", "").zfill(32)[16:]
            tmp2 = hex(get_register_value(arg2)).replace("0x", "").zfill(32)[16:]
            set_register_value(arg1, int(tmp2 + tmp, 16))
        case "punpckhqdq":
            if arg1 not in reg_list_simd and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. punpckhqdq's first argument should be a SIMD register or a memory address.")

            if arg2 not in reg_list_simd and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. punpckhqdq's second argument should be a SIMD register or a memory address.")

            tmp = hex(get_register_value(arg1)).replace("0x", "").zfill(32)[:16]
            tmp2 = hex(get_register_value(arg2)).replace("0x", "").zfill(32)[:16]
            set_register_value(arg1, int(tmp2 + tmp, 16))
        case "psrldq":
            if arg1 not in reg_list_simd or "ymm" in arg1 or "zmm" in arg1:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. psrldq's first argument must be a XMM SIMD register.")

            if arg2 in reg_list_simd or isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. psrldq's second argument must be an 8-bit immediate.")

            if "0x" in arg2:
                arg2 = int(arg2, 16)
            else:
                arg2 = int(arg2)

            if arg2 > 255:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. psrldq's second argument must be smaller than 256.")

            # int("".join(((["00"] * arg2 + divide_str(hex(get_register_value(arg1)).replace("0x", "").zfill(32)))[:16])), 16)
            set_register_value(arg1, int("".join(((["00"] * arg2 + divide_str(hex(get_register_value(arg1)).replace("0x", "").zfill(32)))[:16])), 16))
        case "pslldq":
            if arg1 not in reg_list_simd or "ymm" in arg1 or "zmm" in arg1:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pslldq's first argument must be a XMM SIMD register.")

            if arg2 in reg_list_simd or isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pslldq's second argument must be an 8-bit immediate.")

            if "0x" in arg2:
                arg2 = int(arg2, 16)
            else:
                arg2 = int(arg2)

            if arg2 > 255:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pslldq's second argument must be smaller than 256.")

            set_register_value(arg1, int("".join((divide_str(hex(get_register_value(arg1)).replace("0x", "").zfill(32)) + (["00"] * arg2))[-16:]), 16))
        case "paddq":
            if arg1 not in reg_list_simd or "ymm" in arg1 or "zmm" in arg1:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. paddq's first argument must be a XMM SIMD register.")

            if arg2 not in reg_list_simd and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. paddq's second argument must be a memory address or a XMM SIMD register.")

            set_register_value(arg1, get_register_value(arg1) + get_register_value(arg2))
        case "pextrb":
            if arg1 not in reg_list and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pextrb's first argument must be a general purpose register or a memory address.")
                
            if arg2 not in reg_list_simd:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pextrb's second argument must be a SIMD register.")
                
            if arg3 in reg_list or arg3 in reg_list_simd or isrelative(arg3):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pextrb's third argument must be an 8-bit immediate.")

            try:
                if "0x" in arg3:
                    arg3 = int(arg3, 16)
                else:
                    arg3 = int(arg3)
            except:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pextrb's third argument must be an 8-bit immediate.")

            if arg3 > 255:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pextrb's third argument must be smaller than 256.")

            if arg3 > 15:
                arg3 %= 1

            set_register_value(arg1, int(divide_str(hex(get_register_value(arg2)).replace("0x", "").zfill(32))[-(arg3 + 1)], 16))
        case "pinsrb":
            if arg1 not in reg_list_simd:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pinsrb's first argument must be a SIMD register.")

            if arg2 not in reg_list and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pinsrb's second argument must be a general purpose register or a memory address.")                
                
            if arg3 in reg_list or arg3 in reg_list_simd or isrelative(arg3):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pinsrb's third argument must be an 8-bit immediate.")

            try:
                if "0x" in arg3:
                    arg3 = int(arg3, 16)
                else:
                    arg3 = int(arg3)
            except:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pinsrb's third argument must be an 8-bit immediate.")

            if arg3 > 255:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pinsrb's third argument must be smaller than 256.")

            if arg3 > 15:
                arg3 %= 1

            tmp = divide_str(hex(get_register_value(arg1)).replace("0x", "").zfill(32))
            tmp[-(arg3 + 1)] = hex(get_register_value(arg2)).replace("0x", "").zfill(2)

            set_register_value(arg1, int("".join(tmp), 16))
        case "paddb":
            if arg1 not in reg_list_simd or (arg1 in reg_list_simd and not arg1.startswith("xmm")):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. paddb's first argument must be a XMM SIMD register.")
            
            if arg2 not in reg_list_simd and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. paddb's second argument must be a XMM SIMD register or a memory address.")

            tmp = divide_str(hex(get_register_value(arg1)).replace("0x", "").zfill(32))
            tmp2 = divide_str(hex(get_register_value(arg2)).replace("0x", "").zfill(32))
            new_val = []
            for i in range(16):
                new_val.append(hex((int(tmp[i], 16) + int(tmp2[i], 16)) % 256).replace("0x", "").zfill(2))

            set_register_value(arg1, int("".join(new_val), 16))
        case "psubb":
            if arg1 not in reg_list_simd or (arg1 in reg_list_simd and not arg1.startswith("xmm")):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. psubb's first argument must be a XMM SIMD register.")
            
            if arg2 not in reg_list_simd and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. psubb's second argument must be a XMM SIMD register or a memory address.")

            tmp = divide_str(hex(get_register_value(arg1)).replace("0x", "").zfill(32))
            tmp2 = divide_str(hex(get_register_value(arg2)).replace("0x", "").zfill(32))
            new_val = []
            for i in range(16):
                new_val.append(hex((int(tmp[i], 16) - int(tmp2[i], 16)) % 256).replace("0x", "").zfill(2))

            set_register_value(arg1, int("".join(new_val), 16))
        case "pcmpgtb":
            if arg1 not in reg_list_simd or (arg1 in reg_list_simd and not arg1.startswith("xmm")):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pcmpgtb's first argument must be a XMM SIMD register.")
            
            if arg2 not in reg_list_simd and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pcmpgtb's second argument must be a XMM SIMD register or a memory address.")

            tmp = divide_str(hex(get_register_value(arg1)).replace("0x", "").zfill(32))
            tmp2 = divide_str(hex(get_register_value(arg2)).replace("0x", "").zfill(32))
            new_val = []

            for k in range(16):
                i = int(tmp[k], 16)
                j = int(tmp2[k], 16)

                if i >= 0x7f:
                    i -= 256

                if j >= 0x7f:
                    j -= 256

                if i > j:
                    new_val.append("ff")
                else:
                    new_val.append("00")

            set_register_value(arg1, int("".join(new_val), 16))
        case "pshufb":
            if arg1 not in reg_list_simd or (arg1 in reg_list_simd and not arg1.startswith("xmm")):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pshufb's first argument must be a XMM SIMD register.")
            
            if arg2 not in reg_list_simd and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. pshufb's second argument must be a XMM SIMD register or a memory address.")

            tmp = divide_str(hex(get_register_value(arg1)).replace("0x", "").zfill(32))
            tmp2 = divide_str(hex(get_register_value(arg2)).replace("0x", "").zfill(32))
            new_val = []
            for i in range(16):
                if int(tmp2[i], 16) & 0x80:
                    new_val.append("00")
                else:
                    new_val.append(hex(int(tmp[int(tmp2[i], 16)], 16)).replace("0x", "").zfill(2))

            new_val.reverse()
            set_register_value(arg1, int("".join(new_val), 16))
        case "punpcklbw":
            if arg1 not in reg_list_simd or (arg1 in reg_list_simd and not arg1.startswith("xmm")):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. punpcklbw's first argument must be a XMM SIMD register.")
            
            if arg2 not in reg_list_simd and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. punpcklbw's second argument must be a XMM SIMD register or a memory address.")

            tmp = divide_str(hex(get_register_value(arg1)).replace("0x", "").zfill(32))
            tmp2 = divide_str(hex(get_register_value(arg2)).replace("0x", "").zfill(32))
            tmp.reverse()
            tmp2.reverse()
            new_val = []
            for i in range(8):
                new_val.append(tmp[i])
                new_val.append(tmp2[i])

            new_val.reverse()
            set_register_value(arg1, int("".join(new_val), 16))
        case "punpckhbw":
            if arg1 not in reg_list_simd or (arg1 in reg_list_simd and not arg1.startswith("xmm")):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. punpckhbw's first argument must be a XMM SIMD register.")
            
            if arg2 not in reg_list_simd and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. punpckhbw's second argument must be a XMM SIMD register or a memory address.")

            tmp = divide_str(hex(get_register_value(arg1)).replace("0x", "").zfill(32))
            tmp2 = divide_str(hex(get_register_value(arg2)).replace("0x", "").zfill(32))
            tmp.reverse()
            tmp2.reverse()
            new_val = []
            for i in range(8):
                new_val.append(tmp[i + 8])
                new_val.append(tmp2[i + 8])

            new_val.reverse()
            set_register_value(arg1, int("".join(new_val), 16))
        case "pmovmskb":
            if arg1 not in reg_list:
                raise Exception(f"Errror: RIP is {hex(get_register_value("rip"))}. pmovmskb's first argument must be a non SIMD register.")

            if arg2 not in reg_list_simd:
                raise Exception(f"Errror: RIP is {hex(get_register_value("rip"))}. pmovmskb's second argument must be a SIMD register.")

            new_val = ""
            for i in divide_str(hex(get_register_value(arg2)).replace("0x", "").zfill(32)):
                new_val += bin(int(i, 16)).replace("0b", "").zfill(8)[0]

            set_register_value(arg1, int(new_val, 2))
        case "bsf":
            if arg1 not in reg_list:
                raise Exception(f"Errror: RIP is {hex(get_register_value("rip"))}. bsf's first argument must be a register.")

            if arg2 not in reg_list and not isrelative(arg2):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. bsf's second argument must be a register or a memory address.")

            if get_register_value(arg2) == 0:
                set_rflags("ZF", 1)
            else:
                set_rflags("ZF", 0)
                i = 0
                j = get_register_value(arg2)
                while j % 2 == 0:
                    j //= 2
                    i += 1

                set_register_value(arg1, i)
        case "idiv":
            if arg1 not in reg_list and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. idiv's first argument must be a register or a memory address.")

            bits = get_register_bits(arg1)
            if get_register_value(arg1) > ((2**bits)//2)-1:
                tmp = get_register_value(arg1) - (2**bits)
            else:
                tmp = get_register_value(arg1)

            if bits == 64:
                if get_register_value("rax") > ((2**64)//2)-1:
                    arg1 = get_register_value("rax") - (2**64)
                else:
                    arg1 = get_register_value("rax")
            elif bits == 32:
                if get_register_value("eax") > ((2**32)//2)-1:
                    arg1 = get_register_value("eax") - (2**32)
                else:
                    arg1 = get_register_value("eax")
            elif bits == 16:
                if get_register_value("ax") > ((2**16)//2)-1:
                    arg1 = get_register_value("ax") - (2**16)
                else:
                    arg1 = get_register_value("ax")
            elif bits == 8:
                if get_register_value("al") > ((2**8)//2)-1:
                    arg1 = get_register_value("al") - (2**8)
                else:
                    arg1 = get_register_value("al")

            if arg1 < 0:
                arg1 *= -1
                if bits == 64:
                    set_register_value("rax", ((arg1 // tmp) * -1) + 2**bits)
                    set_register_value("rdx", ((arg1 % tmp) * -1) + 2**bits)
                elif bits == 32:
                    set_register_value("eax", ((arg1 // tmp) * -1) + 2**bits)
                    set_register_value("edx", ((arg1 % tmp) * -1) + 2**bits)
                elif bits == 16:
                    set_register_value("ax", ((arg1 // tmp) * -1) + 2**bits)
                    set_register_value("dx", ((arg1 % tmp) * -1) + 2**bits)
                elif bits == 8:
                    set_register_value("al", ((arg1 // tmp) * -1) + 2**bits)
                    set_register_value("dl", ((arg1 % tmp) * -1) + 2**bits)
            else:
                if tmp < 0:
                    if bits == 64:
                        set_register_value("rax", (arg1 // tmp) + 2**bits)
                        set_register_value("rdx", (arg1 % tmp) + 2**bits)
                    elif bits == 32:
                        set_register_value("eax", (arg1 // tmp) + 2**bits)
                        set_register_value("edx", (arg1 % tmp) + 2**bits)
                    elif bits == 16:
                        set_register_value("ax", (arg1 // tmp) + 2**bits)
                        set_register_value("dx", (arg1 % tmp) + 2**bits)
                    elif bits == 8:
                        set_register_value("al", (arg1 // tmp) + 2**bits)
                        set_register_value("dl", (arg1 % tmp) + 2**bits)
                else:
                    if bits == 64:
                        set_register_value("rax", arg1 // tmp)
                        set_register_value("rdx", arg1 % tmp)
                    elif bits == 32:
                        set_register_value("eax", arg1 // tmp)
                        set_register_value("edx", arg1 % tmp)
                    elif bits == 16:
                        set_register_value("ax", arg1 // tmp)
                        set_register_value("dx", arg1 % tmp)
                    elif bits == 8:
                        set_register_value("al", arg1 // tmp)
                        set_register_value("dl", arg1 % tmp)
        case "cdq":
            if get_register_value("eax") > 2147483647:
                set_register_value("edx", 0xffffffff)
            else:
                set_register_value("edx", 0)
        case "cqo":
            if get_register_value("rax") > 9223372036854775807:
                set_register_value("rdx", 0xffffffffffffffff)
            else:
                set_register_value("rdx", 0)
        case "cwd":
            if get_register_value("ax") > 32767:
                set_register_value("dx", 0xffff)
            else:
                set_register_value("dx", 0)
        case "cbw":
            if get_register_value("al") > 127:
                set_register_value("ax", 0xffff)
            else:
                set_register_value("ax", 0)
        case "neg":
            if arg1 not in reg_list and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. neg's first argument must be a register or a memory address.")

            byte = int(get_register_value(arg1))
            if byte == 0:
                set_rflags("ZF", 1)
            else:
                set_rflags("ZF", 0)

            if byte > (((2 ** get_register_bits(arg1)) // 2) - 1):
                set_rflags("SF", 0)
            else:
                set_rflags("SF", 1)
            
            if byte > (((2 ** get_register_bits(arg1)) // 2) - 1):
                byte = (byte - 2 ** get_register_bits(arg1)) * -1
            else:
                byte = (2 ** get_register_bits(arg1)) - byte
            set_register_value(arg1, byte)
        case "movntdq":
            if not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. movntdq's first argument must be a memory address.")

            if arg2 not in reg_list_simd or (arg2 in reg_list_simd and (not arg2.startswith("xmm"))):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. movntdq's second argument must be a XMM SIMD register.")

            set_register_value(arg1, get_register_value(arg2))
        case "vmovntdq":
            if not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. vmovntdq's first argument must be a memory address.")

            if arg2 not in reg_list_simd or (arg2 in reg_list_simd and arg2.startswith("xmm")):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. vmovntdq's second argument must be a YMM or ZMM SIMD register.")

            set_register_value(arg1, get_register_value(arg2))
        case "sbb":
            if arg1 not in reg_list and not isrelative(arg1):
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Can't move a number to a number")

            if isrelative(arg2):
                val2 = calc_relative(arg2)
            elif arg2 not in reg_list:
                if "0x" not in arg2:
                    val2 = int(arg2)
                else:
                    val2 = int(arg2, 16)
            else:
                val2 = get_register_value(arg2)

            if get_rflags()["CF"]:
                val2 += 1

            result = get_register_value(arg1) - val2
            if result == 0:
                set_rflags("ZF", 1)
            else:
                set_rflags("ZF", 0)

            if bin(result).replace("0b", "").zfill(get_register_bits(arg1))[0] == "1":
                set_rflags("SF", 1)
            else:
                set_rflags("SF", 0)

            tmp = 2 ** (get_register_bits(arg1) - 1)
            if val2 >= tmp or val2 <= (tmp * -1):
                set_rflags("OF", 1)
            else:
                set_rflags("OF", 0)

            set_rflags("CF", (result >> get_register_bits(arg1)) & 1)

            set_register_value(arg1, get_register_value(arg1) - val2)
        case "bswap":
            if arg1 not in reg_list:
                raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. BSWAP can't operate on non-register values.")

            tmp = get_register_value(arg1)
            set_register_value(arg1, int("".join(divide_str(hex(tmp).replace("0x", ""))[::-1]), 16))
        case "endbr64" | "nop" | "nopl" | "nopw" | "notrack" | "prefetcht0" | "prefetcht1" | "prefetcht2" | "prefetcht3" | "prefetchnta" | "sfence" | "":
            pass
        case _:
            raise Exception(f"Error: RIP is {hex(get_register_value("rip"))}. Unknown instruction: {ins}")

      
    set_register_value("rip", get_register_value("rip") + 1)

sys.exit(return_code)
