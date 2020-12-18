# Some python code
import sys
import os 
from string import ascii_lowercase

folder = sys.argv[1]

# correct
# E:0x40120f:C:11e:jnz 0x401217 
# E:0x401211:C:7:add dword ptr [rbp-0xc], 0x1 

# wrong
# E:0x40120f:C:11e:jnz 0x401217 
# E:0x401217:C:180:mov eax, dword ptr [rbp-0x14] 

# Repeat: E:0x40127e:C:2c6:sub dword ptr [rbp-0x10], 0x1


Critical_Point = "E:0x40120f:C:11e:jnz 0x401217"
CORRECT_SEQUENCE = "E:0x401211:C:7:add dword ptr [rbp-0xc], 0x1"
WRONG_SEQUENCE = "E:0x401217:C:180:mov eax, dword ptr [rbp-0x14]"
REPEAT = 'E:0x40127e:C:2c6:sub dword ptr [rbp-0x10], 0x1'
LAST_LINE = 'E:0x441196:C:2cc:syscall'
END_REPEAT_LINE = 'E:0x401288:C:7:add dword ptr [rbp-0x14], 0x1'

CHECKED_LINE = 'E:0x4012a8:C:180:mov eax, 0x1'
FALSE_LINE = 'E:0x4012af:C:180:mov eax, 0x0'


traces = os.listdir(folder)
CHART_LIST = [char for char in ascii_lowercase]


def crack_password():
    
    max_length = 0
    max_file = ''
    for trace in traces:
        if len(trace) > max_length:
            max_length = len(trace)
            max_file = trace
    password_list = [''] * max_length
    
    trace_file = open(folder + '/' + max_file)
    line = trace_file.readline()
    local_counter = 0
    while not (LAST_LINE) in line:
        if Critical_Point in line:
            line = trace_file.readline()
            if CORRECT_SEQUENCE in line:
                password_list[local_counter] = max_file[local_counter]
                local_counter += 1
            if WRONG_SEQUENCE in line:
                line = trace_file.readline()
                counter = 0
                while not END_REPEAT_LINE in line:
                    if REPEAT in line:
                        counter += 1
                        print(counter)
                    line = trace_file.readline()
                character = max_file[local_counter]
                #Calculate the new character
                character_int = CHART_LIST.index(character)
                new_index = (counter + character_int)%26
                new_character = CHART_LIST[new_index]
                password_list[local_counter] = new_character
                local_counter += 1

        if CHECKED_LINE in line:
            password = ""
            for char in password_list:
                if char != '':
                    password += char
            password += " complete"
            return password
        elif FALSE_LINE in line:
            password = ""
            for char in password_list:
                if char != '':
                    password += char
            if max_length >= local_counter:
                password += " complete"
            else:
                password += " partial"
            return password
        else:
            line = trace_file.readline()

    



password = crack_password()
print(password)