# Some python code
import sys
import os 


folder = sys.argv[1]

# correct
# E:0x40120f:C:11e:jnz 0x401217 
# E:0x401211:C:7:add dword ptr [rbp-0xc], 0x1 

# wrong
# E:0x40120f:C:11e:jnz 0x401217 
# E:0x401217:C:180:mov eax, dword ptr [rbp-0x14] 


Critical_Point = "E:0x40120f:C:11e:jnz 0x401217"
CORRECT_SEQUENCE = "E:0x401211:C:7:add dword ptr [rbp-0xc], 0x1"
WRONG_SEQUENCE = "E:0x401217:C:180:mov eax, dword ptr [rbp-0x14]"
LAST_LINE = 'E:0x441196:C:2cc:syscall'

CHECKED_LINE = 'E:0x4012a8:C:180:mov eax, 0x1'


traces = os.listdir(folder)

def crack_password():
    password_list = [''] * 15
    max_length = 0 
    for trace in traces:
        word_length = len(trace) - 4
        if word_length > max_length:
            max_length = word_length
        local_counter = 0
        wrong_counter = 0
        trace_file = open(folder + '/' +trace)
        line = trace_file.readline()
        while not (LAST_LINE in line):
            if Critical_Point in line:
                line = trace_file.readline()
                if CORRECT_SEQUENCE in line:
                    password_list[local_counter] = trace[local_counter]
                if WRONG_SEQUENCE in line:
                    line = trace_file.readline()
                    wrong_counter += 1
                local_counter += 1

            elif CHECKED_LINE in line:
                password = ""
                for char in password_list:
                    if char != '':
                        password += char
                password += " complete"
                return password
            else:
                line = trace_file.readline()
        # Special Case, the correct password is part of the trail
        if local_counter < word_length:
            if wrong_counter == 0:
                password = ""
                for char in password_list:
                    if char != '':
                        password += char
                password += " complete"
                return password


    password = ""
    password_list = password_list[:max_length]
    for char in password_list:
        if char != '':
            password += char
        else:
            password += "_"
    password += " partial"
    return password

    



password = crack_password()
print(password)