# Some python code
import sys
import os 

folder = sys.argv[0]

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

counter = 0 
traces = os.listdir(folder)


def crack_password():
    password_list = [''] * 15
    for trace in traces:
        local_counter = 0
        trace_file = open(trace)
        line = trace_file.readline()
        while not (line in  LAST_LINE):
            if line in Critical_Point:
                line = trace_file.readline()
                if line in CORRECT_SEQUENCE:
                    password_list[local_counter] = trace[local_counter]
                if line in WRONG_SEQUENCE:
                    line = trace_file.readline()
                local_counter += 1
            elif line in CHECKED_LINE:
                password = ""
                for char in password_list:
                    if char != '':
                        password += char
                password += " complete"
                return password
            else:
                line = trace_file.readline()
    
    for char in password_list:
        if char != '':
            password += char
        password += " partial"
        return password

    



password = crack_password()
print(password)







