# Some python code
import sys
import os
from string import ascii_lowercase
import time
folder = sys.argv[0]

CORRECT = "E:0x4011b6:C:7:add dword ptr [rbp-0x8], 0x1"
WRONG = "E:0x4011bc:C:7:add dword ptr [rbp-0xc], 0x1"
LAST_LINE = 'E:0x41c716:C:2cc:syscall'

T2 = "/home/sgx/isl/t2"
T2_EXE = T2 + "/password_checker_2"
T2_trace = T2 + "/trace.txt"
PIN = "~/pin-2.14-71313-gcc.4.4.7-linux/pin.sh"
SGX_TRACE = "~/pin-2.14-71313-gcc.4.4.7-linux/source/tools/SGXTrace/obj-intel64/SGXTrace.so"

generate_trace_base = PIN + " -t " + SGX_TRACE + " -o " + T2_trace + " -trace 1 -- " + T2_EXE + " "

password_list = [''] * 31
CHART_LIST = [char for char in ascii_lowercase]

for char in ascii_lowercase:
    # Something goes here
    trial_password = char * 31
    generate_trace = generate_trace_base + trial_password
    os.system(generate_trace)
    time.sleep(0.5)
    trace_file = open(T2_trace)

    line = trace_file.readline()
    local_counter = 0
    while not (LAST_LINE in line):
        if CORRECT in line:
            password_list[local_counter] = char
            local_counter += 1
        elif WRONG in line:
            local_counter += 1
        line = trace_file.readline()
    trace_file.close()

password = ""
for char in password_list:
    if char != '':
        password += char
print(password)

