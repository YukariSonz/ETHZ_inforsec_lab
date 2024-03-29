import math
import random
from fpylll import LLL
from fpylll import BKZ
from fpylll import IntegerMatrix
from fpylll import CVP
from fpylll import SVP



def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

# Modular inversion computation
def mod_inv(a, p):
    if a < 0:
        return p - mod_inv(-a, p)
    g, x, y = egcd(a, p)
    if g != 1:
        raise ArithmeticError("Modular inverse does not exist")
    else:
        return x % p

def recover_x_known_nonce(k, h, r, s, q):
    # Implement the "known nonce" cryptanalytic attack on ECDSA
    # The function is given the nonce k, (h, r, s) and the base point order q
    # The function should compute and return the secret signing key x
    x = ( mod_inv(r, q) * ( (k * s) - h ) ) % q 
    return x
    # raise NotImplementedError()

def recover_x_repeated_nonce(h_1, r_1, s_1, h_2, r_2, s_2, q):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA
    # The function is given the (hashed-message, signature) pairs (h_1, r_1, s_1) and (h_2, r_2, s_2) generated using the same nonce
    # The function should compute and return the secret signing key x
    x = ( ( (h_1 * s_2) - (h_2 * s_1) ) * mod_inv(( (r_2 * s_1) - (r_1 * s_2) ), q) ) % q
    return x
    # raise NotImplementedError()


def MSB_to_Padded_Int(N, L, list_k_MSB):
    # Implement a function that does the following: 
    # Let a is the integer represented by the L most significant bits of the nonce k 
    # The function should return a.2^{N - L} + 2^{N -L -1}
    # N = bit length
    # L = length of MSB
    a = ""
    for i in (list_k_MSB):
        a += str(i)
    a_int = int(a, 2)
    mid_point = (a_int * (2**(N-L)) )  + (2**(N-L-1))
    return mid_point
    # raise NotImplementedError()


def setup_hnp_single_sample(N, L, list_k_MSB, h, r, s, q):
    # Implement a function that sets up a single instance for the hidden number problem (HNP)
    # The function is given a list of the L most significant bts of the N-bit nonce k, along with (h, r, s) and the base point order q
    # The function should return (t, u) computed as described in the lectures
    t = ( r * mod_inv(s,q) ) % q
    z = ( h * mod_inv(s,q) ) % q
    mid_point = MSB_to_Padded_Int(N, L, list_k_MSB)
    u = mid_point - z
    return (t,u)
    # raise NotImplementedError()


def setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q):
    # Implement a function that sets up n = num_Samples many instances for the hidden number problem (HNP)
    # For each instance, the function is given a list the L most significant bits of the N-bit nonce k, along with (h, r, s) and the base point order q
    # The function should return a list of t values and a list of u values computed as described in the lectures
    # Hint: Use the function you implemented above to set up the t and u values for each instance
    # t_u_list = []
    t_list = []
    u_list = []
    for i in range(num_Samples):
        list_k_MSB = listoflists_k_MSB[i]
        h = list_h[i]
        r = list_r[i]
        s = list_s[i]
        (t,u) = setup_hnp_single_sample(N, L, list_k_MSB, h, r, s, q)
        t = (t,u)[0]
        u = (t,u)[1]
        t_list.append(t)
        u_list.append(u)
    return (t_list, u_list)
    # raise NotImplementedError()

def hnp_to_cvp(N, L, num_Samples, list_t, list_u, q):
    # Implement a function that takes as input an instance of HNP and converts it into an instance of the closest vector problem (CVP)
    # The function is given as input a list of t values, a list of u values and the base point order q
    # The function should return the CVP basis matrix B (to be implemented as a nested list) and the CVP target vector u (to be implemented as a list)
    # NOTE: The basis matrix B and the CVP target vector u should be scaled appropriately. Refer lecture slides and lab sheet for more details 
    u_cvp = list_u
    u_cvp.append(0)
    B_cvp = []
    for i in range(num_Samples):
        row = [0] * (num_Samples + 1 )
        row[i] = q
        B_cvp.append(row)
    t_cvp = list_t
    t_cvp.append(1 / (2**(L+1)) )
    B_cvp.append(t_cvp)

    B_processed = []
    for row in B_cvp:
        new_row = []
        for data in row:
            new_data = int(data * ( 2**(L+1) ) )
            new_row.append(new_data)
        B_processed.append(new_row)
    u_processed = [u * 2**(L+1) for u in u_cvp]
    return (B_processed, u_processed)
    # raise NotImplementedError()

def cvp_to_svp_Kannan_Embedding(N, L, num_Samples, cvp_basis_B, cvp_list_u):
    # Implement a function that takes as input an instance of CVP and converts it into an instance of the shortest vector problem (SVP)
    # Your function should use the Kannan embedding technique in the lecture slides
    # The function is given as input a CVP basis matrix B and the CVP target vector u
    # The function should use the Kannan embedding technique to output the corresponding SVP basis matrix B' of apropriate dimensions.
    # The SVP basis matrix B' should again be implemented as a nested list
    B_SVP = []
    for row in cvp_basis_B:
        new_row = row
        new_row.append(0)
        B_SVP.append(new_row)
    new_u = cvp_list_u

    # M = ( (num_Samples/(2 * math.pi * math.exp(1))) ** 0.5) * B_SVP[1][0] # M to be chosen
    M = int((num_Samples + 1 ) ** 0.5 * (2**N) / 2 )
    new_u.append(M)
    B_SVP.append(new_u)
    return B_SVP # B_SVP have been pre-processed
    # raise NotImplementedError()


def solve_cvp(cvp_basis_B, cvp_list_u):
    # Implement a function that takes as input an instance of CVP and solves it using in-built CVP-solver functions from the fpylll library
    # The function is given as input a CVP basis matrix B and the CVP target vector u
    # The function should output the solution vector v (to be implemented as a list)
    # NOTE: The basis matrix B should be processed appropriately before being passes to the fpylll CVP-solver. See lab sheet for more details

    
    B_matrix = IntegerMatrix.from_matrix(cvp_basis_B)
    # B_BKZ = BKZ.reduction(B_matrix, BKZ.Param(len(cvp_list_u)))
    B_LLL = LLL.reduction(B_matrix)
    v0 = CVP.closest_vector(B_LLL, cvp_list_u)
    return v0
    # raise NotImplementedError()

def solve_svp(svp_basis_B):
    # Implement a function that takes as input an instance of SVP and solves it using in-built SVP-solver functions from the fpylll library
    # The function is given as input the SVP basis matrix B
    # The function should output a vector v (to be implemented as a list)
    # NOTE: Recall from the lecture and also from the exercise session that for ECDSA cryptanalysis based on partial nonces, you might want your function to return the *second* shortest vector. 
    # If required, figure out how to get the in-built SVP-solver functions from the fpylll library to return the second shortest vector
    B_matrix = IntegerMatrix.from_matrix(svp_basis_B)
    # B_BKZ = BKZ.reduction(B_matrix, BKZ.Param(len(B_matrix[0])))
    B_LLL = LLL.reduction(B_matrix)
    v0 = SVP.shortest_vector(B_LLL)
    v0_2 = B_LLL[1]
    return v0_2
    # if v0.norm() >= v0_2.norm():
    #     return v0
    # else:
    #     return v0_2
    # raise NotImplementedError()


def recover_x_partial_nonce_CVP(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA using the in-built CVP-solver functions from the fpylll library
    # The function is partially implemented for you. Note that it invokes some of the functions that you have already implemented
    # You should complete the final step of recovering the secret signing key from the output of the CVP solver
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)
    v_List = solve_cvp(cvp_basis_B, cvp_list_u)
    # The function should recover the secret signing key x from the output of the CVP solver and output the same
    x = v_List[-1]
    x = x % q
    # As it's possible that ouput x-q
    return x
    # raise NotImplementedError()

def recover_x_partial_nonce_SVP(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q):
    # Implement the "repeated nonces" cryptanalytic attack on ECDSA using the in-built CVP-solver functions from the fpylll library
    # The function is partially implemented for you. Note that it invokes some of the functions that you have already implemented
    # You should complete the final step of recovering the secret signing key from the output of the CVP solver
    list_t, list_u = setup_hnp_all_samples(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q)
    cvp_basis_B, cvp_list_u = hnp_to_cvp(N, L, num_Samples, list_t, list_u, q)
    svp_basis_B = cvp_to_svp_Kannan_Embedding(N, L, num_Samples, cvp_basis_B, cvp_list_u)
    f_List = solve_svp(svp_basis_B)
    v_List = [f for f in f_List]
    for i in range(len(cvp_list_u)):
        v_List[i] = cvp_list_u[i] - v_List[i] 
    x = v_List[-2]
    x = x % q
    return x
    # raise NotImplementedError()



# The code below is for unit testing the various modules you are going to implement
# There are four modular tests for scalar multiplication, point addition, signing with fixed nonce and verification
# There s a final test for testing that the verification algorithm accepts signatures generated by the signing algorithm
# You can use the publc input and output files provided to you for testing the modules you have implemented
# Please note that we will use the SAME TESTS on private input and output files for evaluating your implementation
# DO NOT UPDATE THE TEST CODES BELOW since it will interfere with evaluating your implementation


q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


# Unit testing of the "known nonce" attack on ECDSA

num_Experiments = 100
known_nonce_out = []

with open('unit_test_known_nonce_inputs.txt', 'r') as filehandle:
    for i in range(num_Experiments):
        line_space = filehandle.readline()
        known_nonce_inp = filehandle.readline().split()
        k = int(known_nonce_inp[0])
        h = int(known_nonce_inp[1])
        r = int(known_nonce_inp[2])
        s = int(known_nonce_inp[3])
        x = recover_x_known_nonce(k, h, r, s, q)
        known_nonce_out.append(x)

with open('unit_test_known_nonce_outputs_temp.txt', 'w') as filehandle:
    for x in known_nonce_out:
        filehandle.write('\n%d\n' % x)



# Unit testing of the "repeated nonces" attack on ECDSA

num_Experiments = 100
repeated_nonce_out = []

with open('unit_test_repeated_nonce_inputs.txt', 'r') as filehandle:
    for i in range(num_Experiments):
        line_space = filehandle.readline()
        repeated_nonce_inp = filehandle.readline().split()
        h_1 = int(repeated_nonce_inp[0])
        r_1 = int(repeated_nonce_inp[1])
        s_1 = int(repeated_nonce_inp[2])
        h_2 = int(repeated_nonce_inp[3])
        r_2 = int(repeated_nonce_inp[4])
        s_2 = int(repeated_nonce_inp[5])
        x = recover_x_repeated_nonce(h_1, r_1, s_1, h_2, r_2, s_2, q)
        repeated_nonce_out.append(x)

with open('unit_test_repeated_nonce_outputs_temp.txt', 'w') as filehandle:
    for x in repeated_nonce_out:
        filehandle.write('\n%d\n' % x)



# Unit testing phase-1 of the "partial nonce" attack on ECDSA using CVP and SVP for parameters mentioned below

num_Experiments = 100
N = 256
L = 128
num_Samples = 5
list_x_CVP = []
list_x_SVP = []



with open('unit_test_partial_nonce_inputs_256_128_5.txt', 'r') as filehandle:
    for exp in range(num_Experiments):
        listoflists_k_MSB = []
        list_h = []
        list_r = []
        list_s = []
        for samp in range(num_Samples):
            line_space = filehandle.readline()
            line_k_MSB = filehandle.readline().split()
            list_k_MSB = []
            for bit in line_k_MSB:
                list_k_MSB.append(int(bit))
            listoflists_k_MSB.append(list_k_MSB)
            line_space = filehandle.readline()
            line_h_r_s = filehandle.readline().split()
            list_h.append(int(line_h_r_s[0]))
            list_r.append(int(line_h_r_s[1]))
            list_s.append(int(line_h_r_s[2]))
        x_recovered_cvp = recover_x_partial_nonce_CVP(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q)
        x_recovered_svp = recover_x_partial_nonce_SVP(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q)
        list_x_CVP.append(x_recovered_cvp)
        list_x_SVP.append(x_recovered_svp)



with open('unit_test_partial_nonce_outputs_CVP_256_128_5.txt', 'w') as filehandle:
    for x in list_x_CVP:
        filehandle.write('\n%d\n' % (x))
with open('unit_test_partial_nonce_outputs_SVP_256_128_5.txt', 'w') as filehandle:
    for x in list_x_SVP:
        filehandle.write('\n%d\n' % (x))



# Unit testing phase-2 of the "partial nonce" attack on ECDSA using CVP and SVP for parameters mentioned below


num_Experiments = 100
N = 256
L = 32
num_Samples = 10
list_x_CVP = []
list_x_SVP = []



with open('unit_test_partial_nonce_inputs_256_32_10.txt', 'r') as filehandle:
    for exp in range(num_Experiments):
        listoflists_k_MSB = []
        list_h = []
        list_r = []
        list_s = []
        for samp in range(num_Samples):
            line_space = filehandle.readline()
            line_k_MSB = filehandle.readline().split()
            list_k_MSB = []
            for bit in line_k_MSB:
                list_k_MSB.append(int(bit))
            listoflists_k_MSB.append(list_k_MSB)
            line_space = filehandle.readline()
            line_h_r_s = filehandle.readline().split()
            list_h.append(int(line_h_r_s[0]))
            list_r.append(int(line_h_r_s[1]))
            list_s.append(int(line_h_r_s[2]))
        x_recovered_cvp = recover_x_partial_nonce_CVP(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q)
        x_recovered_svp = recover_x_partial_nonce_SVP(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q)
        list_x_CVP.append(x_recovered_cvp)
        list_x_SVP.append(x_recovered_svp)



with open('unit_test_partial_nonce_outputs_CVP_256_32_10.txt', 'w') as filehandle:
    for x in list_x_CVP:
        filehandle.write('\n%d\n' % (x))
with open('unit_test_partial_nonce_outputs_SVP_256_32_10.txt', 'w') as filehandle:
    for x in list_x_SVP:
        filehandle.write('\n%d\n' % (x))



# Unit testing phase-3 of the "partial nonce" attack on ECDSA using CVP and SVP for parameters mentioned below

num_Experiments = 100
N = 256
L = 16
num_Samples = 20
list_x_CVP = []
list_x_SVP = []



with open('unit_test_partial_nonce_inputs_256_16_20.txt', 'r') as filehandle:
    for exp in range(num_Experiments):
        listoflists_k_MSB = []
        list_h = []
        list_r = []
        list_s = []
        for samp in range(num_Samples):
            line_space = filehandle.readline()
            line_k_MSB = filehandle.readline().split()
            list_k_MSB = []
            for bit in line_k_MSB:
                list_k_MSB.append(int(bit))
            listoflists_k_MSB.append(list_k_MSB)
            line_space = filehandle.readline()
            line_h_r_s = filehandle.readline().split()
            list_h.append(int(line_h_r_s[0]))
            list_r.append(int(line_h_r_s[1]))
            list_s.append(int(line_h_r_s[2]))
        x_recovered_cvp = recover_x_partial_nonce_CVP(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q)
        x_recovered_svp = recover_x_partial_nonce_SVP(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q)
        list_x_CVP.append(x_recovered_cvp)
        list_x_SVP.append(x_recovered_svp)



with open('unit_test_partial_nonce_outputs_CVP_256_16_20.txt', 'w') as filehandle:
    for x in list_x_CVP:
        filehandle.write('\n%d\n' % (x))
with open('unit_test_partial_nonce_outputs_SVP_256_16_20.txt', 'w') as filehandle:
    for x in list_x_SVP:
        filehandle.write('\n%d\n' % (x))



# Unit testing phase-4 of the "partial nonce" attack on ECDSA using CVP and SVP for parameters mentioned below

num_Experiments = 100
N = 256
L = 8
num_Samples = 60
list_x_CVP = []
list_x_SVP = []



with open('unit_test_partial_nonce_inputs_256_8_40.txt', 'r') as filehandle:
    for exp in range(num_Experiments):
        listoflists_k_MSB = []
        list_h = []
        list_r = []
        list_s = []
        for samp in range(num_Samples):
            line_space = filehandle.readline()
            line_k_MSB = filehandle.readline().split()
            list_k_MSB = []
            for bit in line_k_MSB:
                list_k_MSB.append(int(bit))
            listoflists_k_MSB.append(list_k_MSB)
            line_space = filehandle.readline()
            line_h_r_s = filehandle.readline().split()
            list_h.append(int(line_h_r_s[0]))
            list_r.append(int(line_h_r_s[1]))
            list_s.append(int(line_h_r_s[2]))
        x_recovered_cvp = recover_x_partial_nonce_CVP(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q)
        x_recovered_svp = recover_x_partial_nonce_SVP(N, L, num_Samples, listoflists_k_MSB, list_h, list_r, list_s, q)
        list_x_CVP.append(x_recovered_cvp)
        list_x_SVP.append(x_recovered_svp)



with open('unit_test_partial_nonce_outputs_CVP_256_8_40.txt', 'w') as filehandle:
    for x in list_x_CVP:
        filehandle.write('\n%d\n' % (x))
with open('unit_test_partial_nonce_outputs_SVP_256_8_40.txt', 'w') as filehandle:
    for x in list_x_SVP:
        filehandle.write('\n%d\n' % (x))