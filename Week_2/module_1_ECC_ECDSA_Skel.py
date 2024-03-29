import math
import random
import warnings
import hashlib

# Euclidean algorithm for gcd computation
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

# Function to map a message to a bit string
def hash_message_to_bits(msg):
    h = hashlib.sha256()
    h.update(msg.encode())
    h_as_bits = ''.join(format(byte, '08b') for byte in h.digest())
    return h_as_bits 

# Function to map a truncated bit string to an integer modulo q
def bits_to_int(h_as_bits, q):
    val = 0
    len = int(math.log(q, 2) + 1)
    for i in range(len):
        val = val * 2
        if(h_as_bits[i] == '1'):
            val = val + 1
    return val % q

# An elliptic curve is represented as an object of type Curve. 
# Note that for this lab, we use the short Weierstrass form of representation.
class Curve(object):

    def __init__(self, a, b, p, P_x, P_y, q):
        self.a = a
        self.b = b
        self.p = p
        self.P_x = P_x
        self.P_y = P_y
        self.q = q

    def is_singular(self):
        return (4 * self.a**3 + 27 * self.b**2) % self.p == 0

    def on_curve(self, x, y):
        return (y**2 - x**3 - self.a * x - self.b) % self.p == 0

    def is_equal(self, other):
        if not isinstance(other, Curve):
            return False
        return self.a == other.a and self.b == other.b and self.p == other.p

# A point at infinity on an elliptic curve is represented separately as an object of type PointInf. 
# We make this distinction between a point at infinity and a regular point purely for the ease of implementation.
class PointInf(object):

    def __init__(self, curve):
        self.curve = curve

    def is_equal(self, other):
        if not isinstance(other, PointInf):
            return False
        return self.curve.is_equal(other.curve)
    
    def negate(self):
        # Write a function that negates a PointInf object.        
        # Ths is an optional extension and is not evaluated
        return PointInf(self.curve)
        # raise NotImplementedError()

    def double(self):
        # Write a function that doubles a PointInf object.
        result = PointInf(self.curve)
        return result
        # raise NotImplementedError()

    def add(self, other):
        # Write a function that adds a Point object (or a PointInf object) to a PointInf object. 
        # See below for the description of a Point object
        # Make sure to output the correct kind of object depending on whether "other" is a Point object or a PointInf object 
        if isinstance(other, PointInf):
            result = PointInf(self.curve)
            return result
        else:
            return other
        # raise NotImplementedError()


# A point on an elliptic curve is represented as an object of type Point. 
# Note that for this lab, we will use the affine coordinates-based representation of a point on an elliptic curve.
class Point(object):

    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y
        self.p = self.curve.p
        self.on_curve = True
        if not self.curve.on_curve(self.x, self.y):
            warnings.warn("Point (%d, %d) is not on curve \"%s\"" % (self.x, self.y, self.curve))
            self.on_curve = False

    def is_equal(self, other):
        if not isinstance(other, Point):
            return False
        return self.curve.is_equal(other.curve) and self.x == other.x and self.y == other.y
    
    def negate(self):
        # Write a function that negates a Point object and returns the resulting Point object
        # Ths is an optional extension and is not evaluated
        new_point = Point(self.curve, x, -y)
        return new_point
        # raise NotImplementedError()

    def double(self):
        # Write a function that doubles a Point object and returns the resulting Point object

        # I use theta here to represent lambda to avoid the python keyword
        a = self.curve.a
        theta = (   (3 * (self.x ** 2) + a) *  mod_inv((2 * self.y), self.p)   ) % self.p
        x_dot = ((theta ** 2) -  (2 * self.x )) % self.p
        y_dot = (- (self.y + theta * (x_dot - self.x))) % self.p
        return Point(self.curve, x_dot, y_dot)
        # raise NotImplementedError()

    def add(self, other):
        # Write a function that adds a Point object (or a PointInf object) to the current Point object and returns the resulting Point object
        if isinstance(other, PointInf):
            return self
        else:
            if self.is_equal(other):
                return self.double()
            else:
                if (self.x == other.x) and (self.y != other.y):
                    return PointInf(self.curve)

                slope = (self.y - other.y) * mod_inv( (self.x - other.x) , self.p) % self.p
                x_dot = ((slope ** 2) - self.x - other.x) % self.p
                y_dot = -(self.y + slope * (x_dot - self.x)) % self.p
                return Point(self.curve, x_dot, y_dot)
        # raise NotImplementedError()

    # Note scalar_multiply with 0 -> PointInf
    def scalar_multiply(self, scalar):
        # Write a function that performs a scalar multiplication on the current Point object and returns the resulting Point object 
        # Make sure to check that the scalar is of type int or long
        # Your function need not be "constant-time"
        new_scalar = scalar % self.curve.q
        binary_scalar = str(bin(new_scalar)[2:])
        result = PointInf(self.curve)
        for i in binary_scalar:
            if i == '1':
                result = result.double()
                result = result.add(self)
            else:
                result = result.double()
        return result

        # if scalar == 0:
        #     return PointInf(self.curve)
        # else:
        #     result = Point(self.curve, self.x, self.y)
        #     for i in binary_scalar:
        #         if i == 1:

        #     return result
        # raise NotImplementedError()

    def scalar_multiply_Montgomery_Ladder(self, scalar):
        # Write a function that performs a "constant-time" scalar multiplication on the current Point object and returns the resulting Point object 
        # Make sure to check that the scalar is of type int or long
        # Implement an elementary timer to check that your implementation is indeed constant-time
        # This is not graded but is an extension for your to try out on your own
        raise NotImplementedError()


# The parameters for an ECDSA scheme are represented as an object of type ECDSA_Params
class ECDSA_Params(object):
    def __init__(self, a, b, p, P_x, P_y, q):
        self.p = p
        self.q = q
        self.curve = Curve(a, b, p, P_x, P_y, q)
        self.P = Point(self.curve, P_x, P_y)


def KeyGen(params):
    # Write a function that takes as input an ECDSA_Params object and outputs the key pair (x, Q)
    random_scalar = random.randint(0, params.q - 1)
    Q = params.P.scalar_multiply(random_scalar)
    return (random_scalar, Q)
    # raise NotImplementedError()

def Sign_FixedNonce(params, k, x, msg):
    # Write a function that takes as input an ECDSA_Params object, a fixed nonce k, a signing key x, and a message msg, and outputs a signature (r, s)
    h = bits_to_int(hash_message_to_bits(msg), params.q) % params.q
    r = 0
    s = 0
    kp = params.P.scalar_multiply(k)
    while (r == 0 or s == 0):
        r = kp.x % params.q
        s = (mod_inv(k, params.q) * (h + x * r)) % params.q
    return (r,s)
    # raise NotImplementedError()

def Sign(params, x, msg):
    # Write a function that takes as input an ECDSA_Params object, a signing key x, and a message msg, and outputs a signature (r, s)
    # The nonce is to be generated uniformly at random in the appropriate range
    k = random.randint(0, params.q - 1 )
    h = bits_to_int(hash_message_to_bits(msg) , params.q) % params.q
    r = 0
    s = 0
    kp = params.P.scalar_multiply(k)
    while (r == 0 or s == 0):
        r = kp.x % params.q
        s = (mod_inv(k, params.q) * (h + x * r)) % params.q
    return (r,s)
    # raise NotImplementedError()

def Verify(params, Q, msg, r, s):
    # Write a function that takes as input an ECDSA_Params object, a verification key Q, a message msg, and a signature (r, s)
    # The output should be either 0 (indicating failure) or 1 (indicating success)
    if (1 <= r <= (params.q - 1) and 1 <= s <= (params.q - 1) ):
        w = mod_inv (s, params.q)
        h = bits_to_int(hash_message_to_bits(msg), params.q) % params.q
        u_1 = (w * h) % q
        u_2 = (w * r) % q
        Z = params.P.scalar_multiply(u_1).add(Q.scalar_multiply(u_2))
        if (Z.x % q == r):
            return 1
        else:
            return 0
    else:
        return 0
    # raise NotImplementedError()


#Parameters for NIST P-256:

a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc

b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296

P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

nistp256_params = ECDSA_Params(a, b, p, P_x, P_y, q)
msg = "Applied Crypto Group"

# The code below is for unit testing the various modules you are going to implement
# There are four modular tests for scalar multiplication, point addition, signing with fixed nonce and verification
# There s a final test for testing that the verification algorithm accepts signatures generated by the signing algorithm
# You can use the publc input and output files provided to you for testing the modules you have implemented
# Please note that we will use the SAME TESTS on private input and output files for evaluating your implementation
# DO NOT UPDATE THE TEST CODES BELOW since it will interfere with evaluating your implementation

# Unit testing for scalar multiplication

N_SAMPLES = 100
N_SAMPLES_2 = 10

scalar_mult_out = []

with open('unit_test_scalar_mult_inputs.txt', 'r') as filehandle:
    for i in range(N_SAMPLES):
        line_space = filehandle.readline()
        scalar_mult_inp = filehandle.readline().split()
        k = int(scalar_mult_inp[0])
        P1_x = int(scalar_mult_inp[1])
        P1_y = int(scalar_mult_inp[2])
        P1 = Point(nistp256_params.curve, P1_x, P1_y)
        P2 = P1.scalar_multiply(k)
        scalar_mult_out.append((P2.x, P2.y))

with open('unit_test_scalar_mult_outputs_temp.txt', 'w') as filehandle:
    for (P2_x, P2_y) in scalar_mult_out:
        filehandle.write('\n%d %d\n' % (P2_x, P2_y))

# Unit testing for point addition

point_add_out = []

with open('unit_test_point_addition_inputs.txt', 'r') as filehandle:
    for i in range(N_SAMPLES):
        line_space = filehandle.readline()
        point_add_inp = filehandle.readline().split()
        P1_x = int(point_add_inp[0])
        P1_y = int(point_add_inp[1])
        P2_x = int(point_add_inp[2])
        P2_y = int(point_add_inp[3])
        P1 = Point(nistp256_params.curve, P1_x, P1_y)
        P2 = Point(nistp256_params.curve, P2_x, P2_y)
        P3 = P1.add(P2)
        point_add_out.append((P3.x, P3.y))

with open('unit_test_point_addition_outputs_temp.txt', 'w') as filehandle:
    for (P3_x, P3_y) in point_add_out:
        filehandle.write('\n%d %d\n' % (P3_x, P3_y))

# Unit testing for sign with fixed nonce

sign_fixed_nonce_out = []
msg = "Unit Test for Sign with Fixed Nonce"

with open('unit_test_sign_fixed_nonce_inputs.txt', 'r') as filehandle:
    for i in range(N_SAMPLES):
        line_space = filehandle.readline()
        sign_fixed_nonce_inp = filehandle.readline().split()
        k = int(sign_fixed_nonce_inp[0])
        x = int(sign_fixed_nonce_inp[1])
        r, s = Sign_FixedNonce(nistp256_params, k, x, msg)
        sign_fixed_nonce_out.append((r, s))

with open('unit_test_sign_fixed_nonce_outputs_temp.txt', 'w') as filehandle:
    for (r, s) in sign_fixed_nonce_out:
        filehandle.write('\n%d %d\n' % (r, s))


# Unit testing for verify

verify_out = []
msg = "Unit Test for Verification"

with open('unit_test_verify_inputs.txt', 'r') as filehandle:
    for i in range(N_SAMPLES):
        line_space = filehandle.readline()
        verify_inp = filehandle.readline().split()
        Q_x = int(verify_inp[0])
        Q_y = int(verify_inp[1])
        r = int(verify_inp[2])
        s = int(verify_inp[3])
        Q = Point(nistp256_params.curve, Q_x, Q_y)
        verify_out.append(Verify(nistp256_params, Q, msg, r, s))

with open('unit_test_verify_outputs_temp.txt', 'w') as filehandle:
    for bit in verify_out:
        filehandle.write('\n%d\n' % bit)


def test_sign_and_verify():
    # Testing for sign + verify
    msg = "Unit Test for Sign and Verify Consistency"
    cnt_failure = 0

    for i in range(N_SAMPLES_2):
        x, Q = KeyGen(nistp256_params)
        for j in range(N_SAMPLES_2):
            r, s = Sign(nistp256_params, x, msg)
            if(Verify(nistp256_params, Q, msg, r, s) == 0):
                cnt_failure = cnt_failure + 1

    return cnt_failure

if __name__ == '__main__':
    if (test_sign_and_verify() > 0):
        raise TypeError("Inconsistency between signing and verification algorithms")