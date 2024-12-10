import numpy as np
from polynomial_helper import multiplicative_inverse, Polynomial

def sbox_get_polynomial(number: int) -> Polynomial:
    # Used only for getting the inverse tables for lookup
    # TODO: Potentially change this description xd
    binary_representation = bin(number).replace("0b", "")
    binary_representation = list(reversed(binary_representation))
    coeff_list = [int(i) for i in binary_representation]
    return Polynomial(coeff_list)
class AES:
    sbox_affine_transform_matrix = np.array((
        [1, 0, 0, 0, 1, 1, 1, 1],
        [1, 1, 0, 0, 0, 1, 1, 1],
        [1, 1, 1, 0, 0, 0, 1, 1],
        [1, 1, 1, 1, 0, 0, 0, 1],
        [1, 1, 1, 1, 1, 0, 0, 0],
        [0, 1, 1, 1, 1, 1, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 0],
        [0, 0, 0, 1, 1, 1, 1, 1]
    ))

    sbox_affine_transform_vector = np.array([1, 1, 0, 0, 0, 1, 1, 0], dtype=int, ndmin=2).T

    sbox_inverse_affine_transform_matrix = np.array((
        [0, 0, 1, 0, 0, 1, 0, 1],
        [1, 0, 0, 1, 0, 0, 1, 0],
        [0, 1, 0, 0, 1, 0, 0, 1],
        [1, 0, 1, 0, 0, 1, 0, 0],
        [0, 1, 0, 1, 0, 0, 1, 0],
        [0, 0, 1, 0, 1, 0, 0, 1],
        [1, 0, 0, 1, 0, 1, 0, 0],
        [0, 1, 0, 0, 1, 0, 1, 0]
    ))

    sbox_inverse_affine_transform_vector = np.array([1, 0, 1, 0, 0, 0, 0, 0], dtype=int, ndmin=2).T

    mix_columns_matrix = np.array((
        [sbox_get_polynomial(2),sbox_get_polynomial(3),sbox_get_polynomial(1),sbox_get_polynomial(1)],
        [sbox_get_polynomial(1),sbox_get_polynomial(2),sbox_get_polynomial(3),sbox_get_polynomial(1)],
        [sbox_get_polynomial(1), sbox_get_polynomial(1), sbox_get_polynomial(2), sbox_get_polynomial(3)],
        [sbox_get_polynomial(3), sbox_get_polynomial(1), sbox_get_polynomial(1), sbox_get_polynomial(2)],
    ))


    def __init__(self):
        self.state = np.empty((4, 4), dtype=int)  # Make sure all entries are 0-255
        self.inverse_table = self.generate_inverse_table()

    def sub_bytes(self):
        # This whole thing can be substituted with a lookup table for MUCH faster calculations
        # At the cost of potentially introducing cache-based attacks
        for (i, j), value in np.ndenumerate(self.state):
            result = self.inverse_table[value]
            result = self.sbox_affine_transform(result)
            self.state[i][j] = result

    def shift_rows(self):
        for i in range(1, 4):
            self.state[i] = np.roll(self.state[i], shift=-i)

    def mix_columns(self):
        pass

    def mix_single_column(self, column):
        # TODO: Clean this up
        print(column.shape)
        print(column)
        print("0x53 as a polynomial:")
        print(sbox_get_polynomial(0x53))
        print("0x2d as a polynomial:")
        print(sbox_get_polynomial(0x2d))
        modulo_polynomial = Polynomial([1, 1, 0, 1, 1, 0, 0, 0, 1])
        vector_poly = np.array([sbox_get_polynomial(column[0][0]),
                                sbox_get_polynomial(column[1][0]),
                                sbox_get_polynomial(column[2][0]),
                                sbox_get_polynomial(column[3][0])], ndmin=2).T

        d0 = sbox_get_polynomial(column[0][0])
        d1 = sbox_get_polynomial(column[1][0])
        d2 = sbox_get_polynomial(column[2][0])
        d3 = sbox_get_polynomial(column[3][0])
        print("Supposedly first result:")
        print(reduce_element_modulo(Polynomial([2])*d0 + Polynomial([3])*d1+Polynomial([1])*d2+Polynomial([1])*d3,Polynomial([1,1,0,1,1,0,0,0,1]),2))
        print("vector poly:")
        print(vector_poly)
        result = np.dot(self.mix_columns_matrix, vector_poly)
        #reduce_array_modulo(result, Polynomial([1, 1, 0, 1, 1, 0, 0, 0, 1]), 2)
        #reduce_array_modulo(result, Polynomial([1,0,0,0,1]), 2)
        reduce_array_modulo(result, Polynomial([1, 1, 0, 1, 1, 0, 0, 0, 1]), 2)
        print("result:")
        print(result)
        print(result.shape)
        result_int = []
        for (i,j), element in np.ndenumerate(result):
            print("a")
            _, el = element.divide_by(modulo_polynomial, 2)
            print(f"element: {el}")
            print(f"coefficients: {el.coefficients.tolist()}")
            int_coefficients = el.coefficients.tolist()
            binary_repr = "".join((str(i) for i in int_coefficients))
            binary_repr = binary_repr[::-1].rjust(8, "0")
            print(f"binary_repr: {binary_repr}")
            integer_repr = int(binary_repr, 2)
            result_int.append(integer_repr)
        print(result_int)
        return np.array(result_int, ndmin=2).T



    def add_round_key(self):
        pass

    def encrypt(self, plain_text):
        pass

    def decrypt(self, encrypted_text):
        pass

    def set_state(self, state):
        self.state = state

    def generate_inverse_table(self):
        inverse_table = {0: 0}
        modulo_polynomial = Polynomial([1, 1, 0, 1, 1, 0, 0, 0, 1])
        for i in range(1, 256):
            poly = sbox_get_polynomial(i)
            inv_poly = poly.get_inverse(modulo_polynomial, 2)
            int_coefficients = inv_poly.coefficients.tolist()
            binary_inverse = "".join((str(i) for i in int_coefficients)).ljust(8, "0")
            binary_inverse = binary_inverse[::-1]
            inv = int(binary_inverse, 2)
            inverse_table[i] = inv
        return inverse_table

    def sbox_affine_transform(self, element: int) -> int:
        # The vectors representing the bytes are from top to bottom from the least significant to most significant bits
        element_vector = int_to_8bit_vector(element)
        result = np.dot(self.sbox_affine_transform_matrix, element_vector)%2
        result = (result + self.sbox_affine_transform_vector) %2
        result = result.T[0].tolist()[::-1]
        result = "".join((str(i%2) for i in result)).ljust(8, "0")
        result = int(result, 2)
        return result


def mix_cols_get_polynomial(number: int) -> Polynomial:
    binary_representation = bin(number).replace("0b", "")
    binary_representation = list(reversed(binary_representation))
    coeff_list = [int(i) for i in binary_representation]
    return Polynomial(coeff_list)

def int_to_8bit_vector(number: int):
    binary_representation = bin(number).replace("0b", "")
    binary_representation = binary_representation.rjust(8, "0")
    binary_list = [int(i) for i in binary_representation][::-1]
    return np.array(binary_list, ndmin=2).T

def reduce_array_modulo(array, modulus_polynomial, modulus_number):
    for (i, j), value in np.ndenumerate(array):
        array[i][j] = reduce_element_modulo(array[i][j],modulus_polynomial, modulus_number)

def reduce_element_modulo(p: Polynomial, modulus_polynomial, modulus_number):
    a = p.reduced_modulo_scalar(modulus_number)
    _, a = a.divide_by(modulus_polynomial, modulus_number)
    return a