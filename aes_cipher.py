import numpy as np
from polynomial_helper import multiplicative_inverse, Polynomial


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
        element_vector = int_to_8bit_vector(element)
        print("Element vector:")
        print(element_vector)
        result = np.dot(self.sbox_affine_transform_matrix, element_vector)
        print("Multiplied by matrix:")
        print(result)
        result = result + self.sbox_affine_transform_vector
        print("With added vector:")
        print(result)
        result = result.T[0].tolist()
        result = "".join((str(i % 2) for i in result)).ljust(8, "0")
        result = int(result, 2)
        return result


def sbox_get_polynomial(number: int) -> Polynomial:
    # Used only for getting the inverse tables for lookup

    binary_representation = bin(number).replace("0b", "")
    binary_representation = list(reversed(binary_representation))
    coeff_list = [int(i) for i in binary_representation]
    return Polynomial(coeff_list)


def int_to_8bit_vector(number: int):
    binary_representation = bin(number).replace("0b", "")
    binary_representation = binary_representation.rjust(8, "0")
    binary_list = [int(i) for i in binary_representation]
    return np.array(binary_list, ndmin=2).T


aes_instance = AES()

print(aes_instance.inverse_table)
