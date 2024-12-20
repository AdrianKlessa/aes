from polynomial_helper import Polynomial
import numpy as np


def int_to_8bit_vector(number: int):
    """
    Given an integer from the range 0-255 returns its 8-bit vector representation consistent with the one required by
    the affine transformation used in the AES S-box
    """
    binary_representation = bin(number).replace("0b", "")
    binary_representation = binary_representation.rjust(8, "0")
    binary_list = [int(i) for i in binary_representation][::-1]
    return np.array(binary_list, ndmin=2).T



def rot_word(word):
    """
    Perform a single rotation on a 4-byte word. Used in the AES key schedule.
    """
    return np.roll(word, -1)

def expanded_key_to_round_key(round_id, expanded_key):
    start_index = round_id*16
    return np.array((
        [expanded_key[start_index], expanded_key[start_index+4], expanded_key[start_index+8], expanded_key[start_index+12]],
        [expanded_key[start_index+1], expanded_key[start_index+5], expanded_key[start_index+9], expanded_key[start_index+13]],
        [expanded_key[start_index+2], expanded_key[start_index+6], expanded_key[start_index+10], expanded_key[start_index+14]],
        [expanded_key[start_index+3], expanded_key[start_index+7], expanded_key[start_index+11], expanded_key[start_index+15]]
    ))

def sbox_get_polynomial(number: int) -> Polynomial:
    """
    Returns the polynomial representation of an input number in Rijndael's finite field
    :param number: Number to represent as a polynomial
    :return: Polynomial representation of the number
    """
    binary_representation = bin(number).replace("0b", "")
    binary_representation = list(reversed(binary_representation))
    coeff_list = [int(i) for i in binary_representation]
    return Polynomial(coeff_list)