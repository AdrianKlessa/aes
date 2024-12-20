from typing import Optional, Sequence, Tuple

import numpy as np

import cipher_utils
from polynomial_helper import multiplicative_inverse, Polynomial


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


def get_ith_word(i: int, word_list: Sequence[int])-> Sequence[int]:
    """
    Given a list of integers, returns the ith 4-byte word on the list
    :param i: Index of the word to return
    :param word_list: List of integers
    :return: The ith word
    """
    return word_list[i * 4:i * 4 + 4]


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
        [sbox_get_polynomial(2), sbox_get_polynomial(3), sbox_get_polynomial(1), sbox_get_polynomial(1)],
        [sbox_get_polynomial(1), sbox_get_polynomial(2), sbox_get_polynomial(3), sbox_get_polynomial(1)],
        [sbox_get_polynomial(1), sbox_get_polynomial(1), sbox_get_polynomial(2), sbox_get_polynomial(3)],
        [sbox_get_polynomial(3), sbox_get_polynomial(1), sbox_get_polynomial(1), sbox_get_polynomial(2)],
    ))

    inverse_mix_columns_matrix = np.array((
        [sbox_get_polynomial(0x0e), sbox_get_polynomial(0x0b), sbox_get_polynomial(0x0d), sbox_get_polynomial(0x09)],
        [sbox_get_polynomial(0x09), sbox_get_polynomial(0x0e), sbox_get_polynomial(0x0b), sbox_get_polynomial(0x0d)],
        [sbox_get_polynomial(0x0d), sbox_get_polynomial(0x09), sbox_get_polynomial(0x0e), sbox_get_polynomial(0x0b)],
        [sbox_get_polynomial(0x0b), sbox_get_polynomial(0x0d), sbox_get_polynomial(0x09), sbox_get_polynomial(0x0e)],
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

    def inverse_sub_bytes(self):
        # Sub bytes would be its own inverse if we only used the lookup table (many implementations use that)
        for (i, j), value in np.ndenumerate(self.state):
            result = self.sbox_inverse_affine_transform(value)
            result = self.inverse_table[result]
            self.state[i][j] = result

    def shift_rows(self):
        for i in range(1, 4):
            self.state[i] = np.roll(self.state[i], shift=-i)

    def inverse_shift_rows(self):
        for i in range(1, 4):
            self.state[i] = np.roll(self.state[i], shift=i)

    def mix_columns(self):
        for i in range(4):
            self.state[:, [i]] = self.mix_single_column(self.state[:, [i]])

    def inverse_mix_columns(self):
        for i in range(4):
            self.state[:, [i]] = self.inverse_mix_single_column(self.state[:, [i]])

    def mix_single_column(self, column):
        """
        Given a 2d numpy array of shape (4,1) performs the MixColumns AES step on it
        :param column: 2d numpy array of shape (4,1)
        :return: Mixed column
        """
        vector_poly = np.array([sbox_get_polynomial(column[0][0]),
                                sbox_get_polynomial(column[1][0]),
                                sbox_get_polynomial(column[2][0]),
                                sbox_get_polynomial(column[3][0])], ndmin=2).T
        result = np.dot(self.mix_columns_matrix, vector_poly)
        reduce_array_modulo(result, Polynomial([1, 1, 0, 1, 1, 0, 0, 0, 1]), 2)
        result_int = []
        for (i, j), element in np.ndenumerate(result):
            int_coefficients = element.coefficients.tolist()
            binary_repr = "".join((str(i) for i in int_coefficients))
            binary_repr = binary_repr[::-1].rjust(8, "0")
            integer_repr = int(binary_repr, 2)
            result_int.append(integer_repr)
        return np.array(result_int, ndmin=2).T

    def inverse_mix_single_column(self, column):
        """
        Given a 2d numpy array of shape (4,1) performs the inverse MixColumns AES step on it
        :param column: 2d numpy array of shape (4,1)
        :return: Unmixed column
        """
        vector_poly = np.array([sbox_get_polynomial(column[0][0]),
                                sbox_get_polynomial(column[1][0]),
                                sbox_get_polynomial(column[2][0]),
                                sbox_get_polynomial(column[3][0])], ndmin=2).T
        result = np.dot(self.inverse_mix_columns_matrix, vector_poly)
        reduce_array_modulo(result, Polynomial([1, 1, 0, 1, 1, 0, 0, 0, 1]), 2)
        result_int = []
        for (i, j), element in np.ndenumerate(result):
            int_coefficients = element.coefficients.tolist()
            binary_repr = "".join((str(i) for i in int_coefficients))
            binary_repr = binary_repr[::-1].rjust(8, "0")
            integer_repr = int(binary_repr, 2)
            result_int.append(integer_repr)
        return np.array(result_int, ndmin=2).T

    def add_round_key(self, round_key_value):
        """
        Given a (4,4) shape numpy array representing the round key, XORs the round key with the cipher state
        :param round_key_value: A (4,4) numpy array representing the round key
        :return:
        """
        # Since it's just XOR it is its own inverse (X^Y^Y = X)
        self.state = np.bitwise_xor(self.state, round_key_value)

    def encrypt_bytes(self, message_bytes: Sequence[int], key: Sequence[int], number_of_rounds: int):
        """

        :param message_bytes: Message to encrypt, given as a sequence of 0-255 integers
        :param key: A key given as a sequence of 0-255 integers
        :param number_of_rounds: 10 for AES-128, 12 for AES-192, 14 for AES-256
        :return: Cipher's state after encryption (block with the encrypted message)
        """
        if len(message_bytes) != 16:
            raise ValueError("message_bytes must have 16 bytes")
        # TODO: Use the new cipher_utils function for this
        self.state = np.array((
            [message_bytes[0], message_bytes[4], message_bytes[8], message_bytes[12]],
            [message_bytes[1], message_bytes[5], message_bytes[9], message_bytes[13]],
            [message_bytes[2], message_bytes[6], message_bytes[10], message_bytes[14]],
            [message_bytes[3], message_bytes[7], message_bytes[11], message_bytes[15]]
        ))
        expanded_key = self.key_expansion(key, number_of_rounds+1)
        temp_key = expanded_key_to_round_key(0, expanded_key)
        self.add_round_key(temp_key)
        for i in range(1,number_of_rounds):
            self.sub_bytes()
            self.shift_rows()
            self.mix_columns()
            round_key = expanded_key_to_round_key(i, expanded_key)
            self.add_round_key(round_key)
        temp_key = expanded_key_to_round_key(number_of_rounds, expanded_key)
        self.sub_bytes()
        self.shift_rows()
        self.add_round_key(temp_key)
        return self.state

    def decrypt_bytes(self, message_bytes, key, number_of_rounds):
        """

        :param message_bytes: Message to encrypt, given as a sequence of 0-255 integers
        :param key: A key given as a sequence of 0-255 integers
        :param number_of_rounds: 10 for AES-128, 12 for AES-192, 14 for AES-256
        :return: Cipher's state after decryption (block with the decrypted message)
        """
        if len(message_bytes) != 16:
            raise ValueError("message_bytes must have 16 bytes")
        # TODO: Use the new cipher_utils function for this
        self.state = np.array((
            [message_bytes[0], message_bytes[4], message_bytes[8], message_bytes[12]],
            [message_bytes[1], message_bytes[5], message_bytes[9], message_bytes[13]],
            [message_bytes[2], message_bytes[6], message_bytes[10], message_bytes[14]],
            [message_bytes[3], message_bytes[7], message_bytes[11], message_bytes[15]]
        ))
        expanded_key = self.key_expansion(key, number_of_rounds+1)
        temp_key = expanded_key_to_round_key(number_of_rounds, expanded_key)
        self.add_round_key(temp_key)
        self.inverse_shift_rows()
        self.inverse_sub_bytes()
        for i in reversed(range(1, number_of_rounds)):
            round_key = expanded_key_to_round_key(i, expanded_key)
            self.add_round_key(round_key)
            self.inverse_mix_columns()
            self.inverse_shift_rows()
            self.inverse_sub_bytes()
        temp_key = expanded_key_to_round_key(0, expanded_key)
        self.add_round_key(temp_key)
        return self.state

    def set_state(self, state):
        self.state = state

    def encrypt_message_cbc(self, message_bytes: Sequence[int], key: Sequence[int], number_of_rounds: int, iv: Optional[Sequence[int]] = None)->Tuple[Sequence[int], Sequence[int]]:
        """
        Encrypt a (potentially multi-block) message using CBC mode of operation.
        If IV is not provided, a random one will be generated
        :param message_bytes: Message to encrypt, given as a sequence of 0-255 integers
        :param key: A key given as a sequence of 0-255 integers
        :param number_of_rounds: 10 for AES-128, 12 for AES-192, 14 for AES-256
        :param iv: Initialization vector as a sequence of 0-255 integers. Should be random and not reused (nonce)
        :return: A tuple (encrypted message, initialization_vector)
        """
        if not iv:
            iv = cipher_utils.generate_iv()
        iv = cipher_utils.int_list_to_block(iv)
        no_blocks = len(message_bytes)//16
        blocks = []
        encrypted_blocks = []
        for i in range(no_blocks):
            block = message_bytes[i*16:(i+1)*16]
            block = cipher_utils.int_list_to_block(block)
            blocks.append(block)

        for i in range(no_blocks):
            if i ==0:
                blocks[0] = np.bitwise_xor(blocks[0], iv)
            else:
                blocks[i] = np.bitwise_xor(blocks[i], encrypted_blocks[i-1])
            encrypted_blocks.append(self.encrypt_bytes(cipher_utils.block_to_int_list(blocks[i]), key, number_of_rounds))
        encrypted_message = []
        for block in encrypted_blocks:
            encrypted_message.extend(cipher_utils.block_to_int_list(block))
        return encrypted_message, cipher_utils.block_to_int_list(iv)


    def decrypt_message_cbc(self, message_bytes: Sequence[int], key: Sequence[int], number_of_rounds: int, iv: Sequence[int]) ->Sequence[int]:
        """
        Decrypt a message encrypted with CBC mode of operation.
        :param message_bytes: Message to decrypt, given as a sequence of 0-255 integers
        :param key: A key given as a sequence of 0-255 integers
        :param number_of_rounds: 10 for AES-128, 12 for AES-192, 14 for AES-256
        :param iv: Initialization vector as a sequence of 0-255 integers. Has to be the same as the one used for encryption
        :return: Decrypted message as a sequence of 0-255 integers
        """
        iv = cipher_utils.int_list_to_block(iv)
        no_blocks = len(message_bytes) // 16
        blocks = []
        decrypted_blocks = []
        for i in range(no_blocks):
            block = message_bytes[i*16:(i+1)*16]
            block = cipher_utils.int_list_to_block(block)
            blocks.append(block)
        for i in range(no_blocks):
            decrypted_blocks.append(
                self.decrypt_bytes(cipher_utils.block_to_int_list(blocks[i]), key, number_of_rounds))
            if i ==0:
                decrypted_blocks[0] = np.bitwise_xor(decrypted_blocks[0], iv)
            else:
                decrypted_blocks[i] = np.bitwise_xor(decrypted_blocks[i], blocks[i-1])
        decrypted_message = []
        for block in decrypted_blocks:
            decrypted_message.extend(cipher_utils.block_to_int_list(block))
        return decrypted_message

    def encrypt_string(self, string_to_encrypt: str)->Tuple[Sequence[int], Sequence[int], Sequence[int]]:
        """
        High-level function to generate a key, iv and use them to encrypt a message.
        The key and IV has to be stored in order to later decrypt the message.
        :param string_to_encrypt: Message to encrypt
        :return: Tuple with the (encrypted_message, encryption_key, initialization_vector)
        """
        key = cipher_utils.generate_key_aes_256()
        iv = cipher_utils.generate_iv()
        message = cipher_utils.text_to_byte_list(string_to_encrypt)
        message = cipher_utils.pad_message(message)
        encrypted, iv = self.encrypt_message_cbc(message, key, 14, iv)
        return encrypted, key, iv

    def decrypt_string(self, message_bytes, key: list[int], iv: list[int]):
        """
        High-level function to reverse encrypt_string
        """
        decrypted = self.decrypt_message_cbc(message_bytes, key, 14, iv)
        message = cipher_utils.unpad_message(decrypted)
        message = cipher_utils.byte_list_to_text(message)
        return message
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
        result = np.dot(self.sbox_affine_transform_matrix, element_vector) % 2
        result = (result + self.sbox_affine_transform_vector) % 2
        result = result.T[0].tolist()[::-1]
        result = "".join((str(i % 2) for i in result)).ljust(8, "0")
        result = int(result, 2)
        return result

    def sbox_inverse_affine_transform(self, element: int)->int:
        element_vector = int_to_8bit_vector(element)
        result = np.dot(self.sbox_inverse_affine_transform_matrix, element_vector) % 2
        result = (result + self.sbox_inverse_affine_transform_vector) % 2
        result = result.T[0].tolist()[::-1]
        result = "".join((str(i % 2) for i in result)).ljust(8, "0")
        result = int(result, 2)
        return result

    def key_expansion(self, key: Sequence[int], no_rounds: int):
        # TODO: Maybe move this and the sub/rot words to another module or sth
        expanded_key = []
        N = len(key) // 4
        for i in range(4 * no_rounds):
            if i < N:
                expanded_key.extend(get_ith_word(i, word_list=key))
                continue
            if i >= N and i % N == 0:
                w_1 = get_ith_word(i - N, expanded_key)
                w_1 = np.array(w_1)
                w_2 = np.array(get_ith_word(i - 1, expanded_key))
                r_con_array = np.array((self.get_round_constant(i // N), 0, 0, 0))
                temp = np.bitwise_xor(w_1, self.sub_word(rot_word(w_2)))
                temp = np.bitwise_xor(temp, r_con_array)
                expanded_key.extend(temp.tolist())
                continue
            if i >= N > 6 and i % N == 4:
                w_1 = get_ith_word(i - N, expanded_key)
                w_1 = np.array(w_1)
                w_2 = np.array(get_ith_word(i - 1, expanded_key))
                w_2 = self.sub_word(w_2)
                temp = np.bitwise_xor(w_1, w_2)
                expanded_key.extend(temp.tolist())
                continue
            w_1 = get_ith_word(i - N, expanded_key)
            w_1 = np.array(w_1)
            w_2 = np.array(get_ith_word(i - 1, expanded_key))
            temp = np.bitwise_xor(w_1, w_2)
            expanded_key.extend(temp.tolist())
        return expanded_key

    def get_round_constant(self, i: int)->int:
        """
        Get the i-th round constant used in the AES key schedule
        """
        if i < 1:
            raise ValueError
        if i == 1:
            return 1
        rc_previous = self.get_round_constant(i - 1)
        if rc_previous < 0x80:
            return 2 * rc_previous % 256
        else:
            return ((2 * rc_previous) ^ 0x11b) % 256

    def sub_word(self, word: Sequence[int]):
        """
        Perform the AES S-box on every element of a 4-byte word.
        Used in the AES key schedule.
        """
        return np.array(
            (self.sbox(word[0]), self.sbox(word[1]), self.sbox(word[2]), self.sbox(word[3]))
        )

    def sbox(self, entry: int)->int:
        """
        Perform the AES S-box on a single byte (int from the range 0-255)
        """
        return self.sbox_affine_transform(self.inverse_table[entry])


def mix_cols_get_polynomial(number: int) -> Polynomial:
    """
    Given an integer from the range 0-255, returns its polynomial representation consistent with the one required by
    the AES MixColumns function
    """
    binary_representation = bin(number).replace("0b", "")
    binary_representation = list(reversed(binary_representation))
    coeff_list = [int(i) for i in binary_representation]
    return Polynomial(coeff_list)


def int_to_8bit_vector(number: int):
    """
    Given an integer from the range 0-255 returns its 8-bit vector representation consistent with the one required by
    the affine transformation used in the AES S-box
    """
    binary_representation = bin(number).replace("0b", "")
    binary_representation = binary_representation.rjust(8, "0")
    binary_list = [int(i) for i in binary_representation][::-1]
    return np.array(binary_list, ndmin=2).T


def reduce_array_modulo(array, modulus_polynomial, modulus_number):
    for (i, j), value in np.ndenumerate(array):
        array[i][j] = reduce_element_modulo(array[i][j], modulus_polynomial, modulus_number)


def reduce_element_modulo(p: Polynomial, modulus_polynomial, modulus_number):
    a = p.reduced_modulo_scalar(modulus_number)
    _, a = a.divide_by(modulus_polynomial, modulus_number)
    return a


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
