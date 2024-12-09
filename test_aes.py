import unittest
import numpy as np
import aes_cipher
from aes_cipher import AES


class AesTest(unittest.TestCase):
    def test_sub_bytes(self):
        state_before = np.array((
            [0x19, 0xA0, 0x9A, 0xE9],
            [0x3D, 0xF4, 0xC6, 0xF8],
            [0xE3, 0xE2, 0x8D, 0x48],
            [0xBE, 0x2B, 0x2A, 0x08]
        ))

        state_expected = np.array((
            [0xD4, 0xE0, 0xB8, 0x1E],
            [0x27, 0xBF, 0xB4, 0x41],
            [0x11, 0x98, 0x5D, 0x52],
            [0xAE, 0xF1, 0xE5, 0x30]
        ))

        aes = AES()
        aes.set_state(state_before)
        aes.sub_bytes()
        state_actual = aes.state

        print(state_expected)
        print(state_actual)
        self.assertTrue(np.array_equal(state_expected, state_actual))

    def test_shift_rows(self):
        state_before = np.array((
            [0x00, 0x01, 0x02, 0x03],
            [0x04, 0x05, 0x06, 0x07],
            [0x08, 0x09, 0x0A, 0x0B],
            [0x0C, 0x0D, 0x0E, 0x0F],
        ))

        aes = AES()
        aes.set_state(state_before)
        aes.shift_rows()
        state_expected = np.array((
            [0x00, 0x01, 0x02, 0x03],
            [0x05, 0x06, 0x07, 0x04],
            [0x0A, 0x0B, 0x08, 0x09],
            [0x0F, 0x0C, 0x0D, 0x0E]
        ))
        state_actual = aes.state
        self.assertTrue(np.array_equal(state_expected, state_actual))

    def test_inverse(self):
        aes = AES()
        inverse_table = aes.inverse_table
        self.assertEqual(0x00,inverse_table[0x00])
        self.assertEqual(0x1C, inverse_table[0xFF])
        self.assertEqual(0x5B, inverse_table[0xF0])
        self.assertEqual(0xC7, inverse_table[0x0F])
        self.assertEqual(0xB6, inverse_table[0x78])

    def test_mix_cols(self):
        pass

    def test_add_round_key(self):
        pass

    def test_encrypt(self):
        pass

    def test_decrypt(self):
        pass

    def test_encrypt_decrypt(self):
        pass

    def test_number_to_bit_vector(self):
        num_1 = 7  #0b00000111
        num_2 = 0  #0b00000000
        num_3 = 4  #0b00000100

        expected_1 = np.array([1,1,1,0,0,0,0,0], ndmin=2).T
        expected_2 = np.array([0, 0, 0, 0, 0, 0, 0, 0], ndmin=2).T
        expected_3 = np.array([0, 0, 1, 0, 0, 0, 0, 0], ndmin=2).T

        actual_1 = aes_cipher.int_to_8bit_vector(num_1)
        actual_2 = aes_cipher.int_to_8bit_vector(num_2)
        actual_3 = aes_cipher.int_to_8bit_vector(num_3)

        print(expected_1)
        print(actual_1)

        self.assertTrue(np.array_equal(expected_1, actual_1))
        self.assertTrue(np.array_equal(expected_2, actual_2))
        self.assertTrue(np.array_equal(expected_3, actual_3))
