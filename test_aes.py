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
        # There are test vectors on Wikipedia:
        # https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
        pass

    def test_mix_single_column(self):

        aes = AES()
        vec1 = np.array([0x63,0x47,0xa2,0xf0], ndmin=2).T
        vec2 = np.array([0xf2, 0x0a, 0x22, 0x5c], ndmin=2).T
        vec3 = np.array([0x01, 0x01, 0x01, 0x01], ndmin=2).T
        vec4 = np.array([0xc6, 0xc6, 0xc6, 0xc6], ndmin=2).T
        vec5 = np.array([0xd4, 0xd4, 0xd4, 0xd5], ndmin=2).T
        vec6 = np.array([0x2d, 0x26, 0x31, 0x4c], ndmin=2).T
        vec7 = np.array([0x00, 0x00, 0x00, 0x00], ndmin=2).T

        vec1_mixed = np.array([0x5d,0xe0,0x70,0xbb],ndmin=2).T
        vec2_mixed = np.array([0x9f, 0xdc, 0x58, 0x9d], ndmin=2).T
        vec3_mixed = np.array([0x01, 0x01, 0x01, 0x01], ndmin=2).T
        vec4_mixed = np.array([0xc6,0xc6, 0xc6, 0xc6], ndmin=2).T
        vec5_mixed = np.array([0xd5,0xd5, 0xd7, 0xd6], ndmin=2).T
        vec6_mixed = np.array([0x4d,0x7e,0xbd, 0xf8], ndmin=2).T
        vec7_mixed = np.array([0x00, 0x00, 0x00, 0x00], ndmin=2).T

        actual_mixed_1 = aes.mix_single_column(vec1)
        actual_mixed_2 = aes.mix_single_column(vec2)
        actual_mixed_3 = aes.mix_single_column(vec3)
        actual_mixed_4 = aes.mix_single_column(vec4)
        actual_mixed_5 = aes.mix_single_column(vec5)
        actual_mixed_6 = aes.mix_single_column(vec6)
        actual_mixed_7 = aes.mix_single_column(vec7)

        self.assertTrue(np.array_equal(vec1_mixed, actual_mixed_1))
        self.assertTrue(np.array_equal(vec2_mixed, actual_mixed_2))
        self.assertTrue(np.array_equal(vec3_mixed, actual_mixed_3))
        self.assertTrue(np.array_equal(vec4_mixed, actual_mixed_4))
        self.assertTrue(np.array_equal(vec5_mixed, actual_mixed_5))
        self.assertTrue(np.array_equal(vec6_mixed, actual_mixed_6))
        self.assertTrue(np.array_equal(vec7_mixed, actual_mixed_7))

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

        self.assertTrue(np.array_equal(expected_1, actual_1))
        self.assertTrue(np.array_equal(expected_2, actual_2))
        self.assertTrue(np.array_equal(expected_3, actual_3))
