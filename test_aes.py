import unittest
import numpy as np
import aes_cipher
from aes_cipher import AES
import cipher_utils

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

    def test_inverse_sub_bytes(self):

        state_before = np.array((
            [0xD4, 0xE0, 0xB8, 0x1E],
            [0x27, 0xBF, 0xB4, 0x41],
            [0x11, 0x98, 0x5D, 0x52],
            [0xAE, 0xF1, 0xE5, 0x30]
        ))

        state_expected = np.array((
            [0x19, 0xA0, 0x9A, 0xE9],
            [0x3D, 0xF4, 0xC6, 0xF8],
            [0xE3, 0xE2, 0x8D, 0x48],
            [0xBE, 0x2B, 0x2A, 0x08]
        ))

        aes = AES()
        aes.set_state(state_before)
        aes.inverse_sub_bytes()
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


    def test_inverse_shift_rows(self):
        state_before = np.array((
            [0x00, 0x01, 0x02, 0x03],
            [0x05, 0x06, 0x07, 0x04],
            [0x0A, 0x0B, 0x08, 0x09],
            [0x0F, 0x0C, 0x0D, 0x0E]
        ))

        aes = AES()
        aes.set_state(state_before)
        aes.inverse_shift_rows()

        state_expected = np.array((
            [0x00, 0x01, 0x02, 0x03],
            [0x04, 0x05, 0x06, 0x07],
            [0x08, 0x09, 0x0A, 0x0B],
            [0x0C, 0x0D, 0x0E, 0x0F],
        ))

        state_actual = aes.state
        self.assertTrue(np.array_equal(state_expected, state_actual))

    def test_inverse(self):
        aes = AES()
        inverse_table = aes.inverse_table
        self.assertEqual(0x00, inverse_table[0x00])
        self.assertEqual(0x1C, inverse_table[0xFF])
        self.assertEqual(0x5B, inverse_table[0xF0])
        self.assertEqual(0xC7, inverse_table[0x0F])
        self.assertEqual(0xB6, inverse_table[0x78])

    def test_mix_cols(self):
        state_before = np.array((
            [0xd4, 0xe0, 0xb8, 0x1e],
            [0xbf, 0xb4, 0x41, 0x27],
            [0x5d, 0x52, 0x11, 0x98],
            [0x30, 0xae, 0xf1, 0xe5],
        ))

        aes = AES()
        aes.set_state(state_before)
        aes.mix_columns()
        state_expected = np.array((
            [0x04, 0xe0, 0x48, 0x28],
            [0x66, 0xcb, 0xf8, 0x06],
            [0x81, 0x19, 0xd3, 0x26],
            [0xe5, 0x9a, 0x7a, 0x4c]
        ))
        state_actual = aes.state
        self.assertTrue(np.array_equal(state_expected, state_actual))

    def test_inverse_mix_cols(self):
        state_before = np.array((
            [0x04, 0xe0, 0x48, 0x28],
            [0x66, 0xcb, 0xf8, 0x06],
            [0x81, 0x19, 0xd3, 0x26],
            [0xe5, 0x9a, 0x7a, 0x4c]
        ))

        aes = AES()
        aes.set_state(state_before)
        aes.inverse_mix_columns()

        state_expected = np.array((
            [0xd4, 0xe0, 0xb8, 0x1e],
            [0xbf, 0xb4, 0x41, 0x27],
            [0x5d, 0x52, 0x11, 0x98],
            [0x30, 0xae, 0xf1, 0xe5],
        ))

        state_actual = aes.state
        self.assertTrue(np.array_equal(state_expected, state_actual))

    def test_mix_single_column(self):
        # There are test vectors on Wikipedia:
        # https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
        aes = AES()
        vec1 = np.array([0x63, 0x47, 0xa2, 0xf0], ndmin=2).T
        vec2 = np.array([0xf2, 0x0a, 0x22, 0x5c], ndmin=2).T
        vec3 = np.array([0x01, 0x01, 0x01, 0x01], ndmin=2).T
        vec4 = np.array([0xc6, 0xc6, 0xc6, 0xc6], ndmin=2).T
        vec5 = np.array([0xd4, 0xd4, 0xd4, 0xd5], ndmin=2).T
        vec6 = np.array([0x2d, 0x26, 0x31, 0x4c], ndmin=2).T
        vec7 = np.array([0x00, 0x00, 0x00, 0x00], ndmin=2).T

        vec1_mixed = np.array([0x5d, 0xe0, 0x70, 0xbb], ndmin=2).T
        vec2_mixed = np.array([0x9f, 0xdc, 0x58, 0x9d], ndmin=2).T
        vec3_mixed = np.array([0x01, 0x01, 0x01, 0x01], ndmin=2).T
        vec4_mixed = np.array([0xc6, 0xc6, 0xc6, 0xc6], ndmin=2).T
        vec5_mixed = np.array([0xd5, 0xd5, 0xd7, 0xd6], ndmin=2).T
        vec6_mixed = np.array([0x4d, 0x7e, 0xbd, 0xf8], ndmin=2).T
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

    def test_inverse_mix_single_column(self):
        # Copied from above but reversed
        aes = AES()

        vec1 = np.array([0x5d, 0xe0, 0x70, 0xbb], ndmin=2).T
        vec2 = np.array([0x9f, 0xdc, 0x58, 0x9d], ndmin=2).T
        vec3 = np.array([0x01, 0x01, 0x01, 0x01], ndmin=2).T
        vec4 = np.array([0xc6, 0xc6, 0xc6, 0xc6], ndmin=2).T
        vec5 = np.array([0xd5, 0xd5, 0xd7, 0xd6], ndmin=2).T
        vec6 = np.array([0x4d, 0x7e, 0xbd, 0xf8], ndmin=2).T
        vec7 = np.array([0x00, 0x00, 0x00, 0x00], ndmin=2).T

        vec1_mixed = np.array([0x63, 0x47, 0xa2, 0xf0], ndmin=2).T
        vec2_mixed = np.array([0xf2, 0x0a, 0x22, 0x5c], ndmin=2).T
        vec3_mixed = np.array([0x01, 0x01, 0x01, 0x01], ndmin=2).T
        vec4_mixed = np.array([0xc6, 0xc6, 0xc6, 0xc6], ndmin=2).T
        vec5_mixed = np.array([0xd4, 0xd4, 0xd4, 0xd5], ndmin=2).T
        vec6_mixed = np.array([0x2d, 0x26, 0x31, 0x4c], ndmin=2).T
        vec7_mixed = np.array([0x00, 0x00, 0x00, 0x00], ndmin=2).T

        actual_mixed_1 = aes.inverse_mix_single_column(vec1)
        actual_mixed_2 = aes.inverse_mix_single_column(vec2)
        actual_mixed_3 = aes.inverse_mix_single_column(vec3)
        actual_mixed_4 = aes.inverse_mix_single_column(vec4)
        actual_mixed_5 = aes.inverse_mix_single_column(vec5)
        actual_mixed_6 = aes.inverse_mix_single_column(vec6)
        actual_mixed_7 = aes.inverse_mix_single_column(vec7)

        self.assertTrue(np.array_equal(vec1_mixed, actual_mixed_1))
        self.assertTrue(np.array_equal(vec2_mixed, actual_mixed_2))
        self.assertTrue(np.array_equal(vec3_mixed, actual_mixed_3))
        self.assertTrue(np.array_equal(vec4_mixed, actual_mixed_4))
        self.assertTrue(np.array_equal(vec5_mixed, actual_mixed_5))
        self.assertTrue(np.array_equal(vec6_mixed, actual_mixed_6))
        self.assertTrue(np.array_equal(vec7_mixed, actual_mixed_7))

    def test_add_round_key(self):
        state_before = np.array((
            [0x04, 0xe0, 0x48, 0x28],
            [0x66, 0xcb, 0xf8, 0x06],
            [0x81, 0x19, 0xd3, 0x26],
            [0xe5, 0x9a, 0x7a, 0x4c]
        ))

        round_key_value = np.array((
            [0xa0, 0x88, 0x23, 0x2a],
            [0xfa, 0x54, 0xa3, 0x6c],
            [0xfe, 0x2c, 0x39, 0x76],
            [0x17, 0xb1, 0x39, 0x05]
        ))

        aes = AES()
        aes.set_state(state_before)
        aes.add_round_key(round_key_value)
        state_expected = np.array((
            [0xa4, 0x68, 0x6b, 0x02],
            [0x9c, 0x9f, 0x5b, 0x6a],
            [0x7f, 0x35, 0xea, 0x50],
            [0xf2, 0x2b, 0x43, 0x49]
        ))
        state_actual = aes.state
        self.assertTrue(np.array_equal(state_expected, state_actual))

    def test_encrypt(self):
        aes = AES()
        message = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
        key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        expected = np.array((
            [0x39, 0x02, 0xdc, 0x19],
            [0x25, 0xdc, 0x11, 0x6a],
            [0x84, 0x09, 0x85, 0x0b],
            [0x1d, 0xfb, 0x97, 0x32]
        ))

        actual = aes.encrypt_bytes(message, key, 10)
        self.assertTrue(np.array_equal(expected, actual))

    def test_decrypt(self):
        aes = AES()
        encrypted = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]
        key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]

        actual_message = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]

        decrypted = aes.decrypt_bytes(encrypted, key, 10)
        self.assertTrue(np.array_equal(actual_message, cipher_utils.block_to_int_list(decrypted)))

    def test_cbc(self):
        aes = AES()
        message = [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                   0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
                   0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
                   0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10]

        expected_ciphertext = [0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
                               0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2,
                               0x73,0xbe,0xd6,0xb8,0xe3,0xc1,0x74,0x3b,0x71,0x16,0xe6,0x9e,0x22,0x22,0x95,0x16,
                               0x3f,0xf1,0xca,0xa1,0x68,0x1f,0xac,0x09,0x12,0x0e,0xca,0x30,0x75,0x86,0xe1,0xa7]

        key = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]

        iv = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]

        actual_ciphertext, iv_returned = aes.encrypt_message_cbc(message, key, 10, iv)
        actual_decrypted = aes.decrypt_message_cbc(expected_ciphertext, key, 10, iv)
        self.assertTrue(np.array_equal(expected_ciphertext, actual_ciphertext))
        self.assertSequenceEqual(message, actual_decrypted)
        self.assertSequenceEqual(iv, iv_returned)

    def test_encrypt_string(self):
        aes = AES()
        message = """
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:.  -*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:      .=%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@-         :=-::-+%@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*                 =@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*-.                   :%@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+.                       -@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#.                          %@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#                            .@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:                             -@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#                               #@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#.                              -@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+                               @@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%+-:                           *@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#                           +@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=                           =@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#.                         -@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+                        -@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.   +=                  -@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@-   -.                  -@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%                   :-  -@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#-==--*@@@@@@@@@@@@@@@@@@@@@                  --*:=-@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@#:        -@@@@@@@@@@@@@@@@@@@#                  -@%##%@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@.          %@@@@@@@@@@@@@@*==*                   :@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@%           *@@@@@@@@@@@@@@.                       #@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@-           :-=*#%@@@@@@@#.                       %@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@%-                .:=*%#-                         *@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@#=:.                                            :@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:                                          #@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+                                           -#=::*@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%                                             :-=#@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=                                             #@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%                      +                       -@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%.                     =*                        =@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:                      @=                         +@@@@@@@@@@@@@@@
"""
        encrypted, key, iv = aes.encrypt_string(message)
        decrypted = aes.decrypt_string(encrypted,key, iv)
        self.assertEqual(message,decrypted)
    def test_number_to_bit_vector(self):
        num_1 = 7  #0b00000111
        num_2 = 0  #0b00000000
        num_3 = 4  #0b00000100

        expected_1 = np.array([1, 1, 1, 0, 0, 0, 0, 0], ndmin=2).T
        expected_2 = np.array([0, 0, 0, 0, 0, 0, 0, 0], ndmin=2).T
        expected_3 = np.array([0, 0, 1, 0, 0, 0, 0, 0], ndmin=2).T

        actual_1 = aes_cipher.int_to_8bit_vector(num_1)
        actual_2 = aes_cipher.int_to_8bit_vector(num_2)
        actual_3 = aes_cipher.int_to_8bit_vector(num_3)

        self.assertTrue(np.array_equal(expected_1, actual_1))
        self.assertTrue(np.array_equal(expected_2, actual_2))
        self.assertTrue(np.array_equal(expected_3, actual_3))

    def test_rot_word(self):
        word1 = np.array((0x0a, 0x0b, 0x0c, 0x0d))
        expected = np.array((0x0b, 0x0c, 0x0d, 0x0a))
        actual = aes_cipher.rot_word(word1)
        self.assertTrue(np.array_equal(expected, actual))

    def test_key_expansion_11_rounds(self):
        # AES-128
        aes = AES()
        key_to_expand = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        keys_actual = aes.key_expansion(key_to_expand, 11)
        expected_beginning = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
                              0x3c, 0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c,
                              0x76, 0x05]
        expected_end = [0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6]

        len_beginning = len(expected_beginning)
        len_end = len(expected_end)

        self.assertSequenceEqual(keys_actual[:len_beginning], expected_beginning)
        self.assertSequenceEqual(keys_actual[-len_end:], expected_end)

    def test_key_expansion_13_rounds(self):
        # AES-192
        aes = AES()
        key_to_expand = [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                         0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b]
        keys_actual = aes.key_expansion(
            key_to_expand, 13)
        expected_beginning = [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79,
                              0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
                              0xfe, 0x0c, 0x91, 0xf7, 0x24, 0x02, 0xf5, 0xa5, 0xec, 0x12, 0x06, 0x8e, 0x6c, 0x82, 0x7f,
                              0x6b, 0x0e, 0x7a, 0x95, 0xb9, 0x5c, 0x56, 0xfe, 0xc2,
                              0x4d, 0xb7, 0xb4, 0xbd]
        expected_end = [0xe9, 0x8b, 0xa0, 0x6f, 0x44, 0x8c, 0x77, 0x3c, 0x8e, 0xcc, 0x72, 0x04, 0x01, 0x00, 0x22, 0x02]

        len_beginning = len(expected_beginning)
        len_end = len(expected_end)

        self.assertSequenceEqual(keys_actual[:len_beginning], expected_beginning)
        self.assertSequenceEqual(keys_actual[-len_end:], expected_end)

    def test_key_expansion_15_rounds(self):
        # AES-256
        aes = AES()
        key_to_expand = [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                         0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4]
        keys_actual = aes.key_expansion(
            key_to_expand, 15)
        expected_beginning = [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
                              0x81,
                              0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf,
                              0xf4,
                              0x9b, 0xa3, 0x54, 0x11, 0x8e, 0x69, 0x25, 0xaf, 0xa5, 0x1a, 0x8b, 0x5f, 0x20, 0x67, 0xfc,
                              0xde,
                              0xa8, 0xb0, 0x9c, 0x1a, 0x93, 0xd1, 0x94, 0xcd, 0xbe, 0x49, 0x84, 0x6e, 0xb7, 0x5d, 0x5b,
                              0x9a,
                              0xd5, 0x9a, 0xec, 0xb8]
        expected_end = [0xfe, 0x48, 0x90, 0xd1, 0xe6, 0x18, 0x8d, 0x0b, 0x04, 0x6d, 0xf3, 0x44, 0x70, 0x6c, 0x63, 0x1e]

        len_beginning = len(expected_beginning)
        len_end = len(expected_end)

        self.assertSequenceEqual(keys_actual[:len_beginning], expected_beginning)
        self.assertSequenceEqual(keys_actual[-len_end:], expected_end)

    def test_expanded_key_to_round_key(self):
        aes = AES()
        key_to_expand = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
        keys_actual = aes.key_expansion(key_to_expand, 11)
        actual_round_key = aes_cipher.expanded_key_to_round_key(2, keys_actual)
        # "round number 2" from the Appendix B - Cipher example
        expected_round_key = np.array((
            [0xf2, 0x7a, 0x59, 0x73],
            [0xc2, 0x96, 0x35, 0x59],
            [0x95, 0xb9, 0x80, 0xf6],
            [0xf2, 0x43, 0x7a, 0x7f]
        ))
        self.assertTrue(np.array_equal(expected_round_key, actual_round_key))
