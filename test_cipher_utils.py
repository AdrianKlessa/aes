import unittest
import cipher_utils

class CipherUtilsTest(unittest.TestCase):
    def test_padding(self):
        m1 = [4]*4 # Four 4s
        m2 = [0]*32 # 32 0s
        m3 = [7]*57

        m1_padded = cipher_utils.pad_message(m1)
        m2_padded = cipher_utils.pad_message(m2)
        m3_padded = cipher_utils.pad_message(m3)

        expected_1 = [4]*4 + [12]*12
        expected_2 = [0]*32 +[16]*16
        expected_3 = [7]*57 +[7]*7

        self.assertSequenceEqual(expected_1, m1_padded)
        self.assertSequenceEqual(expected_2, m2_padded)
        self.assertSequenceEqual(expected_3, m3_padded)
    def test_unpadding(self):
        m1 = [4] * 4 + [12] * 12
        m2 = [0] * 32 + [16] * 16
        m3 = [7] * 57 + [7] * 7
        m4 = [16] * 16 + [16] * 16
        unpadded_1 = cipher_utils.unpad_message(m1)
        unpadded_2 = cipher_utils.unpad_message(m2)
        unpadded_3 = cipher_utils.unpad_message(m3)
        unpadded_4 = cipher_utils.unpad_message(m4)

        expected_1 = [4] * 4
        expected_2 = [0] * 32
        expected_3 = [7] * 57
        expected_4 = [16] * 16

        self.assertSequenceEqual(expected_1, unpadded_1)
        self.assertSequenceEqual(expected_2, unpadded_2)
        self.assertSequenceEqual(expected_3, unpadded_3)
        self.assertSequenceEqual(expected_4, unpadded_4)


    def test_pad_unpad(self):
        m1 = [i for i in range(4)]
        m2 = [i for i in range(16)]
        m3 = [i for i in range(32)]
        m4 = [i for i in range(58)]

        m1_padded = cipher_utils.pad_message(m1)
        m2_padded = cipher_utils.pad_message(m2)
        m3_padded = cipher_utils.pad_message(m3)
        m4_padded = cipher_utils.pad_message(m4)

        m1_unpadded = cipher_utils.unpad_message(m1_padded)
        m2_unpadded = cipher_utils.unpad_message(m2_padded)
        m3_unpadded = cipher_utils.unpad_message(m3_padded)
        m4_unpadded = cipher_utils.unpad_message(m4_padded)

        self.assertSequenceEqual(m1, m1_unpadded)
        self.assertSequenceEqual(m2, m2_unpadded)
        self.assertSequenceEqual(m3, m3_unpadded)
        self.assertSequenceEqual(m4, m4_unpadded)
    def test_bytes_encoding(self):
        message = "This is a test message.　テストメッセージです。　漢字も対応。"
        encoded = cipher_utils.text_to_byte_list(message)
        decoded = cipher_utils.byte_list_to_text(encoded)
        self.assertEqual(message, decoded)