from typing import Sequence
import numpy as np

def pad_message(message: Sequence[int]):
    """
    Add PKCS#7 padding to a message
    :param message: A sequence of bytes to be padded
    :return: A PKCS#7 padded message
    """
    padding_length = 16 - (len(message) % 16)
    if padding_length == 0:
        padding_length = 16
    result = list(message)
    result.extend([padding_length] * padding_length)
    return result

def unpad_message(message: Sequence[int]):
    """
    Remove PKCS#7 padding from a message
    :param message: A PKCS#7 padded message
    :return: Message without padding
    """

    padding_length = message[-1]
    padding = message[-padding_length:]
    if not all(x==padding_length for x in padding):
        raise ValueError('Invalid padding')
    return message[:-padding_length]

def text_to_byte_list(text: str) -> Sequence[int]:
    res = bytes(text, 'utf-8')
    res = list(res)
    return res

def byte_list_to_text(byte_list: Sequence[int]) -> str:
    bytes_of_values = bytes(byte_list)
    return bytes_of_values.decode("utf-8")

def int_list_to_block(int_list: Sequence[int]):
    if len(int_list)!=16:
        raise ValueError('Invalid length')
    return np.array((
        int_list[0:16:4],
        int_list[1:16:4],
        int_list[2:16:4],
        int_list[3:16:4],
    ))

def block_to_int_list(block) -> Sequence[int]:
    if block.shape!= (4,4):
        raise ValueError('Invalid block size')
    return [block[0][0], block[1][0], block[2][0], block[3][0],
            block[0][1], block[1][1], block[2][1], block[3][1],
            block[0][2], block[1][2], block[2][2], block[3][2],
            block[0][3], block[1][3], block[2][3], block[3][3]]