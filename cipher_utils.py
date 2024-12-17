from typing import Sequence


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