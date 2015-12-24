import cryptotools as ct

the_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

def hex_to_base64(hex_str):
    b = ct.hex_to_bytes(hex_str)
    return ct.bytes_to_base64(b)

print(hex_to_base64(the_string))

