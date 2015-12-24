import cryptotools as ct

def xor_hexes(hex_one, hex_two):
    bytes_one = ct.hex_to_bytes(hex_one)
    bytes_two = ct.hex_to_bytes(hex_two)
    xored_bytes = ct.bytes_xor(bytes_one, bytes_two)
    return ct.bytes_to_hex(xored_bytes)

value_one = '1c0111001f010100061a024b53535009181c'
value_two = '686974207468652062756c6c277320657965'

print(xor_hexes(value_one, value_two))
