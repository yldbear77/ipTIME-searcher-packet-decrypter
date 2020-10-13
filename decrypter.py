import sys
from scapy.all import *
NETIF_NAME = 'wlan0'
xor_padd = '\x2B\xA4\xB8\x4B\xFC\x91\x26\x9B\x3D\x3A\x8F\x3A\xAF\x21\x75\x5A' \
               '\x27\xA2\xF6\x12\x35\x52\x34\x5C\xA1\xF8\x3F\x06\xF4\x33\x90\x35' \
               '\xFE\xD7\x93\x2E\xED\x14\x09\x35\xD7\x96\x0F\x46\xE7\xEA\x71\x20' \
               '\x18\xBA\x7B\x5A\x03\x68\x30\x1B\x34\xD9\xD6\x13\xF1\x12\x4B\x7D' \
               '\xEB\x19\x39\xD2\xF7\x1A\x8B\xC2\xAD\x86\x0C\x18\x55\x24\x17\xCA' \
               '\x4C\xC3\xC8\x7D\xAE\x4F\x57\x06\xA9\xB8\x75\x6D\x9B\xEE\xDF\xBE' \
               '\x2F\x9A\xE9\xE4\xF0\x76\x2F\x86\x7B\x2C\x88\xAB\x6C\x01\x86\x8B' \
               '\xB5\xEA\x07\x92\xD7\x71\xA7\x2A\x87\x52\xF3\x72\x25\x7A\xE4\xD4' \
               '\xF9\x60\x4F\x8E\xC4\x93\x00\xA5\x5E\xC7\x0B\xDE\x65\x6C\xB1\x45' \
               '\x5F\x66\x6F\xF6\x97\x4A\x61\xD8\xC8\x32\xD3\xC2\x5A\x10\x00\x7B' \
               '\xA4\x49\x36\x03\x69\xC2\xC3\x46\x13\xA9\xA1\xA2\x57\x8A\x3B\x96' \
               '\x9D\x3E\xBC\x90\xE9\xAC\xA7\x72\x5C\x23\x78\xED\x0E\x3F\xCF\xB6' \
               '\x21\x10\xFD\xBD\x03\xFE\x3F\x2E\xDF\xFA\xD9\x9C\xA0\xEE\x87\xCD' \
               '\x8B\xD4\x98\x0B\x1C\xB1\xE6\x7B\x2D\x9A\xBF\xEA\x5F\x81\x65\x3A' \
               '\xE7\xC2\x63\xD2\x15\xF2\x94\x4C\x51\xE8\x9F\x46\xD4\xF3\xB0\x55' \
               '\xBE\xB7\x83\x8E\x1D\x23\x3F\xAF\xB4\xF5\xCF\x12\x76\xEB\x15\x9C'

rqstp1 = Ether(dst='FF:FF:FF:FF:FF:FF', src=get_if_hwaddr(NETIF_NAME), type=0x887e)/ \
            '\x01\x01\x00\x00\x0e\x00\x00\x00\x0e\x00\x00\x00\x01\x00\x00\x00\x16\x66\xee\x2d' \
            '\x5f\xb5\xa8\xac\x95\x43\x89\x79\xb5\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
            '\x00\x00\x00\x00\x00\x00'

respp1 = srp1(rqstp1)

# hexdump(respp1)

decrypt_byte_array = []
key1 = 0x93
xor_padd_array = map(ord, str(xor_padd))
packet_byte_array = map(ord, str(respp1))
packet_byte_array = packet_byte_array[30:]

loop_count = 10
data_size = len(respp1) - 30

while loop_count < data_size:

    # decrypt original character

    packet_byte = packet_byte_array[loop_count]
    xor_padd_byte1 = xor_padd_array[loop_count]
    key_index1 = loop_count + 0x7B
    key_index1 = key_index1 & 0xFF

    result_chr = xor_padd_array[key_index1]
    result_chr = result_chr ^ xor_padd_array[xor_padd_byte1]
    result_chr = result_chr ^ xor_padd_byte1
    result_chr = result_chr ^ packet_byte
    result_chr = result_chr ^ key1
    decrypt_byte_array.append(chr(result_chr))

    # manipulate XOR key padd to strange way

    key2 = result_chr + key1
    key2 = key2 & 0xFF
    key1 = key2
    xor_padd_byte2 = xor_padd_array[0xFF - loop_count]
    key3 = xor_padd_array[xor_padd_byte2]
    key3 = key3 ^ xor_padd_byte2
    key3 = key3 ^ result_chr
    key3_backup = key3
    xor_padd_array[0xFF - loop_count] = key3
    key3 = xor_padd_array[key3]
    key3 = key3 ^ key2
    xor_padd_array[key3_backup] = key3

    loop_count += 1

print('----------------- SCAN RESULT -----------------\n')
scan_result = ''.join(decrypt_byte_array)

print('*********** original decrypted data ***********')
print(scan_result)
print('***********************************************\n\n')

scan_result = scan_result.split('&')
for chunk in scan_result:
    if chunk != '':
        chunk = chunk.split('=')
        print(chunk[0] + ' ' + chunk[1])

print('\n-----------------------------------------------')