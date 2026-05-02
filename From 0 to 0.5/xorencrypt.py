import sys

KEY = b"figueronSecretKey"

def xor_data(data, key):
    output = bytearray()
    key_len = len(key)

    for i in range(len(data)):
        output.append(data[i] ^ key[i % key_len])

    return output

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <input.bin>")
    sys.exit(1)

input_file = sys.argv[1]

with open(input_file, "rb") as f:
    data = f.read()

encrypted = xor_data(data, KEY)

with open("favicon.ico", "wb") as f:
    f.write(encrypted)

print("Done! Output written to favicon.ico")
print('{ 0x' + ', 0x'.join(format(b, '02x') for b in encrypted) + ' };')