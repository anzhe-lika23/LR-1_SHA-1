import time
import csv


def sha1(data):
    bytes_string = ""

    const_a = 0x67452301
    const_b = 0xEFCDAB89
    const_c = 0x98BADCFE
    const_d = 0x10325476
    const_e = 0xC3D2E1F0

    for letter in range(len(data)):
        bytes_string += '{0:08b}'.format(ord(data[letter]))
    bits = bytes_string + "1"
    origin_bits = bits
    # added "0" until length equals 448 mod 512
    while len(origin_bits) % 512 != 448:
        origin_bits += "0"
    # adding a 64-bit binary number representing the length of the input data
    origin_bits += '{0:064b}'.format(len(bits) - 1)

    def line_break(line, substring_length):
        return [line[element:element + substring_length] for element in range(0, len(line), substring_length)]

    def cyclic_bit_shift(number, shift):
        return ((number << shift) | (number >> (32 - shift))) & 0xffffffff

    for c in line_break(origin_bits, 512):
        words = line_break(c, 32)
        list_worlds = [0] * 80
        for letter in range(0, 16):
            list_worlds[letter] = int(words[letter], 2)
        for i in range(16, 80):
            list_worlds[i] = cyclic_bit_shift((list_worlds[i - 3] ^ list_worlds[i - 8] ^
                                               list_worlds[i - 14] ^ list_worlds[i - 16]), 1)

        a = const_a
        b = const_b
        c = const_c
        d = const_d
        e = const_e

        # Main loop for calculating the hash value
        for i in range(0, 80):
            function_value = 0
            constant = 0
            if 0 <= i <= 19:
                function_value = (b & c) | ((~b) & d)
                constant = 0x5A827999
            elif 20 <= i <= 39:
                function_value = b ^ c ^ d
                constant = 0x6ED9EBA1
            elif 40 <= i <= 59:
                function_value = (b & c) | (b & d) | (c & d)
                constant = 0x8F1BBCDC
            elif 60 <= i <= 79:
                function_value = b ^ c ^ d
                constant = 0xCA62C1D6

            temp = cyclic_bit_shift(a, 5) + function_value + e + constant + list_worlds[i] & 0xffffffff
            e = d
            d = c
            c = cyclic_bit_shift(b, 30)
            b = a
            a = temp

        const_a = const_a + a & 0xffffffff
        const_b = const_b + b & 0xffffffff
        const_c = const_c + c & 0xffffffff
        const_d = const_d + d & 0xffffffff
        const_e = const_e + e & 0xffffffff

    return '%08x%08x%08x%08x%08x' % (const_a, const_b, const_c, const_d, const_e)


# Рахуємо кількість різних бітів між двома хешами
def calculate_changed_bits(origin_hash, modif_hash):
    xor_result = int(origin_hash, 16) ^ int(modif_hash, 16)
    return bin(xor_result).count('1')


def collect_and_save_bit_changes(hash_orig, hash_modify, out_file):
    changes = []
    for i in range(len(hash_orig)):
        if hash_orig[i] != hash_modify[i]:
            changes.append(i)

    with open(out_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Round', 'Changed Bits'])
        for i, bit_position in enumerate(changes):
            csvwriter.writerow([i + 1, bit_position])

    print(f"Bit changes saved to {out_file}")


# Вимірюємо швидкість виконання
def calculate_time(mes):
    start_time = time.time()
    sha1(mes)
    end_time = time.time()
    execution_time = end_time - start_time
    return f"Execution Time: {execution_time} seconds"


message = "Security is well"
original_hash = sha1(message)

print(f"{'=' * 30}\n{' ' * 5}Hash-functions SHA-1\n{'=' * 30}")
print(f"Message -> {message}\nSHA-1 (Original) -> {original_hash}")

# Змінюємо один біт в тексті повідомлення
modified_message = message[:4] + "a" + message[5:]
modified_hash = sha1(modified_message)
print(f"Modified Message -> {modified_message}\nSHA-1 (Modified) -> {modified_hash}")

# Рахуємо кількість змінених бітів
changed_bits_count = calculate_changed_bits(original_hash, modified_hash)
print(f"Changed Bits Count: {changed_bits_count}")

# Збираємо і зберігаємо дані про зміну бітів
output_file = 'bit_changes.csv'
collect_and_save_bit_changes(original_hash, modified_hash, output_file)

print(calculate_time(message))
