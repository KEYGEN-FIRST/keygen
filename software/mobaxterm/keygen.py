class KeyGen(object):
    def __init__(self, encrypt_key: int = 0x787):
        self.encode_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        self.decode_table = {t: i for i, t in enumerate(self.encode_table)}
        self.encrypt_key = encrypt_key

    def encode(self, bs: bytes) -> str:
        result = ""
        blocks_count, left_bytes = divmod(len(bs), 3)

        for i in range(blocks_count):
            coding_int = int.from_bytes(bs[3 * i:3 * i + 3], "little")
            block = self.encode_table[coding_int & 0x3f]
            block += self.encode_table[(coding_int >> 6) & 0x3f]
            block += self.encode_table[(coding_int >> 12) & 0x3f]
            block += self.encode_table[(coding_int >> 18) & 0x3f]
            result += block

        if left_bytes == 0:
            return result
        elif left_bytes == 1:
            coding_int = int.from_bytes(bs[3 * blocks_count:], "little")
            block = self.encode_table[coding_int & 0x3f]
            block += self.encode_table[(coding_int >> 6) & 0x3f]
            result += block
            return result
        else:
            coding_int = int.from_bytes(bs[3 * blocks_count:], "little")
            block = self.encode_table[coding_int & 0x3f]
            block += self.encode_table[(coding_int >> 6) & 0x3f]
            block += self.encode_table[(coding_int >> 12) & 0x3f]
            result += block
            return result

    def decode(self, s: str) -> bytes:
        result = b''
        blocks_count, left_bytes = divmod(len(s), 4)

        for i in range(blocks_count):
            block = self.decode_table[s[4 * i]]
            block += self.decode_table[s[4 * i + 1]] << 6
            block += self.decode_table[s[4 * i + 2]] << 12
            block += self.decode_table[s[4 * i + 3]] << 18
            result += block.to_bytes(3, 'little')

        if left_bytes == 0:
            return result
        elif left_bytes == 2:
            block = self.decode_table[s[4 * blocks_count]]
            block += self.decode_table[s[4 * blocks_count + 1]] << 6
            result += block.to_bytes(1, 'little')
            return result
        elif left_bytes == 3:
            block = self.decode_table[s[4 * blocks_count]]
            block += self.decode_table[s[4 * blocks_count + 1]] << 6
            block += self.decode_table[s[4 * blocks_count + 2]] << 12
            result += block.to_bytes(2, 'little')
            return result
        else:
            raise ValueError('Invalid encoding.')

    def encrypt(self, bs: bytes) -> bytes:
        result = bytearray()
        key = self.encrypt_key
        for i in range(len(bs)):
            result.append(bs[i] ^ ((key >> 8) & 0xff))
            key = result[-1] & key | 0x482D
        return bytes(result)

    def decrypt(self, bs: bytes) -> bytes:
        result = bytearray()
        key = self.encrypt_key
        for i in range(len(bs)):
            result.append(bs[i] ^ ((key >> 8) & 0xff))
            key = bs[i] & key | 0x482D
        return bytes(result)

    def gen_license(self, username: str, major_version: int, minor_version: int) -> str:
        license_type = 1  # Professional: 1, Educational = 3, Personal = 4
        count = 1
        license_string = f"{license_type}#{username}|{major_version}{minor_version}#{count}#{major_version}3" \
                         f"{minor_version}6{minor_version}#0#0#0#"
        encoded_license_string = self.encode(self.decrypt(license_string.encode()))
        print(f"username: {username}\nversion: {major_version}.{minor_version}\n"
              f"encoded_license_string: {encoded_license_string}")
        return encoded_license_string


def main():
    key_gen = KeyGen()
    license_string = key_gen.gen_license(username="test", major_version=21, minor_version=0)
    import zipfile
    with zipfile.ZipFile("Custom.mxtpro", "w") as f:
        f.writestr("Pro.key", data=license_string)


if __name__ == '__main__':
    main()
