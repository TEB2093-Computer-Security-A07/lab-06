#!/usr/bin/env python3


class RSAPublicKey:
    def __init__(self, e: str, n: str):
        self.e = int(e, 16)
        self.n = int(n, 16)

    def __repr__(self) -> str:
        return f"Public Key:\n\te = {hex(self.e)}\n\tn = {hex(self.n)}"


class RSAPrivateKey:
    def __init__(self, d: str, n: str):
        self.d = int(d, 16)
        self.n = int(n, 16)

    def __repr__(self) -> str:
        return f"PrivateKey:\n\td = {hex(self.d)}\n\tn = {hex(self.n)}"


class RSA:
    @staticmethod
    def encrypt(message: str, public_key: RSAPublicKey) -> int:
        message_hex = message.encode("utf-8").hex()
        message_int = int(message_hex, 16)
        return pow(message_int, public_key.e, public_key.n)

    @staticmethod
    def decrypt(encrypted_message: int, private_key: RSAPrivateKey) -> str:
        message_decrypted = pow(encrypted_message, private_key.d, private_key.n)
        message_decrypted_hex = hex(message_decrypted)[2:]
        return bytes.fromhex(message_decrypted_hex).decode("utf-8", errors="ignore")


if __name__ == "__main__":
    # public key from instructions
    public_key = RSAPublicKey(
        "010001", "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5"
    )

    # private key from instructions
    private_key = RSAPrivateKey(
        "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D",
        "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5",
    )

    print("+-------------------------------------------------------------------------+")
    print("|                               Task 02                                   |")
    print("+-------------------------------------------------------------------------+")

    message_str = "A top secret!"
    message_encrypted = RSA.encrypt(message_str, public_key)
    message_decrypted = RSA.decrypt(message_encrypted, private_key)

    print("[*] Logging...")
    print(f"Original message: {message_str}")
    print(f"\tEncrypted message (in BigInt): {message_encrypted}")
    print(f"\tDecrypted message (in String): {message_decrypted}")
    print(
        "[+] Decryption successful!\n"
        if message_decrypted == message_str
        else "[-] Decryption unsuccessful.\n"
    )

    print("+-------------------------------------------------------------------------+")
    print("|                               Task 03                                   |")
    print("+-------------------------------------------------------------------------+")

    message_hex = "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F"
    message_int = int(message_hex, 16)

    print("[*] Logging...")
    print(f"Encrypted message (in hex): {message_hex}")
    print(f"Decrypted message (in str): {RSA.decrypt(message_int, private_key)}")
