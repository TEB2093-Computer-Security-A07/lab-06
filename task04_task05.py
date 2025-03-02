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
    def sign(message: str, private_key: RSAPrivateKey) -> int:
        # in reality, we use hash, but for this lab, it says don't use hash
        # hash = int.from_bytes(sha512(message.encode("utf-8")).digest(), byteorder="big")
        message_hex = message.encode("utf-8").hex()
        message_int = int(message_hex, 16)
        return pow(message_int, private_key.d, private_key.n)

    @staticmethod
    def verify(message: str, signature: int, public_key: RSAPublicKey) -> bool:
        # in reality, we use hash, but for this lab, it says don't use hash
        # hash = int.from_bytes(sha512(message.encode("utf-8")).digest(), byteorder="big")
        message_int = pow(signature, public_key.e, public_key.n)
        message_hex = hex(message_int)[2:]

        try:
            message_str = bytes.fromhex(message_hex).decode("utf-8")
        except UnicodeDecodeError:
            return False

        return message_str == message


if __name__ == "__main__":
    print("+-------------------------------------------------------------------------+")
    print("|                               Task 04                                   |")
    print("+-------------------------------------------------------------------------+")

    # public key from instructions
    public_key = RSAPublicKey(
        "010001", "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5"
    )

    # private key from instructions
    private_key = RSAPrivateKey(
        "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D",
        "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5",
    )

    message_str = "I owe you $2000."
    message_signature = RSA.sign(message_str, private_key)
    message_verification = RSA.verify(message_str, message_signature, public_key)

    print("[*] Logging...")
    print(f"Original message: {message_str}")
    print(f"\tSignature:\t{message_signature}")
    print(f"\tVerification:\t{message_verification}\n")

    message_str = "I owe you $3000."
    message_signature = RSA.sign(message_str, private_key)
    message_verification = RSA.verify(message_str, message_signature, public_key)

    print("[*] Logging...")
    print(f"Modified message: {message_str}")
    print(f"\tSignature:\t{message_signature}")
    print(f"\tVerification:\t{message_verification}\n")

    print("+-------------------------------------------------------------------------+")
    print("|                               Task 05                                   |")
    print("+-------------------------------------------------------------------------+")

    public_key = RSAPublicKey(
        "010001", "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115"
    )

    message_str = "Launch a missile."
    message_signature_hex = (
        "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F"
    )
    message_signature = int(message_signature_hex, 16)
    message_verification = RSA.verify(message_str, message_signature, public_key)

    print("[*] Logging...")
    print(f"Original message: {message_str}")
    print(f"\tSignature:\t{message_signature}")
    print(f"\tVerification:\t{message_verification}\n")

    message_str = "Launch a missile."
    message_signature_hex = (
        "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F"
    )
    message_signature = int(message_signature_hex, 16)
    message_verification = RSA.verify(message_str, message_signature, public_key)

    print("[*] Logging...")
    print(f"Original message: {message_str}")
    print(f"\tCorrupted Signature:\t{message_signature}")
    print(f"\tVerification:\t\t{message_verification}\n")
