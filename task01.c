#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *message, const BIGNUM *number) {
    char *number_str = BN_bn2hex(number);
    printf("%s %s\n", message, number_str);
    OPENSSL_free(number_str);
}

int main(void) {
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *d = BN_new();

    BN_CTX *ctx = BN_CTX_new();

    // values according to instructions
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    // n = p * q
    BN_mul(n, p, q, ctx);

    // φ(n) = (p - 1)(q - 1)
    BIGNUM *one = BN_new();
    BN_one(one);
    BN_sub(p, p, one);
    BN_sub(q, q, one);
    BN_mul(phi, p, q, ctx);

    // d = e^-1 mod φ(n)
    BN_mod_inverse(d, e, phi, ctx);

    printf("Public Key (e, n):\n");
    printBN("\te = ", e);
    printBN("\tn = ", n);

    printf("Private Key (e, n):\n");
    printBN("\td = ", d);
    printBN("\tn = ", n);

    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(n);
    BN_free(phi);
    BN_free(d);

    BN_CTX_free(ctx);

    return 0;
}