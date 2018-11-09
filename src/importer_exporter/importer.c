/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
/**
Generate DER public key from the above
 openssl ecparam -name prime256v1 -genkey -noout -outform DER  -out key.pem
 */
#include <stdio.h>
#include <memory.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <common.h>

#include "common.h"

CK_RV der_encode_ECpoint(CK_BYTE_PTR ppubkey, CK_ULONG pubkey_len,
                         unsigned char **ecpoint_der, CK_ULONG *der_len)
{
    CK_RV rv = CKR_OK;
    unsigned char *der_ptr = NULL;
    unsigned char *der_buff = NULL;
    int der_buff_size = 0;
    ASN1_OCTET_STRING *ec_point_oct_string = NULL;

    if (ppubkey == NULL || der_len == NULL)
        return CKR_GENERAL_ERROR;

    ec_point_oct_string = ASN1_OCTET_STRING_new();
    if (ec_point_oct_string == NULL) {
        rv = CKR_HOST_MEMORY;
        goto end;
    }

    if (0 == ASN1_OCTET_STRING_set(ec_point_oct_string, ppubkey, pubkey_len)) {
        rv = CKR_GENERAL_ERROR;
        goto end;
    }
    der_buff_size = i2d_ASN1_OCTET_STRING(ec_point_oct_string, NULL);
    if (der_buff_size < 0) {
        rv = CKR_GENERAL_ERROR;
        goto end;
    }
    der_buff = (unsigned char *)OPENSSL_malloc(der_buff_size);
    if (der_buff == NULL) {
        rv = CKR_HOST_MEMORY;
        goto end;
    }
    der_ptr = der_buff;
    der_buff_size = i2d_ASN1_OCTET_STRING(ec_point_oct_string, &der_buff);
    if (der_buff_size < 0) {
        OPENSSL_free(der_ptr);
        rv = CKR_GENERAL_ERROR;
        goto end;
    }
    *ecpoint_der = der_ptr;
    *der_len = der_buff_size;
    end:
    /* der_ptr to be freed by calling function */
    if (ec_point_oct_string != NULL)
        ASN1_OCTET_STRING_free(ec_point_oct_string);
    return rv;
}

int decode_ec_public_key(const unsigned char *der_str, int der_size, char **params, char **point) {
    EC_KEY *pubkey = d2i_EC_PUBKEY(NULL, &der_str, der_size);
    if (!pubkey) {
        FILE *fp = fopen("errs", "w");
        ERR_print_errors_fp(fp);
        fclose(fp);
        printf("Failed\n");
        return 1;
    }

    const EC_GROUP *group = EC_KEY_get0_group(pubkey);

    const EC_POINT *ec_point = EC_KEY_get0_public_key(pubkey);

    size_t length = 0;
    length = EC_POINT_point2oct(group, ec_point, EC_GROUP_get_point_conversion_form(group), NULL, 0, NULL);

    unsigned char *oct_point = malloc(length);
    EC_POINT_point2oct(group, ec_point, EC_GROUP_get_point_conversion_form(group),
                       oct_point, length, NULL);

    ASN1_OCTET_STRING *asn1_point = ASN1_OCTET_STRING_new();

    ASN1_OCTET_STRING_set(asn1_point, oct_point, length);

    size_t pointLength = i2d_ASN1_OCTET_STRING(asn1_point, NULL);
    *point = malloc(pointLength);
    unsigned char *tmp = *point;
    pointLength = i2d_ASN1_OCTET_STRING(asn1_point, &tmp);

    return pointLength;
}

CK_RV import_ec_pubkey(CK_SESSION_HANDLE session, CK_BYTE_PTR ec_point, CK_ULONG ec_point_len, CK_OBJECT_HANDLE_PTR key_handle)
{
    CK_RV           rv;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE     keytype = CKK_EC;
    CK_CHAR         label[] = "Imported EC public";

    // Curve parameters for secp256v1
    CK_CHAR ec_params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

    CK_ATTRIBUTE template [] = {
            {CKA_CLASS,             &class,         sizeof(class)},
            {CKA_TOKEN,             &false,         sizeof(CK_BBOOL)},
            {CKA_KEY_TYPE,          &keytype,       sizeof(CK_KEY_TYPE)},
            {CKA_EC_PARAMS,         ec_params,     sizeof(ec_params)},
            {CKA_VERIFY,             &true,         sizeof(CK_BBOOL)},
            {CKA_LABEL,             label,         sizeof(label)},


            // 2.03-22 and 2.04-17 both import and sign correctly when the DER tag is stripped
            {CKA_EC_POINT,          &ec_point[2],      ec_point_len - 2},


            // 2.04-17 fails to import with the DER tag in place (CKR_KEY_SIZE_RANGE).
            // {CKA_EC_POINT,          ec_point,      ec_point_len},

            // 2.03-22 fails to verify a signature with the DER tag in place (CKR_GENERAL_ERROR).
            // {CKA_EC_POINT,          ec_point,      ec_point_len},

    };

    rv = funcs->C_CreateObject(session, template, 7, key_handle);

    return rv;
}

CK_RV import_ec_privkey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR key_handle)
{
    CK_RV           rv;
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE     keytype = CKK_EC;
    CK_CHAR         label[] = "Imported EC private";

    // Hard coded private key values associated with the public key
    char priv_key[] = "\x5F\xFF\xF2\xBE\x06\xAA\x65\x08\x92\x50\x39\x88\x05\xC0\x80\xD6\x6B\xDF\x9E\x52\xEC\x14\x07\xC0\x27\x1A\x52\x96\xBB\x63\x70\xE5";

    CK_CHAR ec_params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    CK_ATTRIBUTE template [] = {
            {CKA_CLASS,             &class,         sizeof(class)},
            {CKA_SIGN,             &true,         sizeof(CK_BBOOL)},
            {CKA_TOKEN,             &false,         sizeof(CK_BBOOL)},
            {CKA_KEY_TYPE,          &keytype,       sizeof(CK_KEY_TYPE)},
            {CKA_VALUE,             priv_key,      sizeof(priv_key) - 1},
            {CKA_EC_PARAMS,         ec_params,     sizeof(ec_params)},
            {CKA_LABEL,             label,         sizeof(label)}
    };

    rv = funcs->C_CreateObject(session, template, 7, key_handle);

    return rv;
}


int main(int argc, char **argv)
{
    CK_RV rv;
    CK_SESSION_HANDLE session;

    struct pkcs_arguments args = {};
    if (get_pkcs_args(argc, argv, &args) < 0) {
        return 1;
    }

    rv = pkcs11_initialize(args.library);
    rv = pkcs11_open_session(args.pin, &session);
    if (rv!=CKR_OK)
        return 0;

    EC_KEY *ec_key;
    if (null==d2i_ECPrivateKey_fp(der_file, &ec_key)) {
        // handle
    }

    //CKA_EC_PARAMS
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    if (null==group) {
        //handle
    }

    int ec_param_len = i2d_ECPKParameters(group, NULL);
    unsigned char *der_group = malloc(ec_param_len);
    CK_BYTE *ec_param = der_group;
    ec_param_len = i2d_ECPKParameters(group, &ec_param);

    //CKA_VALUE
    const BIGNUM *priv_key_n = EC_KEY_get0_private_key(ec_key);
    size_t priv_key_len = BN_num_bytes(priv_key_n);
    unsigned char *bin_priv_key = malloc(priv_key_len);
    BN_bn2bin(priv_key_n, bin_priv_key);
    char hex[512];
    bytes_to_hex(bin_priv_key, priv_key_len * 2, hex);
    for (int i=0;i<priv_key_len;i++)
        printf("%02X ", bin_priv_key[i] & 0x0ff);
    printf("\n");
    //BOOST_TEST(value.size() == BN_bn2bin(priv_key_n, value.data()));

    //CKA_EC_POINT
    const EC_POINT *pub_key = (EC_POINT*) EC_KEY_get0_public_key(ec_key);
    size_t pub_key_len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL );
    CK_BYTE_PTR oct_ec_point = malloc(pub_key_len);
    EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, oct_ec_point, pub_key_len, NULL);
    for (int i=0;i<pub_key_len;i++)
        printf("%02X ", pub_key[i] & 0x0ff);
    printf("\n");

    return 0;
    char * point;
    char * param;
    CK_BYTE der[512];
    CK_LONG len = 0;

    // Read in the larger DER file to prevent copypaste errors
    int fp = open("ec-pub-key.der", O_RDONLY);
    len = read(fp, der, 1024);
    close(fp);

    // After decode, the point value will be DER encoded.
    //CK_ULONG point_len = decode_ec_public_key(der, len, &param, &point);
    //for (int i=0; i<point_len; i++) { printf("%02X ", point[i] & 0x0ff); }
    //printf("\n");

    unsigned char *ecpoint_der;
    CK_ULONG ecpoint_der_len;
    der_encode_ECpoint(der, len, &ecpoint_der, &ecpoint_der_len);
    for (int i=0; i<ecpoint_der_len; i++) { printf("%02X ", ecpoint_der[i] & 0x0ff); }
    printf("\n");

    CK_OBJECT_HANDLE signing_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE signing_private_key = CK_INVALID_HANDLE;
    //rv = import_ec_pubkey(session, point, point_len, &signing_public_key);
    rv = import_ec_pubkey(session, ecpoint_der, ecpoint_der_len, &signing_public_key);
    if (rv != CKR_OK)
    {
        printf("EC pub key import failed: %lu\n", rv);
    }

    rv = import_ec_privkey(session, &signing_private_key);
    if (rv != CKR_OK)
    {
        printf("EC priv key import failed: %lu\n", rv);
    }
    printf("%lu %lu\n", signing_public_key, signing_private_key);

    CK_BYTE_PTR data = "sign this";
    CK_ULONG data_length = strlen(data);

    CK_BYTE signature[MAX_SIGNATURE_LENGTH];
    CK_ULONG signature_length = MAX_SIGNATURE_LENGTH;

    // Set the PKCS11 signature mechanism type.
    CK_MECHANISM_TYPE mechanism = CKM_ECDSA;

    rv = generateSignature(session, signing_private_key, mechanism,
                           data, data_length, signature, &signature_length);
    if (rv == CKR_OK) {
        printf("Data: %s\n", data);
        printf("Signature: %s\n", signature);
    } else {
        printf("Signature generation failed: %lu\n", rv);
    }

    rv = verifySignature(session, signing_public_key, mechanism, data, data_length, signature, signature_length);
    if (rv != CKR_OK)
    {
        printf("Signature verification failed: %lu\n", rv);
    }

    return 0;
}

CK_RV importEcPublicKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR key_handle)
{
    CK_RV           rv;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE     keytype = CKK_EC;
    CK_CHAR         label[] = "Imported EC public";

    /**
 * Curve OIDs generated using OpenSSL on the command line.
 * Visit https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-key-types.html for a list
 * of supported curves.
 * openssl ecparam -name prime256v1 -outform DER | hexdump -C
 * openssl ecparam -name secp256r1 -outform DER | hexdump -C
 */
    CK_BYTE prime256v1[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    CK_BYTE secp256r1[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

    /*openssl ecparam -name prime256v1 -genkey -noout -out eckey.pem
openssl ec -pubout -in eckey.pem -out ecpub.pem
openssl asn1parse -in ecpub.pem -dump
*/

    CK_CHAR ec_point[] = { 0x04, 0x05, 0x76, 0x3B, 0x9B, 0x5D, 0xFF, 0xAA, 0xDF, 0x29, 0x30, 0x8C, 0xAB, 0xDE, 0xB2, 0xF9, 0x46, 0x0B, 0x22, 0x29, 0x78, 0xF2, 0xB0, 0xD8, 0xDC, 0x6E, 0x2D, 0xC8, 0x0A, 0x92, 0xD4, 0x45, 0x25, 0xE9, 0x3D, 0x5D, 0x6C, 0x47, 0x2B, 0xC0, 0x71, 0x4C, 0x89, 0xC4, 0x3D, 0x45, 0x3E, 0x17,
                           0x1D, 0x8F, 0xBB, 0xCE, 0x71, 0xAA, 0xE4, 0x0E, 0x92, 0x7A, 0x79, 0xF7, 0xBB, 0xE8, 0x8E, 0x82, 0x61, 0x09, 0x5E, 0x8C, 0x3B, 0xF7, 0xAD, 0x7E, 0x77, 0x42, 0xF3, 0xBA, 0x09, 0x78, 0x0A, 0x4D, 0x79, 0x58, 0x0B, 0x20, 0x10, 0xEC, 0x43, 0x59, 0xB1, 0xE2, 0xBD, 0xD6, 0xCE, 0xBF, 0xCB, 0x6E, 0x1B };
    //CK_BYTE ec_params[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
/*
    CK_CHAR ec_point[] = { 0x04, 0xa8, 0x0d, 0xff, 0xc0, 0x42, 0x9a, 0xd0, 0x72, 0xfd, 0x59, 0x6a, 0x91, 0xa9, 0x0f,
  0xa4, 0x2d, 0x98, 0x6a, 0xa0, 0x79, 0x13, 0x3a, 0x3f , 0x2c,  0x19 , 0x4a , 0x7e ,0x56 , 0x8c  ,0xb2,
  0x9d, 0x3a, 0xd9, 0x2d, 0xdc, 0x12, 0x69, 0xac,  0xb2,  0xeb,  0x17,  0xd8 , 0xbf  ,0xfb , 0xdb  ,0x4b,
  0x28, 0x6e, 0x6e, 0xe4, 0x4b, 0x49, 0xd6, 0x60,  0xb6,  0x5c,  0xdb,  0xdd , 0x4f , 0x18  ,0x04  ,0xaa,
  0xa4, 0x98};
*/
    printf("Size %lu %lu\n", sizeof(ec_point), sizeof(ec_params));
    CK_ATTRIBUTE template [] = {
            {CKA_CLASS,             &class,         sizeof(class)},
            {CKA_TOKEN,             &false,         sizeof(CK_BBOOL)},
            {CKA_KEY_TYPE,          &keytype,       sizeof(CK_KEY_TYPE)},
            {CKA_EC_POINT,          ec_point,      sizeof(ec_point)},
            {CKA_EC_PARAMS,         ec_params,     sizeof(ec_params)},
            {CKA_LABEL,             label,         sizeof(label)}
    };

    rv = funcs->C_CreateObject(session, template, 6, key_handle);

    return rv;
}

//    uint8_t *raw_key = hexStringToBytes(key);
//    printf("len %d\n", strlen(key));
//RSA *pub_key = create_public_rsa(raw_key, 256);
EVP_PKEY_CTX *ctx = NULL;
unsigned char *md, *sig;
size_t mdlen = 32, siglen;
//EVP_PKEY *rsa_key = create_public_rsa_from_der(raw_key, strlen(key) / 2);
/*if (rsa_key==NULL) {
    printf("Error\n");
    return 1;
}*/

//    ctx = EVP_PKEY_CTX_new(rsa_key, NULL);
/*if (EVP_PKEY_sign_init(ctx) <= 0) {
    printf("Error sign init\n");
    return 1;
}
if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
    printf("Error set padding\n");
    return 1;
}
if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
    printf("Error set sig md\n");
    return 1;
}*/

md = calloc(1, 32);
strcpy(md, "This is a test");
/* Determine buffer length */
if (EVP_PKEY_sign(ctx, NULL, &siglen, md, mdlen) <= 0) {
printf("sign for buf len failed\n");
return 1;
}

sig = OPENSSL_malloc(siglen);

if (!sig) {
printf("malloc failed\n");
return 1;
}


//  printf("sig len %d\n", siglen);
int r = EVP_PKEY_sign(ctx, sig, &siglen, md, mdlen);
if (r <= 0) {
printf("sign failed %d\n", r);
return 1;
}

for (int i = 0; i < siglen; i++) {
printf("%02X", sig[i]);
}

printf("\n");

if (EVP_PKEY_verify_init(ctx) <= 0) {
printf("verify init failed\n");
return 1;
}

if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
printf("Error set padding\n");
return 1;
}
if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
printf("Error set sig md\n");
return 1;
}

sig[4] = 9;
int ret = EVP_PKEY_verify(ctx, sig, siglen, md, mdlen);
printf("Verification code %d\n", ret);

}


static void print_bn(const char *what, const BIGNUM *bn) {
    char *str = BN_bn2hex(bn);
    printf("%s (hex): %s\n", what, str);
    OPENSSL_free(str);
}

EVP_PKEY *create_public_rsa_from_der(const void *der_bytes, size_t der_len) {
    BIO *mem = BIO_new_mem_buf(der_bytes, der_len);
    return d2i_PrivateKey_bio(mem, NULL);
}

RSA *create_public_rsa(unsigned char *key_bytes, size_t key_len) {
    RSA *rsa_key = NULL;

    BIGNUM *mod = BN_bin2bn(key_bytes, key_len, NULL);
    print_bn("Modulus", mod);

    BIGNUM *exp = NULL;
    if (BN_dec2bn(&exp, "65537") == 0) {
        return rsa_key;
    }
    print_bn("Exponent", exp);

    rsa_key = RSA_new();
    if (!rsa_key) {
        return rsa_key;
    }
    rsa_key->e = exp;
    rsa_key->n = mod;

    return rsa_key;
}


