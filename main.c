#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include "elephant160v1/ref/api.h"
#include "elephant160v1/ref/e_crypto_aead.h"

#include "tinyjambu/Implementations/crypto_aead/tinyjambu128v2/opt/crypto_aead.h"
#include "tinyjambu/Implementations/crypto_aead/tinyjambu128v2/opt/api.h"

#include "tinyjambu/Implementations/crypto_aead/tinyjambu192v2/opt/j192_crypto_aead.h"
#include "tinyjambu/Implementations/crypto_aead/tinyjambu192v2/opt/api.h"

#include "tinyjambu/Implementations/crypto_aead/tinyjambu256v2/opt/j256_crypto_aead.h"
#include "tinyjambu/Implementations/crypto_aead/tinyjambu256v2/opt/api.h"

#include "elephant200v2/ref/api.h"
#include "elephant200v2/ref/e200_crypto_aead.h"
#include "elephant200v2/ref/elephant_200.h"

#define MESSAGE_LENGTH			320000
#define ASSOCIATED_DATA_LENGTH	320000
#define NUM_ITERATIONS_E 10
#define NUM_ITERATIONS_J 100

void init_buffer(unsigned char *buffer, unsigned long long numbytes);
float test_elephant();
float test_jambu128();
float test_jambu192();
float test_jambu256();
float test_elephant200();

int main()
{  
    FILE *fp;
    fp = fopen("results.txt", "w");
    
    float j128 = test_jambu128();
    float j192 = test_jambu192();
    float j256 = test_jambu256();
    float e160 = test_elephant();
    float e200 = test_elephant200();

    
    fprintf(fp,"jambu128: %f\njambu192: %f\njambu256: %f\n", j128, j192, j256);
    fprintf(fp, "elephant160: %f\nelephant200: %f\n", e160, e200);
   
    fclose(fp);
    
	return 0;
}

float test_elephant(){
    unsigned char       key[E_CRYPTO_KEYBYTES];
    unsigned char		nonce[E_CRYPTO_NPUBBYTES];
    unsigned char       msg[MESSAGE_LENGTH];
    unsigned char       msg2[MESSAGE_LENGTH];
    unsigned char		ad[ASSOCIATED_DATA_LENGTH];
    unsigned char		ct[MESSAGE_LENGTH + E_CRYPTO_ABYTES];
    unsigned long long	clen, mlen2;
    int                 count = 1;
    init_buffer(key, sizeof(key));
    init_buffer(nonce, sizeof(nonce));
    init_buffer(msg, sizeof(msg));
    init_buffer(ad, sizeof(ad));
    unsigned long long mlen = MESSAGE_LENGTH;
    unsigned long long adlen = ASSOCIATED_DATA_LENGTH;
    struct timeval before_encrypt, after_decrypt;
    printf("testing elephant160:\n");
    gettimeofday(&before_encrypt, NULL);
    for (int i = 0; i < NUM_ITERATIONS_E; i++) {
        elephant_crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen,
                                    NULL, nonce, key);
        elephant_crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad,
                                    adlen, nonce, key);
    }
    gettimeofday(&after_decrypt, NULL);

    float sec = after_decrypt.tv_sec - before_encrypt.tv_sec;
    float usec = after_decrypt.tv_sec - before_encrypt.tv_sec;
    
    // convert to us
    printf("Elephant160 time: %f\n", ((sec * 1000000) + usec)/NUM_ITERATIONS_E);
    return ((sec * 1000000) + usec)/NUM_ITERATIONS_E;
}

float test_jambu128()
{
    unsigned char       key[CRYPTO_KEYBYTES];
    unsigned char		nonce[CRYPTO_NPUBBYTES];
    unsigned char       msg[MESSAGE_LENGTH];
    unsigned char       msg2[MESSAGE_LENGTH];
    unsigned char		ad[ASSOCIATED_DATA_LENGTH];
    unsigned char		ct[MESSAGE_LENGTH + CRYPTO_ABYTES];
    unsigned long long	clen, mlen2;
    int                 count = 1;
    init_buffer(key, sizeof(key));
    init_buffer(nonce, sizeof(nonce));
    init_buffer(msg, sizeof(msg));
    init_buffer(ad, sizeof(ad));
    unsigned long long mlen = MESSAGE_LENGTH;
    unsigned long long adlen = ASSOCIATED_DATA_LENGTH;
    struct timeval before_encrypt, after_decrypt;
    printf("testing jambu128:\n");
    gettimeofday(&before_encrypt, NULL);
    for (int i = 0; i < NUM_ITERATIONS_J; i++) {
      crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key);
      crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key);
    }
    gettimeofday(&after_decrypt, NULL);

    float sec = after_decrypt.tv_sec - before_encrypt.tv_sec;
    float usec = after_decrypt.tv_sec - before_encrypt.tv_sec;
    
    // convert to us
    printf("TinyJambu128 time: %f\n", ((sec * 1000000) + usec)/NUM_ITERATIONS_J);
    return ((sec * 1000000) + usec)/NUM_ITERATIONS_J;
}

float test_jambu192() 
{
    unsigned char       key[J192_CRYPTO_KEYBYTES];
    unsigned char		nonce[J192_CRYPTO_NPUBBYTES];
    unsigned char       msg[MESSAGE_LENGTH];
    unsigned char       msg2[MESSAGE_LENGTH];
    unsigned char		ad[ASSOCIATED_DATA_LENGTH];
    unsigned char		ct[MESSAGE_LENGTH + J192_CRYPTO_ABYTES];
    unsigned long long	clen, mlen2;
    int                 count = 1;
    init_buffer(key, sizeof(key));
    init_buffer(nonce, sizeof(nonce));
    init_buffer(msg, sizeof(msg));
    init_buffer(ad, sizeof(ad));
    unsigned long long mlen = MESSAGE_LENGTH;
    unsigned long long adlen = ASSOCIATED_DATA_LENGTH;
    struct timeval before_encrypt, after_decrypt;
    printf("testing jambu192:\n");
    gettimeofday(&before_encrypt, NULL);
    for (int i = 0; i < NUM_ITERATIONS_J; i++) {
      j192_crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key);
      j192_crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key);
    }
    gettimeofday(&after_decrypt, NULL);

    float sec = after_decrypt.tv_sec - before_encrypt.tv_sec;
    float usec = after_decrypt.tv_sec - before_encrypt.tv_sec;
    
    // convert to us
    printf("TinyJambu192 time: %f\n", ((sec * 1000000) + usec)/NUM_ITERATIONS_J);
    return ((sec * 1000000) + usec)/NUM_ITERATIONS_J;
}

float test_jambu256()
{
    unsigned char       key[J256_CRYPTO_KEYBYTES];
    unsigned char		nonce[J256_CRYPTO_NPUBBYTES];
    unsigned char       msg[MESSAGE_LENGTH];
    unsigned char       msg2[MESSAGE_LENGTH];
    unsigned char		ad[ASSOCIATED_DATA_LENGTH];
    unsigned char		ct[MESSAGE_LENGTH + J256_CRYPTO_ABYTES];
    unsigned long long	clen, mlen2;
    int                 count = 1;
    init_buffer(key, sizeof(key));
    init_buffer(nonce, sizeof(nonce));
    init_buffer(msg, sizeof(msg));
    init_buffer(ad, sizeof(ad));
    unsigned long long mlen = MESSAGE_LENGTH;
    unsigned long long adlen = ASSOCIATED_DATA_LENGTH;
    struct timeval before_encrypt, after_decrypt;
    printf("testing jambu256:\n");
    gettimeofday(&before_encrypt, NULL);
    for (int i = 0; i < NUM_ITERATIONS_J; i++) {
      j256_crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key);
      j256_crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key);
    }
    gettimeofday(&after_decrypt, NULL);

    float sec = after_decrypt.tv_sec - before_encrypt.tv_sec;
    float usec = after_decrypt.tv_sec - before_encrypt.tv_sec;
    
    // convert to us
    printf("TinyJambu256 time: %f\n", ((sec * 1000000) + usec)/NUM_ITERATIONS_J);
    return ((sec * 1000000) + usec)/NUM_ITERATIONS_J;
}

float test_elephant200()
{
    unsigned char       key[E200_CRYPTO_KEYBYTES];
    unsigned char		nonce[E200_CRYPTO_NPUBBYTES];
    unsigned char       msg[MESSAGE_LENGTH];
    unsigned char       msg2[MESSAGE_LENGTH];
    unsigned char		ad[ASSOCIATED_DATA_LENGTH];
    unsigned char		ct[MESSAGE_LENGTH + E200_CRYPTO_ABYTES];
    unsigned long long	clen, mlen2;
    int                 count = 1;
    init_buffer(key, sizeof(key));
    init_buffer(nonce, sizeof(nonce));
    init_buffer(msg, sizeof(msg));
    init_buffer(ad, sizeof(ad));
    unsigned long long mlen = MESSAGE_LENGTH;
    unsigned long long adlen = ASSOCIATED_DATA_LENGTH;
    struct timeval before_encrypt, after_decrypt;
    printf("testing elephant200:\n");
    gettimeofday(&before_encrypt, NULL);
    for (int i = 0; i < NUM_ITERATIONS_E; i++) {
        elephant200_crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key);
        elephant200_crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key);
    }
    gettimeofday(&after_decrypt, NULL);

    float sec = after_decrypt.tv_sec - before_encrypt.tv_sec;
    float usec = after_decrypt.tv_sec - before_encrypt.tv_sec;
    
    // convert to us
    printf("Elephant200 time: %f\n", ((sec * 1000000) + usec)/NUM_ITERATIONS_E);
    return ((sec * 1000000) + usec)/NUM_ITERATIONS_E;
}

void init_buffer(unsigned char *buffer, unsigned long long numbytes)
{
	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)i;
}