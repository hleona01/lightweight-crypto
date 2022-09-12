#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include "aes.h"
#include "gcm.h"
#define NUM_LOOPS 50

using namespace CryptoPP;

void genGCMBlockKey(size_t keylength, size_t blocksize, GCM<AES>::Encryption &enc);
float test_aes(int message_length);

int main()
{
    FILE *fp;
    fp = fopen("results_aes.txt", "w");
    int message_lengths[] = {32, 320, 3200, 32000, 320000};
    int num_message_lengths = 5;
    for (int i = 0; i < num_message_lengths; i++) {
        float result = test_aes(message_lengths[i]);
        fprintf(fp,"message length: %d\n", message_lengths[i]);
        fprintf(fp, "time: %f\n", result);
    }
}

float test_aes(int message_length)
{
    GCM<AES>::Encryption eAES;

    bool randomIvKey = false;
    unsigned keysize = 16;

    genGCMBlockKey(keysize, AES::DEFAULT_KEYLENGTH, eAES);

    struct timeval before_encrypt, after_decrypt;
    gettimeofday(&before_encrypt, NULL);
    for (int i = 0; i < NUM_LOOPS; i++) {
        size_t size = message_length;
        byte plainText[size];
        for (int i = 0; i < size; i++) {
            plainText[i] = i % 256;
        }
        byte cipherText[size];
        eAES.ProcessData(cipherText, plainText, size);
    }
    gettimeofday(&after_decrypt, NULL);

    float sec = after_decrypt.tv_sec - before_encrypt.tv_sec;
    float usec = after_decrypt.tv_sec - before_encrypt.tv_sec;

    // convert to us
    return ((sec * 1000000) + usec)/NUM_LOOPS;
}

void genGCMBlockKey(size_t keylength, size_t blocksize, GCM<AES>::Encryption &enc)
{
      byte key[keylength];
      byte iv[blocksize];

      memset(key, 0x80, 1);
      memset(&key[1], 0x00, keylength - 1);
      memset(iv, 0x00, blocksize);

      enc.SetKeyWithIV(key, keylength, iv, blocksize);
}
