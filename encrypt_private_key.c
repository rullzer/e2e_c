#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

// Taken from https://gist.github.com/barrysteyn/7308212
size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;

	return (len*3)/4 - padding;
}

// Taken from https://gist.github.com/barrysteyn/7308212
int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
	BIO *bio, *b64;

	int decodeLen = calcDecodeLength(b64message);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	*length = BIO_read(bio, *buffer, strlen(b64message));
	assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
	BIO_free_all(bio);

	return (0); //success
}

// Taken from https://gist.github.com/barrysteyn/7308212
int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) {
	BIO* bio;
    BIO* b64;
	BUF_MEM* bufferPtr = BUF_MEM_new();

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text=BUF_strdup(bufferPtr->data);
    BUF_MEM_free(bufferPtr);

	return (0); //success
}

int main(int argc, char **argv) {

    char salt[] = "$4$YmBjm3hk$Qb74D5IUYwghUmzsMqeNFx5z0/8$";
    int iterationCount = 1024;
    int keyStrength = 256;
    char ivDelimiter[] = "fA=="; // "|" base64 encoded

    char mnemonic[] = "resultolympiconlinedogspawnfurycomicskirtimpactmaximumfitnesscurve";

    size_t key_length = keyStrength / 8;
    unsigned char *key = (unsigned char *)calloc(key_length + 1, sizeof(unsigned char));

    // Get the key
    if (1 != PKCS5_PBKDF2_HMAC_SHA1(mnemonic, strlen(mnemonic), salt, strlen(salt), iterationCount, key_length, key)) {
        return -1;
    } 


    char iv_b64[] = "jgvTECibYuxsRNxc";
    unsigned char *iv;
    size_t iv_length;
    Base64Decode(iv_b64, &iv, &iv_length);

    // Init
    EVP_CIPHER_CTX *ctx;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    /* Initialise the decryption operation. */
	if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        return -2;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

  	/* Set IV length. */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_length, NULL)) {
        return -3;
    }

  	/* Initialise key and IV */
	if(!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        return -4;
    }

    // READ FILE
    FILE *f = fopen("pkd", "rb");
    fseek(f , 0L , SEEK_END);
    long psize = ftell(f);
    rewind(f);

    unsigned char *ptext = (unsigned char*) calloc(sizeof(unsigned char), psize);
    fread(ptext, psize, sizeof(unsigned char), f);
    fclose(f);

    // B64 encode the key
    /*
    unsigned char *private_key;
    char *x = (char *)private_key;
    Base64Encode(ptext, psize, &x);
    private_key = (unsigned char *)x;*

    ptext = private_key;
    psize = strlen(private_key);*/

    // huge cypher
    unsigned char *ctext = (unsigned char*) calloc(sizeof(unsigned char), psize * 5);

  	/* Provide the message to be encrypted, and obtain the plaintext output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
    int len = 0;
	if(!EVP_EncryptUpdate(ctx, ctext, &len, ptext, psize)) {
        return -5;
    }

    int clen = len;


  	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ctext + len, &len)) {
        return -6;
    }
	clen += len;

    /* Get the tag */
    unsigned char *tag = calloc(sizeof(unsigned char), 17);
  	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        return -7;
    }

    // Also write out the tag to be on par with the java implementation
    memcpy(ctext+clen, tag, 16);
    clen += 16;

    char *enc_b64;
    Base64Encode(ctext, clen, &enc_b64);

    int enc_b64_len = strlen(enc_b64);

    // Add iv sep
    enc_b64 = realloc(enc_b64, enc_b64_len + strlen(ivDelimiter) + strlen(iv_b64) + 1);

    memcpy(enc_b64+enc_b64_len, ivDelimiter, strlen(ivDelimiter));
    enc_b64_len += strlen(ivDelimiter);
    memcpy(enc_b64+enc_b64_len, iv_b64, strlen(iv_b64));
    enc_b64_len += strlen(iv_b64);

    enc_b64[enc_b64_len] = 0;

    printf("%s\n", enc_b64);

    return -1;
    
    FILE *out = fopen("encout", "wb+");
    fwrite(ctext, clen, sizeof(unsigned char), out);
    fclose(out);

    return 0;
}
