#include <string.h>
#include <stdio.h>
#include <assert.h>

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
	BUF_MEM* bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	//*b64text=(*bufferPtr).data;

	return (0); //success
}

int main(int argc, char **argv) {
    //Static stuff
    char key_b64[] = "WANM0gRv+DhaexIsI0T3Lg==";
    unsigned char *key;
    size_t key_length;
    Base64Decode(key_b64, &key, &key_length);

    char iv_b64[] = "gKm3n+mJzeY26q4OfuZEqg==";
    unsigned char *iv;
    size_t iv_length;
    Base64Decode(iv_b64, &iv, &iv_length);

    char tag_b64[] = "PboI9tqHHX3QeAA22PIu4w==";
    unsigned char *tag;
    size_t tag_length;
    Base64Decode(tag_b64, &tag, &tag_length);


    // Init
    EVP_CIPHER_CTX *ctx;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    /* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        return -2;
    }

  	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_length, NULL)) {
        return -3;
    }

  	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        return -4;
    }

    // READ FILE
    FILE *f = fopen("enc", "rb");
    fseek(f , 0L , SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    unsigned char *ctext = (unsigned char*) calloc(sizeof(unsigned char), fsize);
    fread(ctext, fsize, sizeof(unsigned char), f);
    fclose(f);

    // huge plain
    unsigned char *ptext = (unsigned char*) calloc(sizeof(unsigned char), fsize * 5);
    int plen = 0;


  	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, ptext, &plen, ctext, fsize - tag_length)) {
        return -5;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_length, tag)) {
        return -5;
    }


	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
    int len = plen;
	int ret = EVP_DecryptFinal_ex(ctx, ptext + plen, &len);

    FILE *out = fopen("out", "wb+");
    fwrite(ptext, plen, sizeof(unsigned char), out);
    fclose(out);

    printf("ret: %d\n", ret);

    return 0;
}
