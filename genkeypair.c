#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

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

	const int rsaKeyLen = 2048;

    EVP_PKEY *localKeyPair = NULL;

    // Init RSA
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if(EVP_PKEY_keygen_init(ctx) <= 0) {
        return 1;
    }

    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, rsaKeyLen) <= 0) {
        return 2;
    }

    if(EVP_PKEY_keygen(ctx, &localKeyPair) <= 0) {
        return 3;
    }
    EVP_PKEY_CTX_free(ctx);

    printf("Key correctly generated\n");

	FILE *pub = fopen("pub", "w+");
	PEM_write_PUBKEY(pub, localKeyPair);
	fclose(pub);

	{

	BIO* bio;
    BIO* b64;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	i2d_PUBKEY_bio(bio, localKeyPair);
	BIO_flush(bio);
	char *data = NULL;
	size_t size = BIO_get_mem_data(bio, &data);
	data[size] = 0;
	printf("%d\n", size);
	printf("%s\n", data);


	BIO_set_close(bio, BIO_CLOSE);
	BIO_free_all(bio);

	EVP_PKEY_free(localKeyPair);

	}

	


	return  0;

}
