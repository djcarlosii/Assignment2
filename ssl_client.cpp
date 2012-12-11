//Dennis Carlos
//860867424
//dcarl002
//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
#include <iostream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client -server serveraddress -port portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("2.  Sending challenge to the server...");
	// generates a random number to use as a challenge
	srand ( time(NULL) );
	int ran = rand() % 99999 + 10000;
	stringstream ss;
	ss << ran;
	string randomNumber=ss.str();
	char buffer[BUFFER_SIZE];
	//memcpy copies into the buffer a specified source of a specified length
	memcpy(buffer, randomNumber.c_str(), BUFFER_SIZE);
	//SSL_write writes from a buffer to a ssl connection for a given length
	int blen = SSL_write(ssl, buffer, BUFFER_SIZE);
	//cout << blen << endl;
    	printf("SUCCESS.\n");
	printf("    (Challenge sent: \"%s\")\n", randomNumber.c_str());

    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");
	cout << endl;
	char buffa[BUFFER_SIZE];
    	int len=5;
	// SSL_read reads from the ssl into a buffer for a specified length
	int b3 = SSL_read(ssl, buffa, BUFFER_SIZE);
	//cout << b3 << endl;
	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)buffa, len).c_str(), len);

    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");
	char buffb[BUFFER_SIZE];
	//BIO_new(BIO_s_mem()); new BIO
        //BIO_s_mem() returns the memory BIO function
	BIO *m3 = BIO_new(BIO_s_mem());
	//BIO_write
	int w3 = BIO_write( m3, buffa, b3);
	cout << w3 << endl;
	//BIO_new_file
	string generated_key="rsapublickey.pem";
	BIO *n3 = BIO_new_file(generated_key.c_str(), "r");
	//PEM_read_bio_RSA_PUBKEY
	RSA *rsa1 = PEM_read_bio_RSA_PUBKEY(n3, NULL, NULL, NULL);
	//RSA_public_decrypt recovers message digest of a size from and to sources using a public key
	//RSA_size() returns modulus size in bytes
	int rsasize = RSA_size(rsa1);
	//cout << rsasize << endl;
	int dec = RSA_public_decrypt(rsasize, (const unsigned char* )buffa, (unsigned char* )buffb, rsa1, RSA_PKCS1_PADDING);
	//cout << dec << endl;
	//BIO_free frees up a single bio
	BIO_free(m3);
	BIO_free(n3);
	string decrypted_key="";
	//buff2hex: via utils.h: returns a hex representation of (len) bytes of (buf) in a string
	generated_key = buff2hex((const unsigned char* ) buffa, 20);
        decrypted_key = buff2hex((const unsigned char* ) buffb, 20);
	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", generated_key.c_str());
	printf("    (Decrypted key: %s)\n", decrypted_key.c_str());

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");

	PAUSE(2);
	BIO_flush(m3);
	BIO *b4 = BIO_new(BIO_s_mem());
 	//BIO_puts writes a string to a BIO
	string fn = filename;
	int blen4 = BIO_puts(b4, fn.c_str());
	//SSL_write
	//cout << blen4 << endl;
	int len4 = SSL_write(ssl, fn.c_str(), blen4);

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...");

	char nfile[BUFFER_SIZE];  
    	//BIO_new_file
	// "newfile.txt" will be the file created and written to 
	BIO *filB = BIO_new_file("newfile.txt", "w");
	int len5 = 1;
	int bytesRec=0;
   	//SSL_read
	//BIO_write
	while(len5 > 0){
    		len5 = SSL_read(ssl, nfile, BUFFER_SIZE);
		bytesRec+=len5;
		int w3 = BIO_write( filB, nfile, len5);
		if ( len5 < BUFFER_SIZE){
			//used on end of file to write to terminal if write is smaller than BUFFER_SIZE
			char tmp[len5];
			memcpy(tmp, nfile, sizeof(tmp));
			for(int i = 0; i < len5; i++){
				cout << tmp[i];
			}
		}
		else{
			//used to output to terminal if writting a full BUFFER_SIZE
			for(int i = 0; i < len5; i++){
				cout << nfile[i];
			}
			
		}
		//cout << w3 << endl;
	}
	//BIO_free
	//cout << nfile;
	BIO_free(filB);

	printf("FILE RECEIVED.\n");
	printf("Wrote to newfile.txt\n");

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	//SSL_shutdown
	SSL_shutdown(ssl);
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    //-------------------------------------------------------------------------
	// Freedom?
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;
	
}
