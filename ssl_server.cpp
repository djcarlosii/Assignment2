//Dennis Carlos
//860867424
//dcarl002
//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
#include <iostream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
    SSL_library_init();
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("2. Waiting for client to connect and send challenge...");
    	string challenge="";
	char buffer[BUFFER_SIZE];
	// SSL_read reads from the ssl into a buffer for a specified length
	int blen = SSL_read(ssl, buffer, BUFFER_SIZE);
	//cout << blen << endl;
	challenge = buffer;
	//cout << challenge << endl; 	
	printf("DONE.\n");
	printf("    (Challenge: \"%s\")\n", challenge.c_str());

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("3. Generating SHA1 hash...");
	//BIO_new(BIO_s_mem()); new BIO
        //BIO_s_mem() returns the memory BIO function
	BIO *mem = BIO_new(BIO_s_mem());
	//BIO_write
	int wr = BIO_write( mem, buffer, blen);
	//cout << wr << endl;	
	//BIO_new(BIO_f_md()); new BIO
	//BIO_f_md returns the message digest BIO method
	BIO * md = BIO_new(BIO_f_md());
	//BIO_set_md;
	BIO_set_md(md, EVP_sha1());
	char bf[EVP_MAX_MD_SIZE];
	//BIO_push; appends the second parameter to the first
	BIO_push(md, mem);
	//BIO_gets;
	int got = BIO_gets(md, bf, EVP_MAX_MD_SIZE);
	//cout << got << endl;
	string hash_string = "";
	//buff2hex: via utils.h: returns a hex representation of (len) bytes of (buf) in a string
	hash_string = buff2hex((const unsigned char*)bf, got);
	cout << hash_string << endl; 
    	int mdlen=got;

	printf("SUCCESS.\n");
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", hash_string.c_str(), mdlen);

    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
	printf("4. Signing the key...");
    	//PEM_read_bio_RSAPrivateKey reads a private key using a passphrase. NULL.
    	char privkey[] = "rsaprivatekey.pem";
    	BIO *privB = BIO_new_file(privkey, "r");
	RSA *rsa2 = PEM_read_bio_RSAPrivateKey(privB, NULL, NULL, NULL);
	int rsasize = RSA_size(rsa2)-11;
	//cout << rsasize << endl;
    	//RSA_private_encrypt signs a number of bytes from a source using a private key to another source.
	// RSA_PCKS1_PADDING version 1.5 padding.
    	unsigned char b4[128];
    	int siglen = RSA_private_encrypt(rsasize, (const unsigned char*)bf, b4, rsa2, RSA_PKCS1_PADDING);
	//cout << siglen << endl;
    	unsigned char* signature= b4;
    	printf("DONE.\n");
   	printf("    (Signed key length: %d bytes)\n", siglen);
    	printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signature, siglen).c_str(), siglen);

    //-------------------------------------------------------------------------
	// 5. Send the signature to the client for authentication
	printf("5. Sending signature to client for authentication...");
	//BIO_flush writes out any internally buffered data or used to signal end of file
	BIO_flush(mem);
	//SSL_write
	char b5[BUFFER_SIZE];
    	memcpy(b5, signature, sizeof(b5)); 
	//cout << "got here" << endl;	
	int len5 = SSL_write(ssl, b5, BUFFER_SIZE);
    	printf("DONE.\n");
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("6. Receiving file request from client...");

   	//SSL_read
    	char file[BUFFER_SIZE];
	memset(file,0,sizeof(file));
	//SSL_read;
	int b6 = SSL_read(ssl, file, BUFFER_SIZE);
	//cout << b6 << endl;
	printf("RECEIVED.\n");
    	printf("    (File requested: \"%s\"\n", file);

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);
	//BIO_flush
	BIO_flush(mem);
	//BIO_new_file
    	char send[BUFFER_SIZE];
	int bytesSent=0;
	int len7 = 1;
    	BIO *filB = BIO_new_file(file, "r");
	//BIO_puts(server, "fnf");
	if(filB == NULL){
		//fnf: file not found
		int blen7 = BIO_puts(filB, "fnf");
		cout << endl << "ERROR: file not found!" << endl;
		SSL_write(ssl, filB, BUFFER_SIZE);
	}
    	//BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
	else{
	//SSL_write(ssl, buffer, bytesRead);
		//while something has been read from file
		while(len7 > 0){
			int b7 = BIO_read( filB, send, BUFFER_SIZE);
			//b7 is used to avoid having to do a full BUFFER_SIZE write at the end of a file
			//this avoids writing junk in ssl.
    			len7 = SSL_write(ssl, send, b7);
			bytesSent+=len7;
		}
	    	printf("SENT.\n");
    		printf("    (Bytes sent: %d)\n", bytesSent);
	}

    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("8. Closing connection...");

	//SSL_shutdown
	SSL_shutdown(ssl);
    	//BIO_reset
	BIO_reset(server);
    	printf("DONE.\n");
    	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom?
    
	BIO_free_all(server);
	return EXIT_SUCCESS;
}
