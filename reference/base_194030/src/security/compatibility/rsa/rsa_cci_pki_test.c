
#include <openssl/rsa.h>
#include <bn.h>
#include "cci.h"


#define PKI_MODULES_SIZE	512

/* Sample RSA 512-bit Public and Private keys */
static cci_b rsa_public_e[] = {0x11};
static cci_b rsa_public_n[] = {
	0x9A,0x6F,0x3E,0x67,0xCD,0x4E,0x0A,0xBB,0x4C,0xE3,0x19,0x03,0xF6,0xEE,0x81,0x9E,
	0xF2,0x06,0xF2,0x61,0x78,0x5D,0xCE,0xFB,0xDB,0x4B,0x94,0xE2,0x44,0xA1,0x68,0x02,
	0x90,0x6C,0xB9,0x57,0x0D,0x79,0x4D,0x20,0x39,0x4D,0x4F,0x73,0xE9,0x33,0xD2,0x4A,
	0x92,0xDF,0x8B,0xE5,0xF6,0xC0,0x97,0x64,0xEE,0x7B,0xC0,0x90,0x68,0x3C,0x8F,0xE7};

static cci_b rsa_private_p[] = {
	0xC3,0xDC,0x66,0xD6,0xBC,0xB7,0xC6,0x0B,0x5B,0x63,0x95,0xEA,0xF3,0x9B,0x33,0xF0,
	0x6A,0x1E,0xF1,0x18,0x50,0x33,0x7C,0x42,0x4C,0x4A,0x9D,0xE0,0x81,0xEF,0x12,0xB3};
static cci_b rsa_private_q[] = {
	0xC9,0xDA,0x87,0xE6,0x8F,0xCD,0x98,0x15,0x0D,0x97,0xF4,0xF9,0xB2,0x8E,0xC0,0xC6,
	0x18,0xCA,0xC5,0xAE,0xE2,0x3B,0x91,0x5E,0x84,0x59,0xB5,0xA2,0xDB,0x13,0x17,0xFD};
static cci_b rsa_private_e[] = {0x11};
static cci_b rsa_private_d[] = {
	0x51,0xC2,0x6C,0x55,0x12,0x56,0x7E,0x26,0xEC,0x78,0x3A,0x6B,0x82,0xBA,0x80,0xDB,
	0xAD,0x4E,0xF8,0xCA,0x30,0xAA,0x22,0x49,0x19,0xBE,0x9A,0x1D,0x6F,0xA0,0xBE,0x97,
	0x1F,0x8D,0x6B,0x42,0x57,0x17,0xBA,0xC3,0xAA,0x85,0xA4,0x4B,0xD8,0x32,0x66,0x3F,
	0x53,0xBE,0x61,0xC4,0xFE,0x85,0x85,0x2B,0x97,0x53,0xEE,0x70,0x51,0x3D,0x08,0x69};
static cci_b rsa_private_n[] = {
	0x9A,0x6F,0x3E,0x67,0xCD,0x4E,0x0A,0xBB,0x4C,0xE3,0x19,0x03,0xF6,0xEE,0x81,0x9E,
	0xF2,0x06,0xF2,0x61,0x78,0x5D,0xCE,0xFB,0xDB,0x4B,0x94,0xE2,0x44,0xA1,0x68,0x02,
	0x90,0x6C,0xB9,0x57,0x0D,0x79,0x4D,0x20,0x39,0x4D,0x4F,0x73,0xE9,0x33,0xD2,0x4A,
	0x92,0xDF,0x8B,0xE5,0xF6,0xC0,0x97,0x64,0xEE,0x7B,0xC0,0x90,0x68,0x3C,0x8F,0xE7};
static cci_b rsa_private_phi[] = {
	0x9A,0x6F,0x3E,0x67,0xCD,0x4E,0x0A,0xBB,0x4C,0xE3,0x19,0x03,0xF6,0xEE,0x81,0x9E,
	0xF2,0x06,0xF2,0x61,0x78,0x5D,0xCE,0xFB,0xDB,0x4B,0x94,0xE2,0x44,0xA1,0x68,0x01,
	0x02,0xB5,0xCA,0x99,0xC0,0xF3,0xEE,0xFF,0xD0,0x51,0xC4,0x8F,0x43,0x09,0xDD,0x94,
	0x0F,0xF5,0xD5,0x1E,0xC4,0x51,0x89,0xC4,0x1D,0xD7,0x6D,0x0D,0x0B,0x3A,0x65,0x38};
static cci_b rsa_private_dp[] = {
	0x2E,0x15,0xBD,0xD8,0x2C,0x67,0x79,0xE4,0x8D,0xF9,0x50,0x73,0x84,0x9C,0xFD,0x29,
	0x82,0x61,0xA2,0x23,0xD6,0xA2,0xB3,0xD3,0x5D,0x3E,0xBB,0xBC,0x5A,0xCE,0xD7,0x39};
static cci_b rsa_private_dq[] = {
	0x17,0xBF,0x5B,0x48,0x4D,0x27,0x3F,0x11,0x89,0x20,0xEF,0xA4,0xE7,0xD4,0x8F,0x26,
	0x5D,0x45,0x08,0x32,0xB1,0x34,0x2F,0x38,0x4B,0xCE,0x51,0x9A,0xB0,0x5C,0x99,0x69};
static cci_b rsa_private_pInv[] = {
	0x7A,0xAD,0xB3,0x33,0x85,0x65,0x04,0x95,0x63,0x8A,0x2C,0x10,0xD0,0x5D,0xEF,0xE8,
	0x98,0x5A,0xF5,0x6C,0x1F,0xB9,0xB3,0x37,0xC2,0x00,0x5B,0xAA,0xF6,0x98,0xBD,0x24};
static cci_b rsa_private_qInv[] = {
	0x4C,0xD3,0x15,0x6A,0x9A,0xC1,0x26,0x41,0x4B,0xD1,0xF1,0x13,0x3B,0x19,0xED,0x61,
	0x39,0xB5,0x6B,0xAF,0xEA,0xDA,0xD7,0xBB,0x01,0x5A,0xB8,0x5F,0x55,0x6A,0x1D,0x6C};
static cci_b rsa_private_cp[] = {
	0x3C,0x93,0x50,0x59,0x71,0x61,0x80,0x89,0x15,0xC3,0x65,0x7C,0xDF,0xC6,0x72,0xF2,
	0x2D,0x8B,0x41,0xD9,0xFD,0xF4,0xB4,0xDB,0x56,0x28,0xDC,0x0E,0x97,0x47,0x61,0x3F,
	0xE7,0x2A,0x00,0xFA,0x1A,0xC0,0x80,0x3F,0x16,0x87,0x8A,0xEA,0xAD,0x65,0x25,0x34,
	0x2D,0xC4,0x06,0xDF,0x99,0x2B,0x2C,0xD4,0xB8,0xDD,0xDF,0x47,0x85,0x87,0xC7,0xBC};
static cci_b rsa_private_cq[] = {
	0x5D,0xDB,0xEE,0x0E,0x5B,0xEC,0x8A,0x32,0x37,0x1F,0xB3,0x87,0x17,0x28,0x0E,0xAC,
	0xC4,0x7B,0xB0,0x87,0x7A,0x69,0x1A,0x20,0x85,0x22,0xB8,0xD3,0xAD,0x5A,0x06,0xC2,
	0xA9,0x42,0xB8,0x5C,0xF2,0xB8,0xCC,0xE1,0x22,0xC5,0xC4,0x89,0x3B,0xCE,0xAD,0x16,
	0x65,0x1B,0x85,0x06,0x5D,0x95,0x6A,0x90,0x35,0x9D,0xE1,0x48,0xE2,0xB4,0xC8,0x2C};



#define MY_PRIVATE_DATA	"Only for secure eyes"

static void pki_process( CCI_PROVIDER_ID providerId, CCIPublicKey privateKey, CCIPublicKey publicKey, cci_t keySize )
{
	cci_b			*digestSignature=0, *messageSignature=0, *cipherText=0, *plainText=0;
	cci_t			digestSignatureLength, messageSignatureLength, cipherTextLength, plainTextLength, messageSize;
	cci_st			cciStatus;
	cci_b			digest[CCI_SHA1_DIGESTSIZE], *message;


	/*
	** --- Sign an arbitrary message with the private key
	*/
	messageSize = (rand() % 30000) + 1000;
	message = (cci_b *)cciAlloc( messageSize );
	cciRand( CCI_DEF_PROVIDER_ID, message, messageSize);
	cciStatus = cciPKISignMessage( privateKey, CCI_PUBLICKEY_HASH_SHA1, message, messageSize, &messageSignature, &messageSignatureLength );  
	if (!CCISUCCESS( cciStatus )) printf("cciPKISignMessage() failed, status = %u\n", cciStatus);


	/*
	** --- Verify the signature with the public key
	*/
	cciStatus = cciPKIVerifyMessage( publicKey, CCI_PUBLICKEY_HASH_SHA1, message, messageSize, messageSignature, messageSignatureLength );  
	if (!CCISUCCESS( cciStatus ))
	{
		printf("\n\nRSA %u-bit MESSAGE Signature verification FAILED!!, status = %u\n", PKI_MODULES_SIZE, cciStatus );

		CCI_SHOW_BUFFER("INPUT Data", message, messageSize);
		CCI_SHOW_BUFFER("RSA Signature", messageSignature, messageSignatureLength);

	}
	else
	{
		printf("MESSAGE Signature verification PASSED (%u)!!!\n", messageSize);
	}
	cciFree( message );
	cciFree( messageSignature );


	/*
	** --- Sign a digest with the private key
	*/
	cciRand( CCI_DEF_PROVIDER_ID, digest, sizeof(digest));
	cciStatus = cciPKISignDigest( privateKey, CCI_PUBLICKEY_HASH_SHA1, digest, &digestSignature, &digestSignatureLength );  
	if (!CCISUCCESS( cciStatus )) printf("cciPKISignDigest() failed, status = %u\n", cciStatus);

	/*
	** --- Verify the signature with the public key
	*/
	cciStatus = cciPKIVerifyDigest( publicKey, CCI_PUBLICKEY_HASH_SHA1, digest, digestSignature, digestSignatureLength );  
	if (!CCISUCCESS( cciStatus ))
	{
		printf("\n\nRSA %u-bit DIGEST Signature verification FAILED!!, status = %u\n\n", PKI_MODULES_SIZE, cciStatus );

		CCI_SHOW_BUFFER("INPUT Data", digest, sizeof(digest));
		CCI_SHOW_BUFFER("RSA Signature", digestSignature, digestSignatureLength);
	}
	else
	{
		printf("DIGEST Signature verification PASSED !!!\n");
	}
	cciFree( digestSignature );


	/*
	** --- Encrypt some data with the public key
	*/
	messageSize = (rand() % 30000) + 1000;
	message = (cci_b *)cciAlloc( messageSize );
	cciRand( CCI_DEF_PROVIDER_ID, message, messageSize);
	cciStatus = cciPKIEncrypt( publicKey, CCI_PUBLICKEY_PKCS1_V1_5, 0,message, messageSize, &cipherText, &cipherTextLength );  
	if (!CCISUCCESS( cciStatus )) 
		printf("cciPKIEncrypt() failed, status = %u\n", cciStatus);

	/*
	** --- Decrypt some data with the private key
	*/
	cciStatus = cciPKIDecrypt( privateKey, CCI_PUBLICKEY_PKCS1_V1_5,0, cipherText, cipherTextLength, &plainText, &plainTextLength  );  
	if (!CCISUCCESS( cciStatus )) 
		printf("cciPKIDecrypt() failed, status = %u\n", cciStatus);
	else
	{

		/*
		** --- Make sure it's the same as the original
		*/
		if (!memcmp( (unsigned char *)message, plainText, plainTextLength ))
			printf("PUBLIC/PRIVATE-KEY Encryption/Decryption PASSED (%u)!!!\n", messageSize);
		else
		{
			printf("PUBLIC/PRIVATE-KEY Encryption/Decryption FAILED !!!\n");

			CCI_SHOW_BUFFER("Private Data", message, messageSize);
			CCI_SHOW_BUFFER("CipherText", cipherText, cipherTextLength);
			CCI_SHOW_BUFFER("Plain Text", plainText, plainTextLength);
		}
	}
	cciFree( message );
	cciFree( cipherText );
	cciFree( plainText );

	/*
	** --- Encrypt some data with the private key
	*/
	messageSize = (rand() % 30000) + 1000;
	message = (cci_b *)cciAlloc( messageSize );
	cciRand( CCI_DEF_PROVIDER_ID, message, messageSize);
	cciStatus = cciPKIEncrypt( privateKey, CCI_PUBLICKEY_PKCS1_V1_5,0, message, messageSize, &cipherText, &cipherTextLength );  
	if (!CCISUCCESS( cciStatus )) 
		printf("cciPKI_Encrypt() failed, status = %u\n", cciStatus);

	/*
	** --- Decrypt some data with the public key
	*/
	cciStatus = cciPKIDecrypt( publicKey, CCI_PUBLICKEY_PKCS1_V1_5, 0,cipherText, cipherTextLength, &plainText, &plainTextLength  );  
	if (!CCISUCCESS( cciStatus )) 
		printf("cciPKIDecrypt() failed, status = %u\n", cciStatus);
	else
	{

		/*
		** --- Make sure it's the same as the original
		*/
		if (!memcmp( (unsigned char *)message, plainText, plainTextLength ))
			printf("PRIVATE/PUBLIC-KEY Encryption/Decryption PASSED (%u)!!!\n", messageSize);
		else
		{
			printf("PRIVATE/PUBLIC-KEY Encryption/Decryption FAILED !!!\n");

			CCI_SHOW_BUFFER("Private Data", message, messageSize);
			CCI_SHOW_BUFFER("CipherText", cipherText, cipherTextLength);
			CCI_SHOW_BUFFER("Plain Text", plainText, plainTextLength);
		}
	}
	cciFree( message );
	cciFree( cipherText );
	cciFree( plainText );

}

void cciPkiTest_RandKey( CCI_PROVIDER_ID providerId )
{
	CCIPublicKey	publicKey;
	CCIPublicKey	privateKey;
	cci_t			keySize, idx;

	/*
	** --- Create Public and Private keys, depending on key size and target 
	**     this may take awhile
	*/
	for( idx = 0; idx < 10; idx++ )
	{
		
		keySize = rand() % 104;
		keySize += 24;
		keySize *= 16;
		
		printf("KeySize %u...\n", keySize );
		cciPKIGenerateKeys( providerId, &privateKey, &publicKey, keySize );

		/*
		** --- Run some tests...
		*/
		pki_process( providerId, privateKey, publicKey, keySize );

		/*
		** --- Freeup resources...
		*/
		cciPKIKeyDestroy( privateKey );
		cciPKIKeyDestroy( publicKey );

	}

}



void cciPkiTest_NewKeys( CCI_PROVIDER_ID providerId )
{
	CCIPublicKey	publicKey;
	CCIPublicKey	privateKey;

	/*
	** --- Create Public and Private keys, depending on key size and target 
	**     this may take awhile
	*/
	cciPKIGenerateKeys( providerId, &privateKey, &publicKey, PKI_MODULES_SIZE );

	/*
	** --- Run some tests...
	*/
	pki_process( providerId, privateKey, publicKey, PKI_MODULES_SIZE );

	/*
	** --- Freeup resources...
	*/
	cciPKIKeyDestroy( privateKey );
	cciPKIKeyDestroy( publicKey );

}

void cciPkiTest_CannedKeys( CCI_PROVIDER_ID providerId )
{
	CCIPublicKey	publicKey;
	CCIPublicKey	privateKey;

	/*
	** --- Generate private and public key objects...
	*/
	cciPKIKeyCreate( providerId, CCI_RSA_PUBLIC_KEY, &publicKey );
	cciPKIKeyCreate( providerId, CCI_RSA_PRIVATE_KEY, &privateKey );

	/*
	** --- Populate Private and public key components
	*/
	cciPKIKeyCompSet( privateKey, CCI_RSA_PRIME_FACTOR_P,  rsa_private_p, sizeof(rsa_private_p));
	cciPKIKeyCompSet( privateKey, CCI_RSA_PRIME_FACTOR_Q,  rsa_private_q, sizeof(rsa_private_q));
	cciPKIKeyCompSet( privateKey, CCI_RSA_MODULAS,  rsa_private_n, sizeof(rsa_private_n));
	cciPKIKeyCompSet( privateKey, CCI_RSA_PUBLIC_EXPONENT,  rsa_private_e, sizeof(rsa_private_e));
	cciPKIKeyCompSet( privateKey, CCI_RSA_PHI,  rsa_private_phi, sizeof(rsa_private_phi));
	cciPKIKeyCompSet( privateKey, CCI_RSA_PRIVATE_EXPONENT,  rsa_private_d, sizeof(rsa_private_d));
	cciPKIKeyCompSet( privateKey, CCI_RSA_EXPONENT_dP,  rsa_private_dp, sizeof(rsa_private_dp));
	cciPKIKeyCompSet( privateKey, CCI_RSA_EXPONENT_dQ,  rsa_private_dq, sizeof(rsa_private_dq));
	cciPKIKeyCompSet( privateKey, CCI_RSA_CRT_PINV,  rsa_private_pInv, sizeof(rsa_private_pInv));
	cciPKIKeyCompSet( privateKey, CCI_RSA_CRT_QINV,  rsa_private_qInv, sizeof(rsa_private_qInv));
	cciPKIKeyCompSet( privateKey, CCI_RSA_CQ,  rsa_private_cp, sizeof(rsa_private_cp));
	cciPKIKeyCompSet( privateKey, CCI_RSA_CP,  rsa_private_cq, sizeof(rsa_private_cq));


	cciPKIKeyCompSet( publicKey, CCI_RSA_PUBLIC_EXPONENT, rsa_public_e, sizeof(rsa_public_e));
	cciPKIKeyCompSet( publicKey, CCI_RSA_MODULAS, rsa_public_n, sizeof(rsa_public_n));
	
	/*
	** --- Run some tests...
	*/
	pki_process( providerId, privateKey, publicKey, sizeof(rsa_private_n) * 8 );

	/*
	** --- Freeup resources...
	*/
	cciPKIKeyDestroy( privateKey );
	cciPKIKeyDestroy( publicKey );

}


RSA *cci_to_openssl( CCIPublicKey privateKey )
{
	RSA *opensslKey;
	cci_b *N, *P, *Q, *E, *D, *dP, *dQ, *qINV;
	cci_t sN, sP, sQ, sE, sD, sdP, sdQ, sqINV;

	/*
	** --- Extract byte-streams from CCI keys
	*/
	qINV = dP = dQ = E = D = N = P = Q = NULL;
	sqINV = sdP = sdQ = sD = sE = sN = sP = sQ = 0;
	cciPKIKeyCompGet( privateKey, CCI_RSA_MODULAS, &N, &sN );
	cciPKIKeyCompGet( privateKey, CCI_RSA_PUBLIC_EXPONENT, &E, &sE );
	cciPKIKeyCompGet( privateKey, CCI_RSA_PRIVATE_EXPONENT, &D, &sD );
	cciPKIKeyCompGet( privateKey, CCI_RSA_PRIME_FACTOR_P, &P, &sP );
	cciPKIKeyCompGet( privateKey, CCI_RSA_PRIME_FACTOR_Q, &Q, &sQ );
	cciPKIKeyCompGet( privateKey, CCI_RSA_EXPONENT_dP, &dP, &sdP );
	cciPKIKeyCompGet( privateKey, CCI_RSA_EXPONENT_dQ, &dQ, &sdQ );
	cciPKIKeyCompGet( privateKey, CCI_RSA_CRT_QINV, &qINV, &sqINV );


	/*
	** --- Set key components into RSA key
	*/
	opensslKey = RSA_new();
	opensslKey->n = BN_bin2bn(N, sN, opensslKey->n); \
	opensslKey->e = BN_bin2bn(E, sE, opensslKey->e); \
	opensslKey->d = BN_bin2bn(D, sD, opensslKey->d); \
	opensslKey->p = BN_bin2bn(P, sP, opensslKey->p); \
	opensslKey->q = BN_bin2bn(Q, sQ, opensslKey->q); \
	opensslKey->dmp1 = BN_bin2bn(dP, sdP, opensslKey->dmp1); \
	opensslKey->dmq1 = BN_bin2bn(dQ, sdQ, opensslKey->dmq1); \
	opensslKey->iqmp = BN_bin2bn(qINV, sqINV, opensslKey->iqmp); \


	/*
	** ---Free memory resources
	*/
	cciFree( N );
	cciFree( E );
	cciFree( D );
	cciFree( P );
	cciFree( Q );
	cciFree( dP );
	cciFree( dQ );
	cciFree( qINV );

	return( opensslKey );
}
#if 0
#define BN_STREAM( cciSize, cciStream, bn ) {cciStream = (cci_b *)cciAlloc( BN_num_bytes( bn ));\
                             if(!cciStream){ printf("openssl_to_cci cciAlloc failed\n"); taskSuspend(0);}\
                             else { printf("openssl_to_cci cciAlloc passed\n");}\
                             cciSize = BN_bn2bin( bn, cciStream );}
#else
#define BN_STREAM( cciSize, cciStream, bn ) {cciStream = (cci_b *)cciAlloc( BN_num_bytes( bn ));cciSize = BN_bn2bin( bn, cciStream );}
#endif
BOOL openssl_to_cci( RSA *opensslKey, CCIPublicKey *privateKey, CCIPublicKey *publicKey )
{
	cci_b *N, *P, *Q, *E, *D, *dP, *dQ, *qINV;
	cci_t sN, sP, sQ, sE, sD, sdP, sdQ, sqINV;



	/*
	** --- Generate private and public key objects...
	*/
	cciPKIKeyCreate( CCI_DEF_PROVIDER_ID, CCI_RSA_PUBLIC_KEY, publicKey  );
	cciPKIKeyCreate( CCI_DEF_PROVIDER_ID, CCI_RSA_PRIVATE_KEY, privateKey );


	/*
	** --- Extract byte-streams from RSA key
	*/
	qINV = dP = dQ = E = D = N = P = Q = NULL;
	sqINV = sdP = sdQ = sD = sE = sN = sP = sQ = 0;

    
	if(opensslKey->n) BN_STREAM( sN, N, opensslKey->n );     
	if(opensslKey->e) BN_STREAM( sE, E, opensslKey->e );
	if(opensslKey->d) BN_STREAM( sD, D, opensslKey->d );
	if(opensslKey->p) BN_STREAM( sP, P, opensslKey->p );
	if(opensslKey->q) BN_STREAM( sQ, Q, opensslKey->q );
	if(opensslKey->dmp1) BN_STREAM( sdP, dP, opensslKey->dmp1 );
	if(opensslKey->dmq1) BN_STREAM( sdQ, dQ, opensslKey->dmq1 );
	if(opensslKey->iqmp) BN_STREAM( sqINV, qINV, opensslKey->iqmp );


	
	
	/* --- Set CCI private key components */

	cciPKIKeyCompSet( *privateKey, CCI_RSA_MODULAS, N, sN );
	cciPKIKeyCompSet( *privateKey, CCI_RSA_PUBLIC_EXPONENT, E, sE );
	cciPKIKeyCompSet( *privateKey, CCI_RSA_PRIVATE_EXPONENT, D, sD );
	cciPKIKeyCompSet( *privateKey, CCI_RSA_PRIME_FACTOR_P, P, sP );

	cciPKIKeyCompSet( *privateKey, CCI_RSA_PRIME_FACTOR_Q, Q, sQ );

	cciPKIKeyCompSet( *privateKey, CCI_RSA_EXPONENT_dP, dP, sdP );
	cciPKIKeyCompSet( *privateKey, CCI_RSA_EXPONENT_dQ, dQ, sdQ );
	cciPKIKeyCompSet( *privateKey, CCI_RSA_CRT_QINV, qINV, sqINV );

	/* --- Set CCI public key components */
	cciPKIKeyCompSet( *publicKey, CCI_RSA_MODULAS, N, sN );
	cciPKIKeyCompSet( *publicKey, CCI_RSA_PUBLIC_EXPONENT, E, sE );


	/*
	** ---Free memory resources
	*/

	cciFree( N );
	cciFree( E );
	cciFree( D );
	cciFree( P );
	cciFree( Q );
	cciFree( dP );
	cciFree( dQ );
	cciFree( qINV );

	return( TRUE );
}


static const char rnd_seed[] = "string to make the random number generator think it has entropy";

void cci_to_rsa(CCI_PROVIDER_ID providerId)
{
	cci_b			*cciCipherText=0, *cciPlainText=0;
	cci_t			cciCipherTextLength, cciPlainTextLength;
	cci_b			opensslCipherText[512], opensslPlainText[512];
	cci_t			opensslCipherTextLength, opensslPlainTextLength;
	cci_st			cciStatus;
	CCIPublicKey	cciPublicKey;
	CCIPublicKey	cciPrivateKey;
	RSA 			*opensslKey;
    int temp;

    RAND_seed(rnd_seed, sizeof rnd_seed); 
	opensslKey = RSA_generate_key(PKI_MODULES_SIZE, 0x17, NULL, NULL );


	/*
	** --- Generate private and public key objects...
	*/
	cciPKIGenerateKeys( providerId, &cciPrivateKey, &cciPublicKey, PKI_MODULES_SIZE );

	/*
	** --- Create OPENSSL RSA key from CCI RSA key private key
	*/
	opensslKey = cci_to_openssl( cciPrivateKey );


	/* --- CCI Encrypt */
	cciStatus = cciPKIEncrypt( cciPublicKey, CCI_PUBLICKEY_PKCS1_V1_5,0, MY_PRIVATE_DATA, (cci_t)strlen(MY_PRIVATE_DATA), &cciCipherText, &cciCipherTextLength );  
	if (!CCISUCCESS( cciStatus )) printf(" cciPKI_Encrypt() FAILED, status = %u\n", cciStatus );

	/* --- OPENSSL Encrypt */
	temp = RSA_public_encrypt(strlen(MY_PRIVATE_DATA), MY_PRIVATE_DATA, opensslCipherText, opensslKey, RSA_PKCS1_PADDING);
   
	if (temp<=0){
	 printf(" RSA_public_encrypt() FAILED\n" );
     return;
    }
    opensslCipherTextLength = temp;
	/* --- CCI Decrypt using OPENSSL cipherText buffer */
	cciStatus = cciPKIDecrypt( cciPrivateKey, CCI_PUBLICKEY_PKCS1_V1_5,0, opensslCipherText, opensslCipherTextLength, &cciPlainText, &cciPlainTextLength  );  
	if (!CCISUCCESS( cciStatus )) printf(" cciPKI_Encrypt() FAILED, status = %u\n", cciStatus );

	/* --- OPENSSL Decrypt using CCI cipherText buffer*/
	temp = RSA_private_decrypt(cciCipherTextLength, cciCipherText, opensslPlainText, opensslKey, RSA_PKCS1_PADDING);
	if (temp <=0)
	{
	 printf(" RSA_private_decrypt() FAILED\n");
     return;
    }
    opensslPlainTextLength = temp;

	/* --- Compare output buffers */
	if (!memcmp( opensslPlainText, cciPlainText, opensslPlainTextLength ))
	{
		printf("CCI-RSA Encryption tests PASSED !!!\n");
	}
	else
	{
		printf("CCI-RSA Encryption tests FAILED !!!\n");

		CCI_SHOW_BUFFER("Private Data", MY_PRIVATE_DATA, strlen(MY_PRIVATE_DATA));
		CCI_SHOW_BUFFER("CCI CipherText", cciCipherText, cciCipherTextLength);
		CCI_SHOW_BUFFER("OPENSSL CipherText", opensslCipherText, opensslCipherTextLength);
		CCI_SHOW_BUFFER("CCI PlainText", cciPlainText, cciPlainTextLength);
		CCI_SHOW_BUFFER("OPENSSL PlainText", opensslPlainText, opensslPlainTextLength);
	}



	/*
	** --- Freeup key data	
	*/
	cciFree( cciCipherText );
	cciFree( cciPlainText );
	cciPKIKeyDestroy( cciPrivateKey );
	cciPKIKeyDestroy( cciPublicKey );
	RSA_free(opensslKey);
}




void rsa_to_cci(CCI_PROVIDER_ID providerId)
{
	cci_b			*cciCipherText=0, *cciPlainText=0;
	cci_t			cciCipherTextLength, cciPlainTextLength;
	cci_b			opensslCipherText[512], opensslPlainText[512];
	cci_t			opensslCipherTextLength, opensslPlainTextLength;
	cci_st			cciStatus;
	CCIPublicKey	cciPublicKey;
	CCIPublicKey	cciPrivateKey;
	RSA 			*opensslKey;
    int temp;

	/*
	** --- Generate RSA key object...
	*/

    RAND_seed(rnd_seed, sizeof rnd_seed); 
	opensslKey = RSA_generate_key(PKI_MODULES_SIZE, 0x17, NULL, NULL );

	if(!opensslKey)
	{
		printf("RSA_generate_key failed!\n");
		return;
	}

	/*
	** --- Create CCI RSA keys from OPENSSL key...
	*/
	openssl_to_cci( opensslKey, &cciPrivateKey, &cciPublicKey );


	/* --- CCI Encrypt */
#define PUBLICKEY 0
#if PUBLICKEY
	cciStatus = cciPKIEncrypt( cciPublicKey, CCI_PUBLICKEY_PKCS1_V1_5,0, MY_PRIVATE_DATA, (cci_t)strlen(MY_PRIVATE_DATA), &cciCipherText, &cciCipherTextLength );  
#else
    cciStatus = cciPKIEncrypt( cciPrivateKey, CCI_PUBLICKEY_PKCS1_V1_5,0, MY_PRIVATE_DATA, (cci_t)strlen(MY_PRIVATE_DATA), &cciCipherText, &cciCipherTextLength );  
#endif
	if (!CCISUCCESS( cciStatus )) printf(" cciPKI_Encrypt() FAILED, status = %u\n", cciStatus );

	/* --- OPENSSL Encrypt */
#if PUBLICKEY
	temp = RSA_public_encrypt(strlen(MY_PRIVATE_DATA), MY_PRIVATE_DATA, opensslCipherText, opensslKey, RSA_PKCS1_PADDING);
#else
    temp = RSA_private_encrypt(strlen(MY_PRIVATE_DATA), MY_PRIVATE_DATA, opensslCipherText, opensslKey, RSA_PKCS1_PADDING);    
#endif

    opensslCipherTextLength = temp;
#if PUBLICKEY
	if (temp<=0)
	{
	 printf(" RSA_public_encrypt() FAILED\n" );
     return;
    }
#else
   	if (temp<=0)
	{
     printf(" RSA_private_encrypt() FAILED\n" );
     return;
     }
#endif
	/* --- CCI Decrypt using OPENSSL cipherText buffer */
#if PUBLICKEY
	cciStatus = cciPKIDecrypt( cciPrivateKey, CCI_PUBLICKEY_PKCS1_V1_5,0, opensslCipherText, opensslCipherTextLength, &cciPlainText, &cciPlainTextLength  );  
	if (!CCISUCCESS( cciStatus )) printf(" cciPKI_Decrypt() FAILED, status = %u\n", cciStatus );
#else
	cciStatus = cciPKIDecrypt( cciPublicKey, CCI_PUBLICKEY_PKCS1_V1_5,0, opensslCipherText, opensslCipherTextLength, &cciPlainText, &cciPlainTextLength  );  
	if (!CCISUCCESS( cciStatus )) printf(" cciPKI_Encrypt() FAILED, status = %u\n", cciStatus );
#endif


	/* --- OPENSSL Decrypt using CCI cipherText buffer*/
#if PUBLICKEY
	temp = RSA_private_decrypt(cciCipherTextLength, cciCipherText, opensslPlainText, opensslKey, RSA_PKCS1_PADDING);
	if (temp<=0)
	{
	 printf(" RSA_private_decrypt() FAILED\n");
     return;
    }
#else

	temp = RSA_public_decrypt(cciCipherTextLength, cciCipherText, opensslPlainText, opensslKey, RSA_PKCS1_PADDING);
	if (temp<=0)
	{
	 printf(" RSA_public_decrypt() FAILED\n");
     return;
    }
#endif

    opensslPlainTextLength = temp;
	/* --- Compare output buffers */
	if (!memcmp( opensslPlainText, cciPlainText, opensslPlainTextLength ))
	{
		printf("RSA-CCI Encryption tests PASSED !!!\n");
	}
	else
	{
		printf("RSA-CCI Encryption tests FAILED !!!\n");

		CCI_SHOW_BUFFER("Private Data", MY_PRIVATE_DATA, strlen(MY_PRIVATE_DATA));
		CCI_SHOW_BUFFER("CCI CipherText", cciCipherText, cciCipherTextLength);
		CCI_SHOW_BUFFER("OPENSSL CipherText", opensslCipherText, opensslCipherTextLength);
		CCI_SHOW_BUFFER("CCI PlainText", cciPlainText, cciPlainTextLength);
		CCI_SHOW_BUFFER("OPENSSL PlainText", opensslPlainText, opensslPlainTextLength);
	}



	/*
	** --- Freeup key data	
	*/
	cciFree( cciCipherText );
	cciFree( cciPlainText );
	cciPKIKeyDestroy( cciPrivateKey );
	cciPKIKeyDestroy( cciPublicKey );
	RSA_free(opensslKey);
}

