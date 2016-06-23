
#include <stdio.h>

void openssl_test(void);

#include <string.h>
#include "wrn/cci/cci.h"
/* externs */
STATUS sslMultiThreadInit(void); 
void* sslMemoryAllocate (size_t elemSize);
void* sslMemoryRealloc(void *pBlock, size_t newSize);
void sslMemoryFree (void* p_object);

/* typedefs */

/* globals */

/* defines */

/* locals */

/* forward declarations  */
/***********************************************************************/

/***********************************************************************/
STATUS usrCciLoadProvider( const CCIProviderLoadProc providerLoadProc,
											cci_bool useDefaultSoftware )
{
	cci_st cci_status;

	CCI_NATIVE_ALGORITHM( CCI_CIPHER_AES );
	CCI_NATIVE_ALGORITHM( CCI_CIPHER_AESKW );
	CCI_NATIVE_ALGORITHM( CCI_CIPHER_DES );
    CCI_NATIVE_ALGORITHM( CCI_CIPHER_DESX );
	CCI_NATIVE_ALGORITHM( CCI_CIPHER_3DES );
	CCI_NATIVE_ALGORITHM( CCI_CIPHER_RC4 );
	CCI_NATIVE_ALGORITHM( CCI_CIPHER_RC4TKIP );
	CCI_NATIVE_ALGORITHM( CCI_CIPHER_NULL );
	CCI_NATIVE_ALGORITHM( CCI_RNG_SEED );
	CCI_NATIVE_ALGORITHM( CCI_RNG_GENERIC );
	CCI_NATIVE_ALGORITHM( CCI_HASH_CRC32 );
	CCI_NATIVE_ALGORITHM( CCI_HASH_MD2 );
	CCI_NATIVE_ALGORITHM( CCI_HASH_MD4 );
	CCI_NATIVE_ALGORITHM( CCI_HASH_MD5 );	
	CCI_NATIVE_ALGORITHM( CCI_HASH_SHA1 );
	CCI_NATIVE_ALGORITHM( CCI_HASH_SHA256 );
	CCI_NATIVE_ALGORITHM( CCI_HASH_SHA384 );
	CCI_NATIVE_ALGORITHM( CCI_HASH_SHA512 );
	CCI_NATIVE_ALGORITHM( CCI_HASH_RIPEMD160 );
	CCI_NATIVE_ALGORITHM( CCI_HASH_RIPEMD128 );
	CCI_NATIVE_ALGORITHM( CCI_HMAC_MD4 );
	CCI_NATIVE_ALGORITHM( CCI_HMAC_MD5 );
	CCI_NATIVE_ALGORITHM( CCI_HMAC_SHA1 );
	CCI_NATIVE_ALGORITHM( CCI_HMAC_SHA256 );
	CCI_NATIVE_ALGORITHM( CCI_HMAC_SHA384 );
	CCI_NATIVE_ALGORITHM( CCI_HMAC_SHA512 );
	CCI_NATIVE_ALGORITHM( CCI_HMAC_RIPEMD160 );
	CCI_NATIVE_ALGORITHM( CCI_HMAC_RIPEMD128 );
	CCI_NATIVE_ALGORITHM( CCI_HMAC_AES_XCBC );
	CCI_NATIVE_ALGORITHM( CCI_INTEGER );
	CCI_NATIVE_ALGORITHM( CCI_PUBLICKEY_RSA );

/*
** --- If the default provider wasn't selected make sure the 
**     integer and RSA algorithms are linked in
*/
	CCI_NATIVE_ALGORITHM( CCI_INTEGER );
	CCI_NATIVE_ALGORITHM( CCI_PUBLICKEY_RSA );

    /*
    ** --- Load hardware provider module. By default, the software is always
    **     loaded by cciLibInit();
    */
	cci_status = cciProviderLoad( providerLoadProc, &CCI_APP_PROVIDER_ID );
	if ( !CCISUCCESS( cci_status )) return (ERROR);

	if ( useDefaultSoftware )
		cciProviderInherit( CCI_APP_PROVIDER_ID );

	return(OK);
}
/***********************************************************************/

/***********************************************************************/
STATUS usrCciInit (void)
{
	cci_st cci_status;			 

	cci_status = cciLibInit();
	if ( !CCISUCCESS( cci_status )) 
		return (ERROR);

	return(OK);
}
/***********************************************************************/
int numargs(char **args, int count)
{
   int numargs = 0, idx;
   char *ptr;

   for(idx = 0; idx < count; idx++ )
   {
		ptr = args[idx];
		if( ptr && *ptr )
			numargs++;
   }

   return( numargs );
}
#define TEST_STACKSIZE 100*1024 
#define NUM_ARGS	11
void testhash(void);

extern void *cci_ActualSdOpen(char *name, BOOL create, UINT32 size, void ** pVirtAddress);
extern void cci_ActualSdUnmapDelete(void * pShareRegionID);



void main(void)
{
	/*printf("hello...\n");*//* LEVANCIO S10 comment delete R.Miura 2016/02/03 */
	
	cciSharedMemFunctions(cci_ActualSdOpen, cci_ActualSdUnmapDelete, NULL);	
	cciSharedRegionSet( 409600 );
	cciLibInit();
	
	usrCciInit();
	usrCciLoadProvider( CCI_DEFAULT_PROVIDER, 0 );
	
 
#if 0
    CRYPTO_set_mem_functions(sslMemoryAllocate,sslMemoryRealloc, sslMemoryFree);  

    sslMultiThreadInit();      /* setup multithreading callbacks for locking functions */
    RAND_set_rand_method(RAND_CCI()); /* setup security library to use CCI for random numbers */
#endif

	 /*printf("Float value = %1.2f\n", (double)343.2/(double)133.3);*//* LEVANCIO S10 comment delete R.Miura 2016/02/03 */

 	/* openssl("s_server"); */
#if 0
	openssl_test();
#endif	 
	/* cciProviderValidate(0); */ 
	 /* openssl_test(); */    
	/* openssl(); */
	wrSSLTestClientConnectTestAll("192.168.200.1","4433","192.168.200.1","4434",4,30);
	 /* handleTestSsl(); */  
	/* testhash(); */ 
     
}

void testhash(void)
{
	cci_b input[]="this is a test message";
	cci_b digestBuffer[256];
	cci_t digestLength=256;
	cci_st result;
/*	
cci_st	cciHashBlock( const CCI_PROVIDER_ID providerId, const CCI_ALGORITHM_ID algorithmId, 
								const cci_b *input, const cci_t inputLength, 
								cci_b *digest, cci_t *digestLength );


 */
	
	result =cciHashBlock( (CCI_PROVIDER_ID) 0, ( CCI_ALGORITHM_ID ) CCI_HASH_MD2, (cci_b *) input, (const cci_t)  strlen((char *) input), (cci_b *) digestBuffer, &digestLength );
	
	/*printf("test hash digestLength %d\n",digestLength);*//* LEVANCIO S10 comment delete R.Miura 2016/02/03 */

}
