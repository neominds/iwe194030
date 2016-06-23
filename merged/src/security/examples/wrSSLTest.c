
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <tickLib.h>
#include <sysLib.h>
#include <taskLib.h>

#define TASK_SP
#include <usrLib.h>

/* #define SSL_IPV6 */

#ifdef SSL_IPV6
#include "sockLib.h"
#include "in.h"
#include <netinet/tcp.h>
#endif


#define int_error(msg) handle_error(__FILE__,__LINE__,msg)

#define MAX_BUF_SIZE 1024*16



char *sslv3_dsa_ciphers[] ={
						"DHE-DSS-AES256-SHA",
					    "EDH-DSS-DES-CBC3-SHA",
						"DHE-DSS-AES128-SHA",
						"DHE-DSS-RC4-SHA",
						"EXP1024-DHE-DSS-DES-CBC-SHA",
					    "EDH-DSS-DES-CBC-SHA",
					    "EXP1024-DHE-DSS-RC4-SHA",
					    "EXP-EDH-DSS-DES-CBC-SHA",
					    NULL
						};

char *sslv2_rsa_ciphers[] ={
						"RC4-MD5",
					    "RC4-64-MD5",
					    "DES-CBC3-MD5",
					    "DES-CBC-MD5",
					    NULL
						};

char *sslv3_rsa_ciphers[] = {
						"AES256-SHA",
						"DHE-RSA-AES256-SHA",
					    "EDH-RSA-DES-CBC3-SHA",
					    "DES-CBC3-SHA",
					    "DHE-RSA-AES128-SHA",
					    "AES128-SHA",
					    "RC4-SHA",
					    "RC4-MD5",
					    "EXP1024-DES-CBC-SHA",
					    "EDH-RSA-DES-CBC-SHA",
					    "DES-CBC-SHA",
					    "EXP1024-RC4-SHA",
					    "EXP1024-RC4-MD5",
					    "EXP-EDH-RSA-DES-CBC-SHA",
					    "EXP-DES-CBC-SHA",
					    "EXP-RC4-MD5",
						NULL
					    };


static unsigned char dh512_p[]={
	0xDA,0x58,0x3C,0x16,0xD9,0x85,0x22,0x89,0xD0,0xE4,0xAF,0x75,
	0x6F,0x4C,0xCA,0x92,0xDD,0x4B,0xE5,0x33,0xB8,0x04,0xFB,0x0F,
	0xED,0x94,0xEF,0x9C,0x8A,0x44,0x03,0xED,0x57,0x46,0x50,0xD3,
	0x69,0x99,0xDB,0x29,0xD7,0x76,0x27,0x6B,0xA2,0xD3,0xD4,0x12,
	0xE2,0x18,0xF4,0xDD,0x1E,0x08,0x4C,0xF6,0xD8,0x00,0x3E,0x7C,
	0x47,0x74,0xE8,0x33,
	};
static unsigned char dh512_g[]={
	0x02,
	};

int connectedClients=0;


/* POST_CONNECT_TEST defines what the client should do once it has connected the server */
enum postConnectTest { CONNECT_TEST,  /* connects to server and has it print out cipher suite */
			   CONNECT_TEST_QUIET, /* connects to server with no output */
			   CONNECT_TEST_THRUPUT_TWOWAY, /* attempts to measure thruput using variable buffers, no message checking */
			   CONNECT_TEST_THRUPUT,  /* attempt to measure thruput using variable buffer size, blasting in one direction */
			   CONNECT_TEST_RENEGOTIATE, /* connects to server and renegotiates connection */
			   CONNECT_TEST_SERVER_EXIT, /* connects to server and sends SSL_TEST_EXIT */ 
			   MAX_TESTS};
			   
typedef enum postConnectTest POST_CONNECT_TEST;


enum serverRetCode { SERVER_EXIT, 
					 SERVER_TEST_FAILED,
					 SERVER_TEST_PASSED
					};
typedef enum serverRetCode SERVER_RET_CODE;					

/* enum sslTestMsg is protocol of the messages sent from the client to the server.  Messages must be
 * at least 2 bytes.  msg[0] is enum sslTestMsg, msg[1] is an optional parameter to msg[0] */					
enum sslTestMsg {SSL_TEST_EXIT, /* server to exit */
				SSL_TEST_CONNECT,			/* if byte[1] == 0x01 will print cipher suite */
				SSL_TEST_DISCONNECT,	   /* server immediately disconnects with no output */
				SSL_TEST_SET_WRITE_SIZE,   /* server updates writeBufLen and stays connected */
				SSL_TEST_RX_AND_SEND_BACK, /* server receives data and then sends back */
				SSL_TEST_RX_AND_MEASURE	  /* server receives data and reports thruput 
											 byte[1] == 0x01 start test
											 byte[1] == 0x02  finish test
											*/
				};
typedef enum sslTestMsg SSL_TEST_MSG;

/* SSL_TEST_CTX is used to describe a particular Test session.  It can be passed to sslTestServer() and
 * sslTestClient().  It is used to configure an SSL connection, and to run SSL_TEST (client side).
 * 
 * 
 */
typedef struct {
			SSL_METHOD *method;		/* Protocol to use */
			char port[5];				/* port to bind to (server), or connect to (client) */
			char serverIp[20];			/* address to connect to (client), n/a (server). */
			char *certFname;		/* address of certificate to send to remote side (client/server). */
			char *ciphers;			/* restrict connection to these ciphers (client/server). */
			int  requireClientCert; /* require a client certificate or fail (server), send client certificate - certFname (client) */
			int  outputMsgInfo;		/* print SSL Msgs (client/server). */
			int	 outputStateInfo;   /* print SSL state info (client/server). */
			BIO *bioResult;			/* BIO to print test output on (client/server) */
			POST_CONNECT_TEST test;	/* Test to run after the SSL connection is made (client), n/a (server) */
			int testOption;  /* optional parameter to test */
			int writeBufLen;		/* maximum size of data to write into an SSL Record (client), n/a (server) */
			} SSL_TEST_CTX;
			
			




SERVER_RET_CODE sslServerWorkerTask(SSL *ssl, SSL_TEST_CTX *config, char *serverBuf);
int verify_callback(int ok, X509_STORE_CTX *store);
int sslTestServer(SSL_TEST_CTX *config);
int sslTestClient(SSL_TEST_CTX *config);
int sslTestReadMsg(SSL *ssl,void *buf, int maxbuf);
int sslTestWriteMsg(SSL *ssl,void *buf, int len);
int sendSetWriteSize(SSL *ssl, int size);
int wrSSLTestClientConnectPerformanceTestAll(char *rsaServerIp, char *rsaPort,char *dsaServerIp,char *dsaPort,int time);
int wrSSLTestClientConnectTestAll(char *rsaServerIp, char *rsaPort,char *dsaServerIp,char *dsaPort,int postConnectTest,int testOption, BIO *output);
int wrSSLTestServerClose(char *serverIp, char *port);
void wrSSLTestServer(int dsacert, char *port);

/* EXTERNS */

void msg_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
void apps_ssl_info_callback(const SSL *s, int where, int ret);
void msg_cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
extern BIO *bio_err;


/* DEFINES */

#define CERTFILE "server.pem"
#define CLIENT_CERTFILE "client.pem"
#define PORT "4433"
#define SERVER "192.168.200.1"
#define TEST_PRIORITY 100
#define TEST_STACKSIZE 100*1024

/* globals */

static const char rnd_seed[] = "string to make the random number generator think it has entropy";


/*
 * get_dh512()
 * 
 * Used to get default DH parameters 
 * 
 */
static DH *get_dh512(void)
	{
	DH *dh=NULL;

	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
	dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		return(NULL);
	return(dh);
	}

/******************************************************************************
 * sslAppsInit()
 * - do nothing function to fake linker into pulling in this file
 * 
 ******************************************************************************/
void sslAppsInit()
{

}
/*******************************************************************************
 * handle_error()
 * prints OpenSSL Errs
 *******************************************************************************/ 
void handle_error(const char *file,int lineno,const char *msg)
{
	fprintf(stderr, "** %s:%i %s\n",file,lineno,msg);
	ERR_print_errors_fp(stderr);
}

/*******************************************************************************
 * 
 * setup_server_ctx()
 *
 * called by server to create the SSL_CTX used to create the server.
 * Sets the server to work with TLS1/SSLV2/SSLV3.  Loads certificate and the private
 * key from CERTFILE 
 *
 *******************************************************************************/ 
SSL_CTX *setup_server_ctx()
{
	SSL_CTX *ctx;
	ctx = SSL_CTX_new(SSLv23_server_method());
	if(ctx ==NULL)
		{
		int_error("unable to create SSL_CTX\n");
		exit(-1);
		}
	if(SSL_CTX_use_certificate_chain_file(ctx,CERTFILE)!=1)
		int_error("Error loading certificate from file");
	if(SSL_CTX_use_PrivateKey_file(ctx,CERTFILE,SSL_FILETYPE_PEM)!=1)
		int_error("Error loading private key from file");
		
	return ctx;
}
/*******************************************************************************
 * sslServerWorkerTask()
 * 
 * This function is called after a SSL connection is up.  It processes to 
 * SSL_TEST commands from the client.  The server does not send any unsolicited
 * messages to the client.
 * 
 ********************************************************************************/ 
SERVER_RET_CODE sslServerWorkerTask(SSL *ssl, SSL_TEST_CTX *config, char *serverBuf)
{
	int err;
	char breakLoop=0;
	int timer=0;
	int byteCounter=0;
	int numReads;
	SERVER_RET_CODE ret = SERVER_TEST_PASSED;
	
	
	if(SSL_accept(ssl) <=0)
	{
		int_error("Error accepting SSL connection");
		ret = SERVER_TEST_FAILED;
	}
	else
	{
		 
	    while(!breakLoop)
	    {
	     if((err = sslTestReadMsg(ssl,serverBuf,MAX_BUF_SIZE)) >0) /* received a msg */
	     {
			switch(serverBuf[0]) /* first byte is the cmd */ 
			{
				case SSL_TEST_CONNECT:
					if(serverBuf[1] == 1)  /* print cipher suite */ 
						BIO_printf(config->bioResult,"CONNECTION_TEST (server): %s \n",SSL_get_current_cipher(ssl)->name);
					break;
				case SSL_TEST_SET_WRITE_SIZE:
					config->writeBufLen = ((serverBuf[1]&0xff)<<24) 
											+ ((serverBuf[2]&0xff)<<16) 
											+ ((serverBuf[3]&0xff)<<8)
											+(serverBuf[4] & 0xff);
					
					break;
				case SSL_TEST_EXIT:
					BIO_printf(config->bioResult,"Server on port %s exiting\n",config->port);
					breakLoop=1;
					ret = SERVER_EXIT;
					break;
				case SSL_TEST_RX_AND_SEND_BACK:
					sslTestWriteMsg(ssl,serverBuf,err);
					break;
				case SSL_TEST_RX_AND_MEASURE:
					if(serverBuf[1] == 1)
					{
						byteCounter =err;
						numReads=0;
						timer= tickGet();
					}
					else
					{
						byteCounter+=err;
						numReads++;
					
					}
					if(serverBuf[1] == 2)
					{
					  BIO_printf(config->bioResult,"Thruput for %s is %d B/s with bufsize %d, SSL_reads/s %d\n",SSL_get_current_cipher(ssl)->name,byteCounter*sysClkRateGet()/(tickGet()-timer),config->writeBufLen,numReads*sysClkRateGet()/(tickGet()-timer));
					}
					break;
				default:
					BIO_printf(config->bioResult,"rx unknown message %x %x, length %d ",serverBuf[0],serverBuf[1],err);
					breakLoop=1;
					break;
			}
		  }
		  else
		  {
			breakLoop =1;
		  }
	    }
	    
	}
	SSL_shutdown(ssl);
	
	SSL_free(ssl);
	connectedClients--;
	return ret;
}
/******************************************************************************
 * 
 * sslTestReadMsg()
 * 
 *  Does one SSL_read, up to len bytes 
 *  Returns 0 if connection is being closed 
 *******************************************************************************/
int sslTestReadMsg(SSL *ssl, void *buf, int len)
{
	int err;
	int sslerr;
	int breakloop=0;
	while(!breakloop)
	{
		err	= SSL_read(ssl, buf, len);
		if(err <=0)
		{		
			sslerr = SSL_get_error(ssl,err);
			switch(sslerr)  /* an error might mean just retry the read */
			{
				case SSL_ERROR_NONE:
					break;
				case SSL_ERROR_ZERO_RETURN:
					return(0);
					break;
				case SSL_ERROR_WANT_READ:
					printf("SSL_ERROR_WANT_READ\n");
					break;
				case SSL_ERROR_WANT_WRITE:
					printf("SSL_ERROR_WANT_WRITE\n");
					break;
				default:
					SSL_shutdown(ssl);
					breakloop=1;  /* causes while to terminate and return 0 */ 
					break;
					
			}
		}
		else
		{
			return err; /* num bytes read */
		}
	}
	return 0;
}

/******************************************************************************
 * 
 * sslTestWriteMsg - attempts to call SSL_write 
 * 
 *  returns 1 on success, 0 if ssl connection has gone down
 ******************************************************************************/
int sslTestWriteMsg(SSL *ssl, void *buf, int buflen)
{
	int err;
	int sslerr;
	int breakloop=0;

	while(!breakloop)
	{
		err	= SSL_write(ssl, buf, buflen);
		
		if(err <=0)
			{
			sslerr = SSL_get_error(ssl,err);
			switch(sslerr)  /* an error might mean just retry the write */
				{
				case SSL_ERROR_NONE:
					break;
				case SSL_ERROR_ZERO_RETURN:
					printf("SSL Connection is being closed\n");
					return(0);
				case SSL_ERROR_WANT_READ:
					printf("SSL_ERROR_WANT_READ\n");
					break;
				case SSL_ERROR_WANT_WRITE:
					printf("SSL_ERROR_WANT_WRITE\n");
					break;
				default:
					SSL_shutdown(ssl);
					breakloop=1;
					break;
				}
			}
		else
			return err;
	}
	return 0;
}

/******************************************************************************
 * sslTestServer(SSL_TEST_CTX *config)
 * This function implements an sslTestServer according to the settings in config
 * This server only handles one connection (client) at a time.
 * It does not return unless the client tells the server to exit. 
 * 
 *****************************************************************************/ 
int sslTestServer(SSL_TEST_CTX *config)
{
	
	BIO *acc,*client;
	SSL *ssl;
	SSL_CTX *ctx;
	int ret=1;
	DH *dh=NULL;
	char *serverBuf=NULL;
	static int init=0;

#ifdef SSL_IPV6
	struct sockaddr_in6	sin6, from6;
	int f, s,len;
#endif
	
	if(!init)
	{
		OpenSSL_add_all_algorithms(); 
		ERR_load_crypto_strings();
		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();
		RAND_seed(rnd_seed, sizeof rnd_seed);
		init=1;
	}
	ctx = SSL_CTX_new(config->method);
	
	if(ctx ==NULL)
		{
		int_error("unable to create SSL_CTX\n");
		ret = -1;
		goto err;
		}
	if(SSL_CTX_use_certificate_chain_file(ctx,config->certFname)!=1)
		{
		int_error("Error loading certificate from file");
		ret =-1;
		goto err1;
		}
	if(SSL_CTX_use_PrivateKey_file(ctx,config->certFname,SSL_FILETYPE_PEM)!=1)
		{
		int_error("Error loading private key from file");
		ret =-1;
		goto err1;
		}
	if(SSL_CTX_set_cipher_list(ctx, config->ciphers) != 1)
		{
		int_error("Error setting cipher list (no valid ciphers)");
		ret=-1;
		goto err1;
		}
		
    if(config->requireClientCert)
    {
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
	SSL_CTX_set_verify_depth(ctx,4);
    }
    
    SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY | SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_OFF);
    
	dh=get_dh512();
	SSL_CTX_set_tmp_dh(ctx,dh);
	DH_free(dh);
		
			
	if(config->outputMsgInfo)
	{
		bio_err = config->bioResult; /* hack so that can use apps_ssl_info_callback */
		
		if(config->outputMsgInfo)
			SSL_CTX_set_info_callback(ctx,apps_ssl_info_callback);
	}
		
		
#ifdef SSL_IPV6
	bzero ((char *) &sin6, sizeof (sin6));
	bzero ((char *) &from6, sizeof (from6));
	
	f = socket (AF_INET6, SOCK_STREAM, 0);
		
	if (f < 0)
	{
	printf ("cannot open IPV6 socket\n");
	ret=-1;
	goto err;
	}
		
	sin6.sin6_len = sizeof(sin6);
	sin6.sin6_family	= AF_INET6;
	sin6.sin6_port	= htons (atoi(config->port));
	
	if (bind (f, (struct sockaddr*)&sin6, sizeof (sin6)) < 0)
	{
		printf ("IPV6 bind error\n");
		ret=-1;
		goto err;
	}
	if (listen (f, 5) < 0)
	{
		printf ("IPV6 listen failed\n");
		ret=-1;
		goto err;
	}
#else
	acc = BIO_new_accept(config->port);
		
	if(!acc)
		{
		int_error("Error creating server socket");
		ret =-1;
		goto err1;
		}
	
	if(BIO_do_accept(acc) <=0)
		{
		int_error("Error binding socket server");
		ret = -1;
		goto err2;
		}
#endif	
	serverBuf = malloc(sizeof(char) * MAX_BUF_SIZE);
	if(!serverBuf)
	{
		printf("malloc failed\n");
		goto err2;
	}
	for(;;)
	{
		int acc_temp;
		int break_loop=0;
		
		while(!break_loop){
#ifdef SSL_IPV6
		len = sizeof (from6);
	
		if((s = accept (f, (struct sockaddr*)&from6, &len))  == -1)
		{
			printf("accept returns -1\n");
			ret=1;
			goto err;
		}
#else			
			acc_temp = BIO_do_accept(acc);
			if(acc_temp>0)
				break_loop=1;
			
			else
			{
				ret =-1;
				int_error("Error accepting connection");
				goto err2;
			}
#endif	
		if(!(ssl = SSL_new(ctx)))
			{
			ret =-1;
			int_error("Error creating SSL context");
			goto err2;
			}
		if(config->outputStateInfo)
		{
			SSL_set_msg_callback(ssl, msg_cb);
			SSL_set_msg_callback_arg(ssl, config->bioResult);
		}
#ifdef SSL_IPV6
		client = BIO_new_socket(s,1);
#else
		client = BIO_pop(acc);
#endif			
		SSL_set_bio(ssl,client,client);
	    connectedClients++;
#ifndef TASK_SP		
		if(sslServerWorkerTask(ssl,config,serverBuf)== SERVER_EXIT) /* when this returns, the ssl conneciton is closed */
			{
			printf("exiting server\n");
			goto err2;
			}
#else
/*	    sp(sslServerWorkerTask,(int) ssl, (int) config, (int)serverBuf,0,0,0,0,0,0); */
		taskSpawn("server_t",100,0,20000,sslServerWorkerTask,(int) ssl, (int) config, (int)serverBuf,0,0,0,0,0,0,0);
#endif
	  
		} /* end while */
	} /* end for */
err2:	
#ifndef SSL_IPV6
	BIO_set_close(acc, BIO_CLOSE);
	BIO_free(acc);
#endif	

err1:
	SSL_CTX_free(ctx);
	
err:
	if(serverBuf)
		free(serverBuf);

	free(config);
	ERR_remove_state(0);
	return ret;
}

/******************************************************************************
 * sslTestClient(SSL_TEST_CTX *config)
 * This function implements a sslTestClient according to the settings in config
 * See declaration for SSL_TEST_CTX above.  sslTestClient connects
 * to the server defined in config and executes the post connection test
 * defined in config.
 * 
 * Returns 1 for success, 0 for failure.  
 * 
 *****************************************************************************/ 
int sslTestClient(SSL_TEST_CTX *config)
{

	SSL_CTX *ctx=NULL;
	BIO *conn;
	SSL *ssl;
	int ret=1;
	int i;
	int err;
	char connect_string[128];
	char *client_buffer=NULL;
	int numWrites =0;
	static int init=0;

#ifdef SSL_IPV6
	int		port;
	struct sockaddr_in6	sin6;
	int s;
#endif

	int timeout;  
	
	if(!init)
	{
		OpenSSL_add_all_algorithms(); 
		ERR_load_crypto_strings();
		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();
		RAND_seed(rnd_seed, sizeof rnd_seed);
		init=1;
	}

	client_buffer= malloc(sizeof(char) * MAX_BUF_SIZE);
	if(!client_buffer)
	{
		printf("malloc failed\n");
		goto err;
	}
	
	ctx = SSL_CTX_new(config->method);
	if(ctx ==NULL)
		{
		int_error("unable to create SSL_CTX\n");
		ret =0;
		goto err;
		}
		
	if(SSL_CTX_set_cipher_list(ctx, config->ciphers) != 1)
		{ 
		int_error("Error setting cipher list (no valid ciphers)");
		ret =0;
		goto err;
		}

	
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
	SSL_CTX_set_verify_depth(ctx,4); 
	SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_OFF);
	SSL_CTX_set_options(ctx,SSL_OP_ALL);
		
		
		
		
    if(	config->requireClientCert)
    {
		if(SSL_CTX_use_certificate_chain_file(ctx,config->certFname)!=1)
			{
			int_error("Error loading certificate from file");
			ret =0;
			goto err;
			}
		if(SSL_CTX_use_PrivateKey_file(ctx,config->certFname,SSL_FILETYPE_PEM)!=1)
			{
			int_error("Error loading private key from file");
			ret =0;
			goto err;
			}		
    }
    
				
	if(config->outputMsgInfo)
	{
		bio_err = config->bioResult; /* hack so that can use apps_ssl_info_callback */
		
		if(config->outputMsgInfo)
			SSL_CTX_set_info_callback(ctx,apps_ssl_info_callback);
	}
	sprintf(connect_string,"%s:%s",config->serverIp,config->port);

#ifdef SSL_IPV6
	s = socket (AF_INET6, SOCK_STREAM, 0);
	if (s < 0) {
		printf ("cannot open IPV6 socket\n");
		ret=0;
		goto err;
	}

	port = atoi(config->port);
	bzero ((char *) &sin6, sizeof (sin6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family 	= AF_INET6;
	sin6.sin6_port	= htons (port);	
	
	inet_pton(AF_INET6,config->serverIp,(void *)&sin6.sin6_addr);
	if (connect (s, (struct sockaddr*) &sin6, sizeof (sin6)) < 0)
		{
			printf ("IPV6 connect failed:  port %d\n", ntohs (sin6.sin6_port));
			close (s);
			ret=0;
			goto err;
		}
    conn = BIO_new_socket(s,1);
    

#else	 
	conn = BIO_new_connect(connect_string);
	
	if(!conn)
	{
		int_error("Error creating connection BIO");
		ret =0;
		goto err;
	}
		
	if(BIO_do_connect(conn) <=0)
	{
		int_error("Error conecting to remote machine");
		BIO_free(conn);
		ret =0;
		goto err;
	}
#endif	
	if(!(ssl = SSL_new(ctx)))
	{
		int_error("Error creating an SSL context");
		BIO_free(conn);
		ret =0;
		goto err;
	}
	
	
	
	SSL_set_bio(ssl,conn,conn);
	
	if(SSL_connect(ssl) <=0)
	{
		int_error("Error connecting SSL object");
		ret =0;
		
	}
	else
	{
		switch(config->test)
		{
			case CONNECT_TEST_SERVER_EXIT:
				BIO_printf(config->bioResult,"sending SSL_TEST_EXIT\n");
				client_buffer[0] = SSL_TEST_EXIT;
				client_buffer[1] = 0;
				sslTestWriteMsg(ssl,client_buffer,2);
				ret=1;
				break;
			case CONNECT_TEST_RENEGOTIATE:
				timeout = tickGet() + config->testOption *sysClkRateGet();
				i=0;
				while(tickGet() < timeout)
				 { 
				   i++;
				   SSL_renegotiate(ssl);
				   if((err=SSL_do_handshake(ssl))<=0)
				   {
					BIO_printf(config->bioResult,"SSL_do_handshake returns %d on i %d\n",err,i);
					BIO_printf(config->bioResult,"SSL_get_error(ssl,err) %d\n",SSL_get_error(ssl,err));
					BIO_printf(config->bioResult,"ERROR String %s\n",ERR_error_string(ERR_get_error(),NULL));
					ret=0;
					break;
					}
				 }
				BIO_printf(config->bioResult,"%s: %d renegotiations/second (%d renegotiations in %d seconds\n",SSL_get_current_cipher(ssl)->name,i/config->testOption,i,config->testOption);
				
				 break;
			case CONNECT_TEST:
			    client_buffer[0] = SSL_TEST_CONNECT;
			    client_buffer[1] = 1;
				sslTestWriteMsg(ssl,client_buffer,2);
				break;
			case CONNECT_TEST_QUIET:
			
				client_buffer[0] = SSL_TEST_CONNECT;
			    client_buffer[1] = 0;
			    sslTestWriteMsg(ssl,client_buffer,2);
			    
				break;
			case CONNECT_TEST_THRUPUT_TWOWAY:
				for(config->writeBufLen = 1;config->writeBufLen <=MAX_BUF_SIZE;config->writeBufLen = config->writeBufLen<<1)
				{
					if(config->writeBufLen == MAX_BUF_SIZE)
						config->writeBufLen = MAX_BUF_SIZE-512;
						
					sendSetWriteSize(ssl,config->writeBufLen);
					memset(client_buffer,0xA5,config->writeBufLen);
					client_buffer[0] = SSL_TEST_RX_AND_SEND_BACK;
					timeout = tickGet() + config->testOption *sysClkRateGet();
					i=0;
					numWrites=0;
					while(tickGet()<=timeout)
					{
						sslTestWriteMsg(ssl,client_buffer,config->writeBufLen);
						if((err = sslTestReadMsg(ssl,client_buffer,MAX_BUF_SIZE))==0)
						{
							ret =0;
							printf("sslTestReadMsg failed\n");
							goto err2;
						
						}
						if(err != config->writeBufLen)
							printf("didn't tx expected num bytes got %d\n",err);
							
						i+=err;
						numWrites++;
					 }
					 printf("Thruput for %s is %d B/s with bufsize %d, SSL_writes/s %d\n",SSL_get_current_cipher(ssl)->name,i/config->testOption,config->writeBufLen,numWrites/config->testOption);
					 if(MAX_BUF_SIZE-512 == config->writeBufLen)
						break;
					} 	
				 break;
			case CONNECT_TEST_THRUPUT:
				for(config->writeBufLen = 2;config->writeBufLen <=MAX_BUF_SIZE;config->writeBufLen = config->writeBufLen<<1)
				{
					if(config->writeBufLen == MAX_BUF_SIZE)
						config->writeBufLen = MAX_BUF_SIZE-512;
						
					sendSetWriteSize(ssl,config->writeBufLen);
					memset(client_buffer,0xA5,config->writeBufLen);
					client_buffer[0] = SSL_TEST_RX_AND_MEASURE;
					client_buffer[1] = 1;
					timeout = tickGet() + config->testOption *sysClkRateGet();
					i=0;
					numWrites=0;
					while(tickGet()<=timeout)
					{
						
						if((err = sslTestWriteMsg(ssl,client_buffer,config->writeBufLen))==0)
						{
							ret =0;
							printf("sslTestWriteMsg failed\n");
							break;
						
						}
						if(err != config->writeBufLen)
							printf("didn't tx expected num bytes %d\n",err);
							
						i+=err;
						numWrites++;
						client_buffer[1] = 0; /* clear this byte, only needs to be sent to start/stop timer on server */
					 }
					client_buffer[1] = 2; /* tell server test is done */
					i+=sslTestWriteMsg(ssl,client_buffer,config->writeBufLen);
					numWrites++;
					 printf("Thruput for %s is %d B/s with bufsize %d, SSL_writes/s %d\n",SSL_get_current_cipher(ssl)->name,i/config->testOption,config->writeBufLen,numWrites/config->testOption);
					 if(MAX_BUF_SIZE-512 == config->writeBufLen)
						break;
					}
				 break;			
			
			
			
							 
			default:
				int_error("Unknown test to run\n");
				break;
		
		}
	}
err2:
	if(!SSL_shutdown(ssl))
		SSL_shutdown(ssl);

	SSL_free(ssl); /* this frees conn as well*/
	
err:
	if(ctx)
		SSL_CTX_free(ctx);
		 
	if(client_buffer)
		free(client_buffer);
		
	ERR_remove_state(0);		
		
	return ret;
}
	
	


int sendSetWriteSize(SSL *ssl, int size)
{
	char buf[5];

	buf[0] = SSL_TEST_SET_WRITE_SIZE;
	buf[1] = (size>>24) & 0xff;
	buf[2] = (size >> 16)  & 0xff;
	buf[3] = (size >> 8)  & 0xff;
	buf[4] = size & 0xff;  
			
	sslTestWriteMsg(ssl,buf,5);
	return size;
				
}



/*******************************************************************
 * 
 * void wrSSLTestServer(int dsacert, char *port)
 * 
 * This function creates a new SSL server task
 * 
 * dsacert - set to 1 if the server is to use dsacert.pem, 0 if it is to use server.pem
 * port - port number to bind too (string) 
 * 
 *******************************************************************/
void wrSSLTestServer(int dsacert, char *port)
{
	SSL_TEST_CTX *server1;
		
	server1 = malloc(sizeof(SSL_TEST_CTX)); /* freed by sslTestServer */
	
	bzero((char *) server1,sizeof(SSL_TEST_CTX));
		
	server1->method= SSLv23_server_method();
	strcpy(server1->port,port);
	if(dsacert)
		server1->certFname = "dsacert.pem";
	else
		server1->certFname = "server.pem";
	
	server1->requireClientCert = 0;
	server1->ciphers = "ALL";
	server1->outputMsgInfo =0;
	server1->outputStateInfo =0;
	
	server1->bioResult =BIO_new_fp(stdout,BIO_NOCLOSE);  
#ifdef TASK_SP
	sp(sslTestServer,(int) server1,0,0,0,0,0,0,0,0);
#endif
}
/*******************************************************************
 * int wrSSLTestServerClose(int dsacert, char *serverIp, char *port)
 * 
 * This function attempts to connect to the server and send the SSL_TEST_EXIT
 * command to cause the server to close the accept socket.
 * 
 * serverIp - IP address of server
 * port		- port number of server
 * 
 * returns 1 if success, 0 if failure
 *******************************************************************/
int wrSSLTestServerClose(char *serverIp, char *port)
{
	int ret =0;
	SSL_TEST_CTX *config;
	
	config = (SSL_TEST_CTX *) malloc(sizeof(SSL_TEST_CTX));
	
	bzero((char *) config,sizeof(SSL_TEST_CTX));
	
	config->method= SSLv23_client_method();
	strcpy(config->serverIp,serverIp);
	strcpy(config->port,port);

	config->requireClientCert = 0;
	config->ciphers ="ALL";
	
		
	config->outputMsgInfo = 0;
	config->outputStateInfo =0;
	config->test = CONNECT_TEST_SERVER_EXIT;
	config->bioResult = BIO_new_fp(stdout,BIO_NOCLOSE);
	  
	ret = sslTestClient(config);
	
	BIO_free(config->bioResult);
	return ret;
}

/*******************************************************************
 * int wrSSLTestClientConnectTestAll(char *rsaServerIp, char *rsaPort,char *dsaServerIp,char *dsaPort,int postConnectTest,int testOption, BIO *output)
 * 
 * This function attempts to connect to the server and perform the test postConnectTest.
 * All ciphers will be attempted sequentially.
 * 
 * rsaServerIp - IP address of server using a RSA certificate
 * rsaPort	   - port of server using a RSA certificate
 * dsaServerIp - IP address of server using a DSA certificate
 * dsaPort	   - port of server using a DSA certificate
 * postConnectTest - POST_CONNECT_TEST, defines what test client is to do after connected
 * testOption	- optional parameter to postConnectTest
 * output		- output log bio, NULL stdio is used
 * 
 * returns 1 if success, 0 if failure
 *******************************************************************/
int wrSSLTestClientConnectTestAll(char *rsaServerIp, char *rsaPort,char *dsaServerIp,char *dsaPort,int postConnectTest,int testOption, BIO *output)
{
	SSL_TEST_CTX config;
	int i;
	int ret=1;
	
	
	bzero((char *) &config,sizeof(SSL_TEST_CTX));

	if(!output)
	{
		config.bioResult = BIO_new_fp( stdout,BIO_NOCLOSE);  
	}
	else
	{
		config.bioResult = output;
	}
	if(!config.bioResult)
		printf("bad bio\n");
	
	BIO_printf(config.bioResult,"wrSSLTestClientConnectTestAll");
	
	
	if(rsaServerIp == NULL || rsaPort==NULL || dsaServerIp==NULL || dsaPort==NULL)
	{
		BIO_printf(config.bioResult,"bad parameter IP or Port parameter");
		BIO_free(config.bioResult);
		return 0;
	}
	
	config.method= SSLv23_client_method();
	strcpy(config.port,rsaPort);
	strcpy(config.serverIp,rsaServerIp);
	config.certFname = CERTFILE;
	config.requireClientCert = 1;
	config.outputMsgInfo = 0;
	config.outputStateInfo =0;
	config.test = postConnectTest;
	config.testOption = testOption;

	
	for(i=0;sslv3_rsa_ciphers[i] != NULL; i++)
	{
		config.ciphers = sslv3_rsa_ciphers[i];
		if(sslTestClient(&config))
		{
			BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s passed\n",config.ciphers);
		
		}
		else
		{
			BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s failed\n",config.ciphers);
			ret =0;
		}
	}
	
	
	config.method= SSLv2_client_method();
	for(i=0;sslv2_rsa_ciphers[i] != NULL; i++)
	{
		config.ciphers = sslv2_rsa_ciphers[i];
			
		if(sslTestClient(&config))
		{
			BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s passed\n",config.ciphers);
		
		}
		else
		{
			BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s failed\n",config.ciphers);
			ret =0;
		}
		
	}
	
	config.certFname = "dsacert.pem";
	strcpy(config.port,dsaPort);
	strcpy(config.serverIp,dsaServerIp); 
	config.method= SSLv23_client_method();
	for(i=0;sslv3_dsa_ciphers[i] != NULL; i++)
	{
		config.ciphers = sslv3_dsa_ciphers[i];
			
		if(sslTestClient(&config))
		{
			BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s passed\n",config.ciphers);
		
		}
		else
		{
			BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s failed\n",config.ciphers);
			ret =0;
		}
	}
  if(!output)
  {
	BIO_free(config.bioResult);
  }
  return ret;
}

/*******************************************************************
 * int wrSSLTestClientConnectPerformanceTestAll(char *rsaServerIp, char *rsaPort,char *dsaServerIp,char *dsaPort,int time)
 * 
 * This function attempts to connect/disconnect from the server as many times as possible in time seconds. 
 * 
 * rsaServerIp - IP address of server using a RSA certificate
 * rsaPort	   - port of server using a RSA certificate
 * dsaServerIp - IP address of server using a DSA certificate
 * dsaPort	   - port of server using a DSA certificate
 * time		   - time in seconds to run the test for each cipher
 * 
 * returns 1 if success, 0 if failure
 *******************************************************************/
int wrSSLTestClientConnectPerformanceTestAll(char *rsaServerIp, char *rsaPort,char *dsaServerIp,char *dsaPort,int time)
{
	SSL_TEST_CTX client;
	int numconnects=0;
	int i;
	int timeout;
	int ret =1;


	/* for each cipher, spend time connecting, and then calculate number of connections */
	
	bzero((char *) &client,sizeof(SSL_TEST_CTX));
	
	client.bioResult = BIO_new_fp( stdout,BIO_NOCLOSE);  
	if(!client.bioResult)
		printf("bad bio\n");
	
	BIO_printf(client.bioResult,"wrSSLTestClientConnectPerformanceTestAll\n");
	
	
	if(rsaServerIp == NULL || rsaPort==NULL || dsaServerIp==NULL || dsaPort==NULL)
	{
		BIO_printf(client.bioResult,"bad parameter IP or Port parameter");
		BIO_free(client.bioResult);
		return 0;
	}
	

	strcpy(client.port,rsaPort);
	strcpy(client.serverIp,rsaServerIp);
	client.certFname = NULL;
	client.requireClientCert = 0; /* set this if you want to use client authentication */
	client.outputMsgInfo = 0;
	client.outputStateInfo =0;
	client.test = CONNECT_TEST_QUIET;	

	
	BIO_printf(client.bioResult,"Testing SSLV3 ciphers\n");
	client.method= SSLv23_client_method();
	for(i=0;sslv3_rsa_ciphers[i] != NULL; i++)
	{
		
		client.ciphers = sslv3_rsa_ciphers[i];
		numconnects=0;
		BIO_printf(client.bioResult,"starting test for %s\n",client.ciphers);
		timeout = tickGet() + time *sysClkRateGet();
			while(tickGet() < timeout)
			{
				if(sslTestClient(&client))
				{
					numconnects++;
				}
				else
				{
					BIO_printf(client.bioResult,"i %d numconnects %d\n",i,numconnects);
					int_error("sslTestClient failed");
					ret= 0;
				}
			}
			BIO_printf(client.bioResult,"%s: %d Connections per second\n",client.ciphers,numconnects/time);
	}
	
		client.method= SSLv2_client_method();
		BIO_printf(client.bioResult,"Testing SSLV2 ciphers\n");
		for(i=0;sslv2_rsa_ciphers[i] != NULL; i++)
		{
		client.ciphers = sslv2_rsa_ciphers[i];
		numconnects=0;
		timeout = tickGet() + time *sysClkRateGet();
			while(tickGet() < timeout)
			{
				if(sslTestClient(&client))
				{
					numconnects++;
				}
				else
				{
					BIO_printf(client.bioResult,"numconnects %d\n",numconnects);
					int_error("sslTestClient failed");
					ret=0;
				}
			}
			BIO_printf(client.bioResult,"%s: %d Connections per second\n",client.ciphers,numconnects/time);
	}
	
	client.certFname = "dsacert.pem"; 
	strcpy(client.port,dsaPort);
	strcpy(client.serverIp,dsaServerIp);
	client.method= SSLv23_client_method();
	BIO_printf(client.bioResult,"Testing SSLV3 DSA ciphers\n");
	for (i=0; sslv3_dsa_ciphers[i] != NULL; i++)
		{
		numconnects=0;
		client.ciphers = sslv3_dsa_ciphers[i];
		timeout = tickGet() + time *sysClkRateGet();
		while (tickGet() < timeout)
			{
			if (sslTestClient(&client))
				{
				numconnects++;
				}
			else
				{
				BIO_printf(client.bioResult,"numconnects %d\n", numconnects);
				int_error("sslTestClient failed");
				ret =0;
				}
			}
		BIO_printf(client.bioResult,"%s: %d Connections per second\n", client.ciphers, numconnects/time);
		}
	return ret;	
}	


void serverDebug()
{
	wrSSLTestServer(0, "4433");
	wrSSLTestServer(1, "4434");
}

int connectDebug(int test,int testOption)
{
return wrSSLTestClientConnectTestAll("192.168.200.1","4433","192.168.200.1","4434",test,testOption,0);
}
 
int connectPerfDebug()
{
 int i;
 for( i=0;i<40;i++)
	/* sp(wrSSLTestClientConnectPerformanceTestAll,"192.168.200.1","4433","192.168.200.1","4434",4,1,0,0,0,0); */
#ifdef TASK_SP	
	sp(wrSSLTestClientConnectTestAll,"192.168.200.1","4433","192.168.200.1","4434",4,10,0,0,0);
#endif	 
 return 1;
}




int testA()
{
	SSL_TEST_CTX config;
	char *rsaServerIp="192.168.200.1";
	char *rsaPort ="4433";
	int ret=1;
	
	
	bzero((char *) &config,sizeof(SSL_TEST_CTX));
	
	config.bioResult = BIO_new_fp( stdout,BIO_NOCLOSE);  
	if(!config.bioResult)
		printf("bad bio\n");
	
	BIO_printf(config.bioResult,"testing AES256-SHA");
	
	
	if(rsaServerIp == NULL || rsaPort==NULL )
	{
		BIO_printf(config.bioResult,"bad parameter IP or Port parameter");
		BIO_free(config.bioResult);
		return 0;
	}
	
	config.method= SSLv23_client_method();
	strcpy(config.port,rsaPort);
	strcpy(config.serverIp,rsaServerIp);
	config.certFname = CERTFILE;
	config.requireClientCert = 0;
	config.outputMsgInfo = 0;
	config.outputStateInfo =1;
	config.test = 4;
	config.testOption = 600;

	config.ciphers = "AES256-SHA";
		if(sslTestClient(&config))
		{
			BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s passed\n",config.ciphers);
		
		}
		else
		{
			BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s failed\n",config.ciphers);
			ret =0;
		}
	
  BIO_free(config.bioResult);
  return ret;
}

void perfTest(void)
{
	SSL_TEST_CTX config;
	char *rsaServerIp="192.168.200.1";
	char *rsaPort ="4433";
	int ret=1;
	int i;
	
	char *test_ciphers[] ={
		"AES256-SHA",
		"RC4-SHA",
		"DES-CBC3-SHA",
		NULL
		};
	
	
	bzero((char *) &config,sizeof(SSL_TEST_CTX));
	
	
	
	config.bioResult = BIO_new_fp( stdout,BIO_NOCLOSE);  
	if(!config.bioResult)
		printf("bad bio\n");
	
	BIO_printf(config.bioResult,"Beginning Performance Tests\n");
	
	
	if(rsaServerIp == NULL || rsaPort==NULL )
	{
		BIO_printf(config.bioResult,"bad parameter IP or Port parameter");
		BIO_free(config.bioResult);
		return;
	}
	
	config.method= SSLv23_client_method();
	strcpy(config.port,rsaPort);
	strcpy(config.serverIp,rsaServerIp);
	config.certFname = CERTFILE;
	config.requireClientCert = 0;
	config.outputMsgInfo = 0;
	config.outputStateInfo =1;
	config.test = 4;
	config.testOption = 5;


	for(i=0;test_ciphers[i] != NULL; i++)
	{
		config.ciphers = test_ciphers[i];
		if(sslTestClient(&config))
		{
			BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s passed\n",config.ciphers);
		
		}
		else
		{
			BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s failed\n",config.ciphers);
			ret =0;
		}
     }
	config.test = CONNECT_TEST_THRUPUT_TWOWAY;
	
	for(i=0;test_ciphers[i] != NULL; i++)
	{
			config.ciphers = test_ciphers[i];
			if(sslTestClient(&config))
			{
				BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s passed\n",config.ciphers);
		
			}
			else
			{
				BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s failed\n",config.ciphers);
				ret =0;
			}
		 }

  BIO_printf(config.bioResult,"Tests Completed\n");
  BIO_free(config.bioResult);
  
}
/* 
*  autoTest - run quick connect test 
* 
*  RETURNS = 0 if fails
*/
int autoTest()
{
	int ret=1;
	char *opensslServerIp = "192.168.200.254";
	char *logname="sslTestOut.txt";
	BIO *fBio;
	
	serverDebug();   /* launch servers on localhost */
	sleep(1);
	
	fBio = BIO_new_file(logname,"w");
	/* fBio=NULL; set to NULL if you want output on console, not in file */
	ret &= wrSSLTestClientConnectTestAll("127.0.0.1","4433","127.0.0.1","4434",SSL_TEST_CONNECT,CONNECT_TEST_QUIET,fBio);
	ret &= wrSSLTestClientConnectTestAll(opensslServerIp,"4433",opensslServerIp,"4434",SSL_TEST_CONNECT,CONNECT_TEST_QUIET,fBio);
	
	BIO_free(fBio);
	printf("\nSSL autoTest Result: %d\n",ret);
	return ret;
}

int autoTest6()
{
	int ret=1;
	char *logname="sslTestOut.txt";
	BIO *fBio;
	
	sleep(1);
	
	fBio = BIO_new_file(logname,"w");
	fBio=NULL; /* set to NULL if you want output on console, not in file */
	
	ret &= wrSSLTestClientConnectTestAll("::1","4433","::1","4434",SSL_TEST_CONNECT,CONNECT_TEST_QUIET,fBio);
	
	BIO_free(fBio);
	printf("\nSSL autoTest Result: %d\n",ret);
	return ret;
}

int renegTest()
{
	SSL_TEST_CTX config;
	char *rsaServerIp="192.168.200.1";
	char *rsaPort ="4433";
	int ret=1;
	
	
	bzero((char *) &config,sizeof(SSL_TEST_CTX));
	
	config.bioResult = BIO_new_fp( stdout,BIO_NOCLOSE);  
	if(!config.bioResult)
		printf("bad bio\n");
	
	BIO_printf(config.bioResult,"testing AES256-SHA");
	
	
	if(rsaServerIp == NULL || rsaPort==NULL )
	{
		BIO_printf(config.bioResult,"bad parameter IP or Port parameter");
		BIO_free(config.bioResult);
		return 0;
	}
	
	config.method= SSLv23_client_method();
	strcpy(config.port,rsaPort);
	strcpy(config.serverIp,rsaServerIp);
	config.certFname = CERTFILE;
	config.requireClientCert = 0;
	config.outputMsgInfo = 0;
	config.outputStateInfo =1;
	config.test = 4;
	config.testOption = 600;

	config.ciphers = "AES256-SHA";
		if(sslTestClient(&config))
		{
			BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s passed\n",config.ciphers);
		
		}
		else
		{
			BIO_printf(config.bioResult,"CONNECTION_TEST (client): %s failed\n",config.ciphers);
			ret =0;
		}
	
  BIO_free(config.bioResult);
  return ret;
}
