#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <openssl/bio.h> /* Basic Input/Output streams */
#include <openssl/err.h> /* errors */
#include <openssl/ssl.h> /* core library */
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>

#include <pthread.h>

#define BUFFER_SIZE 1024
#define DATE_LEN 128


void report_and_exit(const char* msg) {
  perror(msg);
  fprintf(stderr, "\n\nReport and Exit\n\n");
  ERR_print_errors_fp(stderr);
  exit(-1);
}

void init_ssl() {
  SSL_load_error_strings();
  SSL_library_init();
}

void cleanup(SSL_CTX* ctx, BIO* bio) {
  SSL_CTX_free(ctx);
  BIO_free_all(bio);
}

int convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len)
{
	int rc;
	BIO *b = BIO_new(BIO_s_mem());
	rc = ASN1_TIME_print(b, t);
	if (rc <= 0) {
		BIO_free(b);
		return EXIT_FAILURE;
	}
	rc = BIO_gets(b, buf, len);
	if (rc <= 0) {
		BIO_free(b);
		return EXIT_FAILURE;
	}
	BIO_free(b);
	return EXIT_SUCCESS;
}

void *read_user_input(void *arg) {
  // SSL *ssl = arg;
  BIO* bio_in = arg;
  char buf[BUFFER_SIZE];
  size_t n;
  SSL* ssl = NULL;
  while (fgets(buf, sizeof(buf) - 1, stdin)) {
    /* Most text-based protocols use CRLF for line-termination. This
       code replaced a LF with a CRLF. */
    n = strlen(buf);
    BIO_get_ssl(bio_in, &ssl); 
    if(buf[n-1] == '\04'){
      break;
    }
    if (buf[n-1] == '\n' && (n == 1 || buf[n-2] != '\r'))
      strcpy(&buf[n-1], "\r\n");
    if(BIO_puts(bio_in, buf) <= 0) {
      fprintf(stderr, "Error sending message to server");
      break;
    }
  }
  
  exit(0);
  return 0;
}

void secure_connect(const char* hostname, const char *port) {

  char buf[BUFFER_SIZE];

  /* TODO Establish SSL context and connection */
  const SSL_METHOD* ssl_method = TLS_client_method();

  SSL_CTX* ctx = NULL;
  ctx = SSL_CTX_new(ssl_method);
  if (NULL == ctx) report_and_exit("Error at SSL_CTX_new");

  SSL_CTX_set_default_verify_paths(ctx);
  SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);

  SSL* ssl = NULL;
  
  BIO *bio_in = NULL, *bio_out = BIO_new_fp(stderr, BIO_NOCLOSE);
  
  bio_in = BIO_new_ssl_connect(ctx);
  if (NULL == bio_in) report_and_exit("Error at BIO_new_ssl_connect");

  BIO_get_ssl(bio_in, &ssl); 
  if (ssl == NULL) {
    report_and_exit("Error when checking BIO connection");
  }
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  BIO_set_conn_hostname(bio_in, hostname);
  BIO_set_conn_port(bio_in, port);

  if (BIO_do_connect(bio_in) <= 0) {
    cleanup(ctx, bio_in);
    report_and_exit("Error when checking BIO connection");
  }
  if(BIO_do_handshake(bio_in) <= 0) {
    cleanup(ctx, bio_in);
    report_and_exit("Error establishing SSL connection");
  }

  /* Create thread that will read data from stdin */
  pthread_t thread;
  pthread_create(&thread, NULL, read_user_input, bio_in);
  pthread_detach(thread);

  int mk_nums = 0;
  SSL_SESSION *session = SSL_get_session(ssl);

  // get session master key
  unsigned char *mk_out = malloc(BUFFER_SIZE);  
  mk_nums = SSL_SESSION_get_master_key(session, mk_out, BUFFER_SIZE);
  fprintf(stderr, "Master Key:\n");
  if (mk_nums == 0){
    fprintf(stderr, "Error retreiving Master Key\n");
  }
  int i;
  for (i=0; i < mk_nums; i++) {
    fprintf(stderr, "%02X", mk_out[i]);
  }

  fprintf(stderr, "\n\n");
  free(mk_out);

  // trying to print the supported ciphers

  fprintf(stderr, "Supported cipher suites:\n");
  STACK_OF(SSL_CIPHER) *ciphers = SSL_get1_supported_ciphers(ssl);

  for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
    const SSL_CIPHER *curr_cipher = sk_SSL_CIPHER_value(ciphers, i);
    const char *name = SSL_CIPHER_get_name(curr_cipher);
    fprintf(stderr, "%s\n", name);
  }

  const char *current_cipher_name = SSL_get_cipher_name(ssl);
  fprintf(stderr, "Using cipher suite: %s\n\n", current_cipher_name);

  X509 *cert;

  cert = SSL_get_peer_certificate(ssl);

  if (cert != NULL) {
    int version = ((int) X509_get_version(cert)) + 1;
    fprintf(stderr, "Certificate version: %d\n", version);

    long verify_flag = SSL_get_verify_result(ssl);
    fprintf(stderr, "Certificate verification: %s\n", X509_verify_cert_error_string(verify_flag));

    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    char not_after_str[DATE_LEN];
    convert_ASN1TIME(not_after, not_after_str, DATE_LEN);

    char not_before_str[DATE_LEN];
    convert_ASN1TIME(not_before, not_before_str, DATE_LEN);

    fprintf(stderr, "Certificate start time: %s\n", not_before_str);
    fprintf(stderr, "Certificate end time: %s\n\n", not_after_str);

    char *cert_key_buf = malloc(BUFFER_SIZE);

    X509_NAME *subj = X509_get_subject_name(cert);
    fprintf(stderr, "Certificate Subject: \n");

    for (int i = 0; i < X509_NAME_entry_count(subj); i++) {
	    X509_NAME_ENTRY *e = X509_NAME_get_entry(subj, i);
      OBJ_obj2txt(cert_key_buf, BUFFER_SIZE, X509_NAME_ENTRY_get_object(e), 0);
	    const unsigned char *value = ASN1_STRING_get0_data(X509_NAME_ENTRY_get_data(e));
      fprintf(stderr, "%s: %s\n", cert_key_buf, value);
    }

    fprintf(stderr, "\n");

    X509_NAME *issu = X509_get_issuer_name(cert);
    fprintf(stderr, "Certificate Issuer: \n");

    for (int i = 0; i < X509_NAME_entry_count(issu); i++) {
	    X509_NAME_ENTRY *e = X509_NAME_get_entry(issu, i);
      OBJ_obj2txt(cert_key_buf, BUFFER_SIZE, X509_NAME_ENTRY_get_object(e), 0);
	    const unsigned char *value = ASN1_STRING_get0_data(X509_NAME_ENTRY_get_data(e));
      fprintf(stderr, "%s: %s\n", cert_key_buf, value);
    }

    fprintf(stderr, "\n");

    free(cert_key_buf);

    EVP_PKEY * pubkey; 
    pubkey = X509_get_pubkey (cert);
    if(!PEM_write_bio_PUBKEY(bio_out, pubkey))
      BIO_printf(bio_out, "Error writing public key data in PEM format");
    
    X509_free(cert);
  } else {
    fprintf(stderr, "Certificate version: NONE\n\n");
  }

  fprintf(stderr, "\nType your message:\n\n");

  /* TODO Receive messages and print them to stdout */
  size_t len;
  while(1) {
    len = BIO_read(bio_in, buf, sizeof(buf));
    if(len > 0)
      BIO_write(bio_out, buf, len);
  }
  free(bio_in);
  free(bio_out);
  
}

void sigpipe_handler(int unused)
{
  perror("Connection was closed by server");
}

int main(int argc, char *argv[]) {
  init_ssl();
  // sigaction(SIGPIPE, (const struct siginfo_t *)report_and_exit, (void*)connection_closed_msg);
  signal(SIGPIPE, sigpipe_handler);
  const char* hostname;
  const char* port = "443";

  if (argc < 2) {
    fprintf(stderr, "Usage: %s hostname [port]\n", argv[0]);
    return 1;
  }

  hostname = argv[1];
  if (argc > 2)
    port = argv[2];
  
  fprintf(stderr, "Host: %s\nPort: %s\n\n", hostname, port);
  secure_connect(hostname, port);
  
  return 0;
}
