#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  SSL *ssl = arg;

  char buf[BUFFER_SIZE];
  size_t n;
  //printf("\nread_user_input\n");

  while (fgets(buf, sizeof(buf) - 1, stdin)) {
    /* Most text-based protocols use CRLF for line-termination. This
       code replaced a LF with a CRLF. */
    n = strlen(buf);
    if (buf[n-1] == '\n' && (n == 1 || buf[n-2] != '\r'))
      strcpy(&buf[n-1], "\r\n");
    
    /* TODO Send message */
  }
  /* TODO EOF in stdin, shutdown the connection */
  
  return 0;
}

void secure_connect(const char* hostname, const char *port) {

  char buf[BUFFER_SIZE];

  /* TODO Establish SSL context and connection */
  const SSL_METHOD* ssl_method = TLSv1_2_client_method();
  //const SSL_METHOD* ssl_method = TLS_client_method();

  SSL_CTX* ctx = NULL;
  ctx = SSL_CTX_new(ssl_method);
  if (NULL == ctx) report_and_exit("Error at SSL_CTX_new");

  SSL* ssl = NULL;
  
  BIO *bio_in = NULL, *bio_out = NULL;
  
  bio_in = BIO_new_ssl_connect(ctx);
  if (NULL == bio_in) report_and_exit("Error at BIO_new_ssl_connect");

  BIO_get_ssl(bio_in, &ssl);
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  BIO_set_conn_hostname(bio_in, hostname);
  BIO_set_conn_port(bio_in, port);

  if (BIO_do_connect(bio_in) <= 0) {
    cleanup(ctx, bio_in);
    report_and_exit("Error when checking BIO connection");
  }

  // if (!SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs/")) {
  //   report_and_exit("SSL_CTX_load_verify_locations...");
  // }

  /* TODO Print stats about connection */
  /* Create thread that will read data from stdin */
  pthread_t thread;
  pthread_create(&thread, NULL, read_user_input, ssl);
  pthread_detach(thread);

  size_t mk_len = 1;
  size_t num_copied = 0;
  unsigned char* mk = malloc(mk_len);

  SSL_SESSION *session = SSL_get_session(ssl);

  // get session master key
  unsigned char *mk_out[48];
  int nk_nums = SSL_SESSION_get_master_key(session, mk_out, 48);
  fprintf(stderr, "%d\n", nk_nums);

  //fprintf(stderr, "Master Key: %s\n", mk_out);

  fprintf(stderr, "Master Key: \n");
  int i;
  for (i=0; i<nk_nums; i++) {
    fprintf(stderr, "%02X", mk_out[i]);
  }
  fprintf(stderr, "\n\n");

  // trying to print the supported ciphers

  SSL_CIPHER *curr_cipher = NULL;
  char *name;

  fprintf(stderr, "Supported cipher suites:\n");
  STACK_OF(SSL_CIPHER) *ciphers = SSL_get1_supported_ciphers(ssl);
  
  for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
    curr_cipher = sk_SSL_CIPHER_value(ciphers, i);
    name = SSL_CIPHER_get_name(curr_cipher);
    fprintf(stderr, "%s\n", name);
  }

  char *current_cipher_name = SSL_get_cipher_name(ssl);
  fprintf(stderr, "Using cipher suite: %s\n\n", current_cipher_name);

  X509 *cert;
  char *line;

  cert = SSL_get_peer_certificate(ssl);

  if (cert != NULL) {
    int version = ((int) X509_get_version(cert)) + 1;
    fprintf(stderr, "Certificate version: %d\n", version);

    fprintf(stderr, "Certificate verification: %s\n", "yes");

    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    char not_after_str[DATE_LEN];
    convert_ASN1TIME(not_after, not_after_str, DATE_LEN);

    char not_before_str[DATE_LEN];
    convert_ASN1TIME(not_before, not_before_str, DATE_LEN);

    fprintf(stderr, "Certificate start time: %s\n", not_before_str);
    fprintf(stderr, "Certificate end time: %s\n\n", not_after_str);

    line = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    fprintf(stderr, "Certificate Subject: %s\n", line);
    OPENSSL_free(line);

    line = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    fprintf(stderr, "Certificate Issuer: %s\n\n", line);
    OPENSSL_free(line);

    //int pubkey_algonid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);

    X509_free(cert);
  } else {
    fprintf(stderr, "Certificate version: NONE\n\n");
  }

  // int version = ((int) X509_get_version(cert)) + 1;
  // fprintf(stderr, "Certificate version: %d\n\n", version);

  // do {
  //   mk_len *= 2;
  //   mk = (char*)realloc(mk, mk_len);
  //   num_copied = SSL_SESSION_get_master_key(session, mk, mk_len);
  // } while (mk_len > num_copied);
  // for (int i = 0; i < num_copied; i++)
  // {
  //   printf("hello: %02X", mk[i]);
  // }

  fprintf(stderr, "\nType your message:\n\n");

  /* TODO Receive messages and print them to stdout */
  // while(buf) {
    
  // }
}

int main(int argc, char *argv[]) {
  init_ssl();
  
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
