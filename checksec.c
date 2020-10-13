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

void *read_user_input(void *arg) {
  printf("\nhere\n");
  SSL *ssl = arg;

  char buf[BUFFER_SIZE];
  printf("\nheresdf\n");
  size_t n;
  printf("\nher3e\n");
  while (fgets(buf, sizeof(buf) - 1, stdin)) {
    // printf("her123123e\n");
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
  SSL_CTX* ctx = SSL_CTX_new(ssl_method);
  SSL* ssl = NULL;
  X509 *certificate;
  BIO* bio = BIO_new_ssl_connect(ctx);
  BIO_get_ssl(bio, &ssl);
  certificate = SSL_get_peer_certificate(ssl);
  BIO_set_conn_hostname(bio, hostname);
  BIO_do_connect(bio);
  /* TODO Print stats about connection */
  /* Create thread that will read data from stdin */
  pthread_t thread;
  pthread_create(&thread, NULL, read_user_input, ssl);
  pthread_detach(thread);
  size_t mk_len = 1;
  size_t num_copied = 0;
  unsigned char* mk = malloc(mk_len);
  SSL_SESSION* session = SSL_get_session(ssl);
  do{
    mk_len *= 2;
    mk = (char*)realloc(mk, mk_len);
    num_copied = SSL_SESSION_get_master_key(session, mk, mk_len);
  } while(mk_len > num_copied);
  for (int i = 0; i < num_copied; i++)
  {
    printf("hello: %02X", mk[i]);
  }
  fprintf(stderr, "\nType your message:\n\n");

  /* TODO Receive messages and print them to stdout */
  // while(buf) {
    
  // }
  printf("sadfsdfsdf");
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
