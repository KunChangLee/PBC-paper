/*
  ID-based encrypt. 多个用户的情况(for循环)
*/

#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <stdio.h>
#include <math.h>
#include <gmp.h>
#include <string.h>
#include <stdlib.h>
#include "pbc/pbc_fp.h"

void messageToValue(void *message, mpz_t message_mpz, char *m){
  char* c = NULL;
  unsigned int value = 0, size = 0;
  c = message;
  while(*c != '\0'){
  	value = (unsigned int) *c;
	mpz_mul_ui(message_mpz, message_mpz, 256);
  	mpz_add_ui(message_mpz, message_mpz, value);
	c += 1;
  }
  mpz_get_str(m, 10, message_mpz);
}

void valueToMessage(char *message, mpz_t message_mpz){
  char *c = NULL;
  c = (char*) message_mpz->_mp_d;
  unsigned int count = 0;

  while(*(c + count) != '\0'){
	count += 1;
  }
  message[count] = '\0';
  while(count > 0){
  	count -= 1;
  	message[count] = *c;
	c += 1;
  }
} 
int main(int argc, char **argv) {
  pairing_t pairing;
  enum { K = 10000 };
  int i;
  double time0, time1, time2, time3;
  element_t Ppub, s, P, R[K], r[K], m[K], Did[K], Qid[K], t1[K], t2[K], t3[K], t4[K], t5[K];
  char raw_message[2048] = "S000000001\0";
  char message_dec[2048], message[2048];
  mpz_t message_mpz;
  pbc_demo_pairing_init(pairing, argc, argv);
  if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

  element_init_G1(P, pairing);
  element_init_G1(Ppub, pairing);
  element_init_Zr(s, pairing);
  mpz_init(message_mpz);
  for(i = 0; i < K; i++) {
  element_init_G1(Qid[i], pairing);
  element_init_G1(Did[i], pairing);
  element_init_G1(R[i], pairing);
  element_init_GT(t1[i], pairing);
  element_init_GT(t2[i], pairing);
  element_init_GT(t3[i], pairing);
  element_init_Zr(r[i], pairing);
  element_init_GT(m[i], pairing);
  element_init_GT(t4[i], pairing);
  element_init_GT(t5[i], pairing);
  }
  
  time0 = pbc_get_time();
  printf("ID-based encrypt.\n");
  printf("KEYGEN:\n");
  element_random(P);
  element_random(s);
  element_mul_zn(Ppub, P, s);
  element_printf("P = %B\n", P);
  element_printf("Ppub = %B\n", Ppub);
  for(i = 0; i < K; i++) {
  printf("User %d\n", i);
  element_from_hash(Qid[i], "ID", 2);
  element_printf("Qid = %B\n", Qid[i]);
  element_mul_zn(Did[i], Qid[i], s);
  }
  
  time1 = pbc_get_time();
  
  printf("Encrypt:\n");
  messageToValue(raw_message, message_mpz, message_dec);
  strcpy(message, "[");
  strcat(message, message_dec);
  strcat(message, ",0]");
  for(i = 0; i < K; i++) {
  printf("User %d\n", i+1);
  element_random(r[i]);
  element_mul_zn(R[i], P, r[i]);  
  printf("Before encryption. The raw message is: ");
  puts(raw_message);
  element_set_str(m[i], message, 10);
  element_pairing(t1[i], Ppub, Qid[i]);
  element_pow_zn(t2[i], t1[i], r[i]);
  element_mul(t3[i], t2[i], m[i]);
  printf("Encryption of message \"m\" is: \n");
  element_printf("C1 = %B\n", R[i]);
  element_printf("C2 = %B\n", t3[i]);
  }
  time2 = pbc_get_time();

  printf("Decrypt:\n");
  for(i = 0; i < K; i++) {
  printf("User %d\n", i+1);
  element_pairing(t4[i], R[i], Did[i]);
  element_div(t5[i], t3[i], t4[i]);
  element_to_mpz(message_mpz, t5[i]);
  valueToMessage(message, message_mpz);
  printf("Decrypt successfully. The message is: ");
  puts(message);
  }
  time3 = pbc_get_time();
  
  printf("KEYGEN's time = %fs\n", time1 - time0);
  printf("Encrypt's time = %fs\n", time2 - time1);
  printf("Decrypt's time = %fs\n", time3 - time2);
  printf("All time = %fs\n", time3 - time0);

  element_clear(P);
  element_clear(Ppub);
  element_clear(s);
  for(i = 0; i < K; i++) {
  element_clear(Qid[i]);
  element_clear(Did[i]);
  element_clear(R[i]);
  element_clear(t2[i]);
  element_clear(t3[i]);
  element_clear(t4[i]);
  element_clear(t5[i]);
  element_clear(r[i]);
  element_clear(t1[i]);
  element_clear(m[i]);
  }
  mpz_clear(message_mpz);
  pairing_clear(pairing);
  return 0;
}
