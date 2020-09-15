/*
  ID-based encrypt. 一个用户的情况
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
  double time0, time1, time2, time3;
  element_t Ppub, s, P, R, r, g, m, Did, Qid, t1, t2, t3, t4, t5;
  char raw_message[2048] = "S000000001\0";
  char message_dec[2048], message[2048];
  mpz_t message_mpz;
  pbc_demo_pairing_init(pairing, argc, argv);
  if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

  element_init_G1(P, pairing);
  element_init_G1(Ppub, pairing);
  element_init_G1(Qid, pairing);
  element_init_G1(Did, pairing);
  element_init_G1(R, pairing);
  element_init_G1(g, pairing);
  element_init_GT(t1, pairing);
  element_init_GT(t2, pairing);
  element_init_GT(t3, pairing);
  element_init_Zr(s, pairing);
  element_init_Zr(r, pairing);
  element_init_GT(m, pairing);
  element_init_GT(t4, pairing);
  element_init_GT(t5, pairing);
  mpz_init(message_mpz);
  
  time0 = pbc_get_time();
  printf("ID-based encrypt.\n");
  printf("KEYGEN\n");
  element_random(P);
  element_random(s);
  element_mul_zn(Ppub, P, s);
  element_printf("P = %B\n", P);
  element_printf("Ppub = %B\n", Ppub);
  element_from_hash(Qid, "ID", 2);
  element_printf("Qid = %B\n", Qid);
  element_mul_zn(Did, Qid, s);
  
  time1 = pbc_get_time();
  
  //printf("Encrypt\n");
  element_random(r);
  element_mul_zn(R, P, r);  
  printf("Before encryption. The raw message is: ");
  puts(raw_message);
  messageToValue(raw_message, message_mpz, message_dec);
  strcpy(message, "[");
  strcat(message, message_dec);
  strcat(message, ",0]");
  element_set_str(m, message, 10);
  element_pairing(t1, Ppub, Qid);
  element_pow_zn(t2, t1, r);
  element_mul(t3, t2, m);
  printf("Encryption of message \"m\" is: \n");
  element_printf("C1 = %B\n", R);
  element_printf("C2 = %B\n", t3);
  
  time2 = pbc_get_time();

  //printf("Decrypt\n");
  element_pairing(t4, R, Did);
  element_div(t5, t3, t4);
  element_to_mpz(message_mpz, t5);
  valueToMessage(message, message_mpz);
  printf("Decrypt successfully. The message is: ");
  puts(message);
 
  time3 = pbc_get_time();
  
  printf("KEYGEN's time = %fs\n", time1 - time0);
  printf("Encrypt's time = %fs\n", time2 - time1);
  printf("Decrypt's time = %fs\n", time3 - time2);
  printf("All time = %fs\n", time3 - time0);

  element_clear(P);
  element_clear(Ppub);
  element_clear(Qid);
  element_clear(Did);
  element_clear(R);
  element_clear(t2);
  element_clear(t3);
  element_clear(t4);
  element_clear(t5);
  element_clear(s);
  element_clear(r);
  element_clear(t1);
  element_clear(m);
  mpz_clear(message_mpz);
  pairing_clear(pairing);
  return 0;
}
