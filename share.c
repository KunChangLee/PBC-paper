/*
  ID-based proxy-reencrypt. 一个用户的情况
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
  double time0, time1, time2, time3, time4, time5;
  element_t Ppub, s, P, R, r, r1, x, m, Did, Qid, Did1, Qid1, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17;
  char raw_message[2048] = "S000000001\0";
  char message_dec[2048], message[2048];
  mpz_t message_mpz;
  pbc_demo_pairing_init(pairing, argc, argv);
  if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

  element_init_G1(P, pairing);
  element_init_G1(Ppub, pairing);
  element_init_Zr(s, pairing);
  element_init_G1(Qid, pairing);
  element_init_G1(Did, pairing);
  element_init_G1(Qid1, pairing);
  element_init_G1(Did1, pairing);
  element_init_G1(R, pairing);
  element_init_GT(x, pairing);
  element_init_GT(t1, pairing);
  element_init_GT(t2, pairing);
  element_init_GT(t3, pairing);
  element_init_Zr(r, pairing);
  element_init_Zr(r1, pairing);
  element_init_GT(m, pairing);
  element_init_G1(t4, pairing);
  element_init_GT(t5, pairing);
  element_init_GT(t6, pairing);
  element_init_GT(t7, pairing);
  element_init_G1(t8, pairing);
  element_init_G1(t9, pairing);
  element_init_G1(t10, pairing);
  element_init_GT(t11, pairing);
  element_init_GT(t12, pairing);
  element_init_GT(t13, pairing);
  element_init_GT(t14, pairing);
  element_init_G1(t15, pairing);
  element_init_GT(t16, pairing);
  element_init_GT(t17, pairing);
  mpz_init(message_mpz);
  
  time0 = pbc_get_time();
  printf("ID-based Proxy re-encrypt.\n");
  printf("KEYGEN\n");
  element_random(P);
  element_random(s);
  element_mul_zn(Ppub, P, s);
  element_printf("P = %B\n", P);
  element_printf("Ppub = %B\n", Ppub);
  element_from_hash(Qid, "ID", 2);
  element_printf("Qid = %B\n", Qid);
  element_mul_zn(Did, Qid, s);
  element_from_hash(Qid1, "ID1", 3);
  element_printf("user's Qid = %B\n", Qid1);
  element_mul_zn(Did1, Qid1, s);
  
  time1 = pbc_get_time();
  
  printf("Encrypt\n");
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

  printf("Re-kengen genration\n");
  element_random(x);
  element_random(r1);
  element_mul_zn(t4, P, r1);
  element_pairing(t5, Ppub, Qid1);
  element_pow_zn(t6, t5, r);
  element_mul(t7, t6, x);
  element_from_hash(t9, x, 3);
  element_sub(t10, t9, Did);
  printf("Re-kengen rk is \n");
  element_printf("R1 = %B\n", t4);
  element_printf("R2 = %B\n", t7);
  element_printf("R3 = %B\n", t10);
  
  time3 = pbc_get_time();
  
  printf("Re-encrypt\n");
  element_pairing(t11, R, t10);
  element_mul(t12, t3, t11);
  printf("Re-encrypt message C_rk is: \n");
  element_printf("C11 = %B\n", R);
  element_printf("C12 = %B\n", t12);
  element_printf("C13 = %B\n", t4);
  element_printf("C14 = %B\n", t7);
  
  time4 = pbc_get_time();
  
  printf("Decrypt\n");
  element_pairing(t13, R, Did1);
  element_div(t14, t7, t13);
  element_from_hash(t15, t14, 3);
  element_pairing(t16, t15, R);
  element_div(t17, t12, t16);
  element_to_mpz(message_mpz, t17);
  valueToMessage(message, message_mpz);
  printf("Decrypt successfully. The message is: ");
  puts(message);
 
  time5 = pbc_get_time();
  
  printf("KEYGEN's time = %fs\n", time1 - time0);
  printf("Encrypt's time = %fs\n", time2 - time1);
  printf("Re-kengen's time = %fs\n", time3 - time2);
  printf("Re-encrypt's time = %fs\n", time4 - time3);
  printf("Decrypt's time = %fs\n", time5 - time4);
  printf("All time = %fs\n", time5 - time0);

  element_clear(P);
  element_clear(Ppub);
  element_clear(s);
  element_clear(Qid);
  element_clear(Did);
  element_clear(R);
  element_clear(t2);
  element_clear(t3);
  element_clear(t4);
  element_clear(t5);
  element_clear(t6);
  element_clear(t7);
  element_clear(t8);
  element_clear(t9);
  element_clear(x);
  element_clear(r);
  element_clear(t1);
  element_clear(m);
  element_clear(t10);
  element_clear(t11);
  element_clear(t12);
  element_clear(t13);
  element_clear(t14);
  element_clear(t15);
  element_clear(t16);
  element_clear(t17);
  mpz_clear(message_mpz);
  pairing_clear(pairing);
  return 0;
}
