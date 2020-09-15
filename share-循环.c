/*
  ID-based proxy-reencrypt. 多个用户的情况
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
  enum { K = 9000 };
  int i;
  double time0, time1, time2, time3, time4, time5;
  element_t Ppub, s, P, R[K], r[K], r1[K], x[K], m[K], Did, Qid, Did1[K], Qid1[K], t1[K], t2[K], t3[K], t4[K], t5[K], t6[K], t7[K], t8[K], t9[K], t10[K], t11[K], t12[K], t13[K], t14[K], t15[K], t16[K], t17[K];
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
  for(i = 0; i < K; i++) {
  element_init_G1(Qid1[i], pairing);
  element_init_G1(Did1[i], pairing);
  element_init_G1(R[i], pairing);
  element_init_GT(x[i], pairing);
  element_init_GT(t1[i], pairing);
  element_init_GT(t2[i], pairing);
  element_init_GT(t3[i], pairing);
  element_init_Zr(r[i], pairing);
  element_init_Zr(r1[i], pairing);
  element_init_GT(m[i], pairing);
  element_init_G1(t4[i], pairing);
  element_init_GT(t5[i], pairing);
  element_init_GT(t6[i], pairing);
  element_init_GT(t7[i], pairing);
  element_init_G1(t8[i], pairing);
  element_init_G1(t9[i], pairing);
  element_init_G1(t10[i], pairing);
  element_init_GT(t11[i], pairing);
  element_init_GT(t12[i], pairing);
  element_init_GT(t13[i], pairing);
  element_init_GT(t14[i], pairing);
  element_init_G1(t15[i], pairing);
  element_init_GT(t16[i], pairing);
  element_init_GT(t17[i], pairing);
  }
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
  for(i = 0; i < K; i++) {
  printf("Saleman User %d\n", i+1);
  element_from_hash(Qid1[i], "ID1", 3);
  element_printf("Saleman user's Qid = %B\n", Qid1[i]);
  element_mul_zn(Did1[i], Qid1[i], s);
  }
  
  time1 = pbc_get_time();
  
  printf("Encrypt\n");
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
  element_pairing(t1[i], Ppub, Qid);
  element_pow_zn(t2[i], t1[i], r[i]);
  element_mul(t3[i], t2[i], m[i]);
  printf("Encryption of message \"m\" is: \n");
  element_printf("C1 = %B\n", R[i]);
  element_printf("C2 = %B\n", t3[i]);
  }
  
  time2 = pbc_get_time();

  printf("Re-kengen genration\n");
  for(i = 0; i < K; i++) {
  printf("User %d\n", i+1);
  element_random(r1[i]);
  element_mul_zn(t4[i], P, r1[i]);
  element_random(x[i]);
  element_pairing(t5[i], Ppub, Qid1[i]);
  element_pow_zn(t6[i], t5[i], r[i]);
  element_mul(t7[i], t6[i], x[i]);
  element_from_hash(t9[i], x[i], 3);
  element_sub(t10[i], t9[i], Did);
  printf("Re-kengen rk is \n");
  element_printf("R1 = %B\n", t4[i]);
  element_printf("R2 = %B\n", t7[i]);
  element_printf("R3 = %B\n", t10[i]);
  }
  
  time3 = pbc_get_time();
  
  printf("Re-encrypt\n");
  for(i = 0; i < K; i++) {
  printf("User %d\n", i+1);
  element_pairing(t11[i], R[i], t10[i]);
  element_mul(t12[i], t3[i], t11[i]);
  printf("Re-encrypt message C_rk is: \n");
  element_printf("C11 = %B\n", R[i]);
  element_printf("C12 = %B\n", t12[i]);
  element_printf("C13 = %B\n", t4[i]);
  element_printf("C14 = %B\n", t7[i]);
  }
  
  time4 = pbc_get_time();
  
  printf("Decrypt\n");
  for(i = 0; i < K; i++) {
  printf("User %d\n", i+1);
  element_pairing(t13[i], R[i], Did1[i]);
  element_div(t14[i], t7[i], t13[i]);
  element_from_hash(t15[i], t14[i], 3);
  element_pairing(t16[i], t15[i], R[i]);
  element_div(t17[i], t12[i], t16[i]);
  element_to_mpz(message_mpz, t17[i]);
  valueToMessage(message, message_mpz);
  printf("Decrypt successfully. The message is: ");
  puts(message);
  }
 
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
  for(i = 0; i < K; i++) {
  element_clear(Qid1[i]);
  element_clear(Did1[i]);
  element_clear(R[i]);
  element_clear(t2[i]);
  element_clear(t3[i]);
  element_clear(t4[i]);
  element_clear(t5[i]);
  element_clear(t6[i]);
  element_clear(t7[i]);
  element_clear(t8[i]);
  element_clear(t9[i]);
  element_clear(x[i]);
  element_clear(r[i]);
  element_clear(r1[i]);
  element_clear(t1[i]);
  element_clear(m[i]);
  element_clear(t10[i]);
  element_clear(t11[i]);
  element_clear(t12[i]);
  element_clear(t13[i]);
  element_clear(t14[i]);
  element_clear(t15[i]);
  element_clear(t16[i]);
  element_clear(t17[i]);
  }
  mpz_clear(message_mpz);
  pairing_clear(pairing);
  return 0;
}
