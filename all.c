/*
  ID-based protocol. 多个用户的情况
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
  enum { K1 = 1 };
  enum { K2 = 1 };
  int i;
  double time0, time1, time2, time3, time4, time5, time6, time7, time8;
  element_t Ppub, s, P, R[K1], S[K1], T[K1], r[K1], h[K1], x[K2], m[K1], Did[K1], Qid[K1], Did1[K2], Qid1[K2], t1[K1], t2[K1], t3[K1], t4[K1], t5[K1], t6[K1], t7[K1], t8[K1], t9[K1], t10[K1], t11[K2], t12[K2], t13[K2], t14[K2], t15[K2], t16[K2], t17[K2], t18[K2], t19[K2], t20[K2], t21[K2], t22[K2], R1[K2], r1[K2];
  char raw_message[2048] = "S000000001\0";
  char message_dec[2048], message[2048];
  mpz_t message_mpz;
  pbc_demo_pairing_init(pairing, argc, argv);
  if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

  element_init_G1(P, pairing);
  element_init_G1(Ppub, pairing);
  element_init_Zr(s, pairing);
  for(i = 0; i < K1; i++) {
  element_init_G1(Qid[i], pairing);
  element_init_G1(Did[i], pairing);
  element_init_G1(R[i], pairing);
  element_init_G1(S[i], pairing);
  element_init_G1(T[i], pairing);
  element_init_GT(t1[i], pairing);
  element_init_GT(t2[i], pairing);
  element_init_GT(t3[i], pairing);
  element_init_Zr(r[i], pairing);
  element_init_GT(m[i], pairing);
  element_init_G1(t4[i], pairing);
  element_init_G1(t5[i], pairing);
  element_init_G1(t6[i], pairing);
  element_init_GT(t7[i], pairing);
  element_init_GT(t8[i], pairing);
  element_init_GT(t9[i], pairing);
  element_init_GT(t10[i], pairing);
  element_init_Zr(h[i], pairing);
  }
  for(i = 0; i < K2; i++) {
  element_init_G1(Qid1[i], pairing);
  element_init_G1(Did1[i], pairing);
  element_init_GT(x[i], pairing);
  element_init_GT(t11[i], pairing);
  element_init_GT(t12[i], pairing);
  element_init_GT(t13[i], pairing);
  element_init_G1(t14[i], pairing);
  element_init_G1(t15[i], pairing);
  element_init_GT(t16[i], pairing);
  element_init_GT(t17[i], pairing);
  element_init_GT(t18[i], pairing);
  element_init_GT(t19[i], pairing);
  element_init_GT(t20[i], pairing);
  element_init_GT(t21[i], pairing);
  element_init_GT(t22[i], pairing);
  element_init_Zr(r1[i], pairing);
  element_init_G1(R1[i], pairing);
  
  }
  mpz_init(message_mpz);
  
  time0 = pbc_get_time();
  printf("All protocol.\n");
  printf("KEYGEN\n");
  element_random(P);
  element_random(s);
  element_mul_zn(Ppub, P, s);
  element_printf("P = %B\n", P);
  element_printf("Ppub = %B\n", Ppub);
  for(i = 0; i < K1; i++) {
  printf("User %d\n", i+1);
  element_from_hash(Qid[i], "ID", 2);
  element_printf("Qid = %B\n", Qid[i]);
  element_mul_zn(Did[i], Qid[i], s);
  }
  for(i = 0; i < K2; i++) {
  printf("Salemen User %d\n", i+1);
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
  for(i = 0; i < K1; i++) {
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
  
  printf("SIGN\n");
  for(i = 0; i < K1; i++) {
  printf("User %d\n", i+1);
  //element_random(r[i]);
  element_mul_zn(R[i], P, r[i]);
  element_from_hash(h[i], "S000000001", 10);
  element_mul_zn(t4[i], Ppub, r[i]);
  element_mul_zn(t5[i], Did[i], h[i]);
  element_add(S[i], t4[i], t5[i]);
  printf("Signature of message \"Message\" is:\n");
  element_printf("R = %B\n", R[i]);
  element_printf("S = %B\n", S[i]);
  }
  
  time3 = pbc_get_time();

  printf("VERIFY\n");
  for(i = 0; i < K1; i++) {
  printf("User %d\n", i+1);
  element_from_hash(h[i], "S000000001", 10);
  element_mul_zn(t6[i], Qid[i], h[i]);
  element_add(T[i], t6[i], R[i]);
  element_pairing(t7[i], P, S[i]);
  element_pairing(t8[i], Ppub, T[i]);
  element_printf("e(Ppub, T) = %B\n", t8[i]);
  element_printf("e(P, S) = %B\n", t7[i]);
  if (!element_cmp(t7[i], t8[i])) {
    printf("Signature is valid!\n");
  } else {
    printf("Signature is invalid!\n");
  }}

  time4 = pbc_get_time();
  
  printf("Decrypt:\n");
  for(i = 0; i < K1; i++) {
  printf("User %d\n", i+1);
  element_pairing(t9[i], R[i], Did[i]);
  element_div(t10[i], t3[i], t9[i]);
  element_to_mpz(message_mpz, t10[i]);
  valueToMessage(message, message_mpz);
  printf("Decrypt successfully. The message is: ");
  puts(message);
  }
  
  time5 = pbc_get_time();
  
  //printf("Encrypt\n");
  messageToValue(raw_message, message_mpz, message_dec);
  strcpy(message, "[");
  strcat(message, message_dec);
  strcat(message, ",0]");
  for(i = 0; i < K1; i++) {
  //printf("User %d\n", i+1);
  element_random(r[i]);
  element_mul_zn(R[i], P, r[i]);  
  printf("Before encryption. The raw message is: ");
  puts(raw_message);
  element_set_str(m[i], message, 10);
  element_pairing(t1[i], Ppub, Qid[i]);
  element_pow_zn(t2[i], t1[i], r[i]);
  element_mul(t3[i], t2[i], m[i]);
  //printf("Encryption of message \"m\" is: \n");
  //element_printf("C1 = %B\n", R[i]);
  //element_printf("C2 = %B\n", t3[i]);
  }

  printf("Re-kengen genration\n");
  for(i = 0; i < K2; i++) {
  printf("Saleman User %d\n", i+1);
  element_random(r1[i]);
  element_mul_zn(R1[i], P, r1[i]);
  element_random(x[i]);
  element_pairing(t11[i], Ppub, Qid1[i]);
  element_pow_zn(t12[i], t11[i], r1[i]);
  element_mul(t13[i], t12[i], x[i]);
  element_from_hash(t14[i], x[i], 3);
  element_sub(t15[i], t14[i], Did[0]);
  printf("Re-kengen rk is \n");
  element_printf("R1 = %B\n", R1[i]);
  element_printf("R2 = %B\n", t13[i]);
  element_printf("R3 = %B\n", t15[i]);
  }
  
  time6 = pbc_get_time();
  
  printf("Re-encrypt\n");
  for(i = 0; i < K2; i++) {
  printf("User %d\n", i+1);
  element_pairing(t16[i], R[0], t15[i]);
  element_mul(t17[i], t3[i], t16[i]);
  printf("Re-encrypt message C_rk is: \n");
  element_printf("C11 = %B\n", R[0]);
  element_printf("C12 = %B\n", t17[i]);
  element_printf("C13 = %B\n", R1[i]);
  element_printf("C14 = %B\n", t13[i]);
  }
  
  time7 = pbc_get_time();
  
  printf("Decrypt\n");
  for(i = 0; i < K2; i++) {
  printf("User %d\n", i+1);
  element_pairing(t18[i], R1[i], Did1[i]);
  element_div(t19[i], t13[i], t18[i]);
  element_from_hash(t20[i], t19[i], 3);
  element_pairing(t21[i], t20[i], R[0]);
  element_div(t22[i], t17[i], t21[i]);
  element_to_mpz(message_mpz, t22[i]);
  valueToMessage(message, message_mpz);
  printf("Decrypt successfully. The message is: ");
  puts(message);
  }
 
  time8 = pbc_get_time();
  
  printf("KEYGEN's time = %fs\n", time1 - time0);
  printf("Encrypt alogrimth's time = %fs\n", time2 - time1 + time5 - time4);
  printf("Signature alogrimth's time = %fs\n", time4 - time2);
  printf("Re-encrypt alogrimth's time = %fs\n", time8 - time5);
  printf("All time = %fs\n", time8 - time0 - time2 + time1);

  element_clear(P);
  element_clear(Ppub);
  element_clear(s);
  for(i = 0; i < K1; i++) {
  element_clear(Qid[i]);
  element_clear(Did[i]);
  element_clear(R[i]);
  element_clear(S[i]);
  element_clear(T[i]);
  element_clear(t1[i]);
  element_clear(t2[i]);
  element_clear(t3[i]);
  element_clear(r[i]);
  element_clear(m[i]);
  element_clear(h[i]);
  element_clear(t4[i]);
  element_clear(t5[i]);
  element_clear(t6[i]);
  element_clear(t7[i]);
  element_clear(t8[i]);
  element_clear(t9[i]);
  element_clear(t10[i]);
  
  }
  for(i = 0; i < K2; i++) {
  element_clear(Qid1[i]);
  element_clear(Did1[i]);
  element_clear(x[i]);
  element_clear(t11[i]);
  element_clear(t12[i]);
  element_clear(t13[i]);
  element_clear(t14[i]);
  element_clear(t15[i]);
  element_clear(t16[i]);
  element_clear(t17[i]);
  element_clear(t18[i]);
  element_clear(t19[i]);
  element_clear(t20[i]);
  element_clear(t21[i]);
  element_clear(t22[i]);
  element_clear(r1[i]);
  element_clear(R1[i]);
  
  }
  mpz_clear(message_mpz);
  pairing_clear(pairing);
  return 0;
}
