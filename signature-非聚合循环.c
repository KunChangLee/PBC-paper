/*
  ID-based signature. 多个用户的情况(用for循环)
*/

#include <pbc/pbc.h>
#include <pbc/pbc_test.h>

int main(int argc, char **argv) {
  enum { K = 9000 };
  pairing_t pairing;
  int i;
  double time0, time1, time2, time3;
  element_t Ppub, s, P, R[K], r[K], h[K], S[K], Did[K], Qid[K], T[K], t1[K], t2[K], t3[K], t4[K], t5[K];
  
  pbc_demo_pairing_init(pairing, argc, argv);
  if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

  element_init_G1(P, pairing);
  element_init_G1(Ppub, pairing);
  element_init_Zr(s, pairing);
  for(i = 0; i < K; i++) {
  element_init_G1(Qid[i], pairing);
  element_init_G1(Did[i], pairing);
  element_init_G1(R[i], pairing);
  element_init_G1(S[i], pairing);
  element_init_G1(T[i], pairing);
  element_init_G1(t1[i], pairing);
  element_init_G1(t2[i], pairing);
  element_init_G1(t3[i], pairing);

  element_init_Zr(r[i], pairing);
  element_init_Zr(h[i], pairing);

  element_init_GT(t4[i], pairing);
  element_init_GT(t5[i], pairing);
  }
  
  time0 = pbc_get_time();
  printf("ID-based signature.\n");
  printf("KEYGEN\n");
  element_random(P);
  element_random(s);
  element_mul_zn(Ppub, P, s);
  element_printf("P = %B\n", P);
  element_printf("Ppub = %B\n", Ppub);
  for(i = 0; i < K; i++) {
  printf("User %d\n", i);
  element_from_hash(Qid[i], "ID", 2);
  element_printf("user's Qid = %B\n", Qid[i]);  
  element_mul_zn(Did[i], Qid[i], s);
  }
  time1 = pbc_get_time();
  
  printf("SIGN\n");
  for(i = 0; i < K; i++) {
  printf("User %d\n", i);
  element_random(r[i]);
  element_mul_zn(R[i], P, r[i]);
  element_from_hash(h[i], "Message", 7);
  element_mul_zn(t1[i], Ppub, r[i]);
  element_mul_zn(t2[i], Did[i], h[i]);
  element_add(S[i], t1[i], t2[i]);
  printf("Signature of message \"Message\" is:\n");
  element_printf("R = %B\n", R[i]);
  element_printf("S = %B\n", S[i]);
  }
  time2 = pbc_get_time();

  printf("VERIFY\n");
  for(i = 0; i < K; i++) {
  printf("User %d\n", i);
  element_from_hash(h[i], "Message", 7);
  element_mul_zn(t3[i], Qid[i], h[i]);
  element_add(T[i], t3[i], R[i]);
  element_pairing(t4[i], P, S[i]);
  element_pairing(t5[i], Ppub, T[i]);
  element_printf("e(Ppub, T) = %B\n", t5[i]);
  element_printf("e(P, S) = %B\n", t4[i]);
  if (!element_cmp(t4[i], t5[i])) {
    printf("Signature is valid!\n");
  } else {
    printf("Signature is invalid!\n");
  }}
  time3 = pbc_get_time();
  
  printf("KEYGEN's time = %fs\n", time1 - time0);
  printf("SIGN's time = %fs\n", time2 - time1);
  printf("VERIFY's time = %fs\n", time3 - time2);
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
  element_clear(h[i]);
  element_clear(T[i]);
  element_clear(S[i]);
  }
  pairing_clear(pairing);

  return 0;
}
