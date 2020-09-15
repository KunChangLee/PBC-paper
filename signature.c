/*
  ID-based signature. 一个用户的情况
*/

#include <pbc/pbc.h>
#include <pbc/pbc_test.h>

int main(int argc, char **argv) {
  pairing_t pairing;
  double time0, time1, time2, time3;
  element_t Ppub, s, P, R, r, h, S, Did, Qid, T, t1, t2, t3, t4, t5;
  
  pbc_demo_pairing_init(pairing, argc, argv);
  if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");

  element_init_G1(P, pairing);
  element_init_G1(Ppub, pairing);
  element_init_G1(Qid, pairing);
  element_init_G1(Did, pairing);
  element_init_G1(R, pairing);
  element_init_G1(S, pairing);
  element_init_G1(T, pairing);
  element_init_G1(t1, pairing);
  element_init_G1(t2, pairing);
  element_init_G1(t3, pairing);

  element_init_Zr(s, pairing);
  element_init_Zr(r, pairing);
  element_init_Zr(h, pairing);

  element_init_GT(t4, pairing);
  element_init_GT(t5, pairing);

  time0 = pbc_get_time();
  printf("ID-based signature.\n");
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
  
  printf("SIGN\n");
  element_random(r);
  element_mul_zn(R, P, r);
  element_from_hash(h, "Message", 7);
  element_mul_zn(t1, Ppub, r);
  element_mul_zn(t2, Did, h);
  element_add(S, t1, t2);
  printf("Signature of message \"Message\" is:\n");
  element_printf("R = %B\n", R);
  element_printf("S = %B\n", S);
  
  time2 = pbc_get_time();

  printf("VERIFY\n");
  element_from_hash(h, "Message", 7);
  element_mul_zn(t3, Qid, h);
  element_add(T, t3, R);
  element_pairing(t4, P, S);
  element_pairing(t5, Ppub, T);
  element_printf("e(Ppub, T) = %B\n", t5);
  element_printf("e(P, S) = %B\n", t4);
  if (!element_cmp(t4, t5)) {
    printf("Signature is valid!\n");
  } else {
    printf("Signature is invalid!\n");
  }
  time3 = pbc_get_time();
  
  printf("KEYGEN's time = %fs\n", time1 - time0);
  printf("SIGN's time = %fs\n", time2 - time1);
  printf("VERIFY's time = %fs\n", time3 - time2);
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
  element_clear(h);
  element_clear(T);
  element_clear(S);
  pairing_clear(pairing);

  return 0;
}
