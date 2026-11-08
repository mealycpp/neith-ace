/* Byte-match + XMSS round-trip check for neith_shim against the reference.
   Build with validate.sh; prints MAC/DIG/GEN/SIGNMSG hex and a sign/verify result,
   which must equal the Python reference (validate.sh runs both and diffs). */
#include <stdio.h>
#include "neith_shim.h"
void neith_manifest_genesis(uint32_t,uint16_t,uint8_t[32]);
size_t neith_manifest_signmsg(uint32_t,uint16_t,uint32_t,int64_t,const uint8_t[32],int,
    const uint32_t*,const uint8_t(*)[32],size_t,uint8_t[32],uint8_t[32]);
int xw_verify(const unsigned char*,const unsigned char*,const unsigned char*,unsigned long long);
static void hex(const char*l,const unsigned char*b,int n){printf("%s ",l);for(int i=0;i<n;i++)printf("%02x",b[i]);printf("\n");}
int main(){
  unsigned char key[16]; for(int i=0;i<16;i++)key[i]=i;
  unsigned char p[40]; for(int i=0;i<40;i++)p[i]=(i*7)&0xff;
  unsigned char tag[32],dig[32],gen[32],sm[32],np[32],digs[2][32]; uint32_t seqs[2]={0,1};
  neith_mac_chunk(key,1,0,5,p,40,tag); hex("MAC",tag,32);
  neith_digest(p,40,dig); hex("DIG",dig,32);
  neith_manifest_genesis(1,0,gen); hex("GEN",gen,32);
  neith_digest(p,40,digs[0]); neith_digest(p,20,digs[1]);
  neith_manifest_signmsg(1,0,1,5,gen,0,seqs,digs,2,sm,np); hex("SIGNMSG",sm,32);
  if(neith_xmss_open("XMSS-SHAKE256_10_256","/tmp/neith_rt.state")){printf("XMSS open FAIL\n");return 2;}
  unsigned char pk[132]; size_t pkl=sizeof(pk); neith_xmss_pubkey(pk,&pkl);
  unsigned char sig[3072]; size_t sl=sizeof(sig);
  if(neith_xmss_sign(sm,32,sig,&sl)){printf("XMSS sign FAIL (key exhausted?)\n");return 3;}
  printf("XMSS verify (0=ok): %d  siglen=%zu\n", xw_verify(pk,sig,sm,32), sl);
  return 0;
}
