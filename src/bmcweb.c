/* bmcweb.c — complete standalone BMC web stack for ASMB4 AST2050, NOLIBC.
 *
 * Replaces the GoAhead web layer entirely:
 *   :80  HTTP/1.1  — embedded SPA + JSON API
 *   /ws            — WebSocket <-> adviserd:7578 IVTP bridge (KVM)
 *   /api/*         — JSON endpoints backed by RMCP+/IPMI-LAN to 127.0.0.1:623
 *   /fw/*          — streaming proxy to GoAhead on :8080 (stock flash path 1:1)
 *   /legacy/*      — same, for stock UI pages
 *
 * Auth: RAKP2 verify = password check (HMAC-SHA1 keyed by password against the
 * BMC's own IPMI user database). Our API session = HMAC-signed token with a
 * boot-time random key in /var/ikvmkey.
 *
 * OABI syscalls via .word immediates (2.6.15-ami kernel), socketcall for all
 * socket I/O (kernel write()/read() on sockets are broken in this context),
 * NO .bss/.data — all state on stack, single LOAD segment.
 *
 * Build: arm-linux-gnueabi-gcc -nostdlib -static -Os -fno-builtin \
 *          -fno-tree-loop-distribute-patterns -o bmcweb bmcweb.c
 */
typedef unsigned int u32; typedef unsigned short u16; typedef unsigned char u8;
typedef unsigned long long u64; typedef int i32;

/* ---------- OABI syscalls ---------- */
#define _SC0(c) ({register int r0 asm("r0");asm volatile(".word " #c :"=r"(r0)::"memory");r0;})
#define _SC1(c,a) ({register int r0 asm("r0")=(a);asm volatile(".word " #c :"=r"(r0):"0"(r0):"memory");r0;})
#define _SC2(c,a,b) ({register int r0 asm("r0")=(a),r1 asm("r1")=(b);asm volatile(".word " #c :"=r"(r0):"0"(r0),"r"(r1):"memory");r0;})
#define _SC3(c,a,b,cc) ({register int r0 asm("r0")=(a),r1 asm("r1")=(b),r2 asm("r2")=(cc);asm volatile(".word " #c :"=r"(r0):"0"(r0),"r"(r1),"r"(r2):"memory");r0;})
#define _SC4(c,a,b,cc,d) ({register int r0 asm("r0")=(a),r1 asm("r1")=(b),r2 asm("r2")=(cc),r3 asm("r3")=(d);asm volatile(".word " #c :"=r"(r0):"0"(r0),"r"(r1),"r"(r2),"r"(r3):"memory");r0;})
#define _SC5(c,a,b,cc,d,e) ({register int r0 asm("r0")=(a),r1 asm("r1")=(b),r2 asm("r2")=(cc),r3 asm("r3")=(d),r4 asm("r4")=(e);asm volatile(".word " #c :"=r"(r0):"0"(r0),"r"(r1),"r"(r2),"r"(r3),"r"(r4):"memory");r0;})
#define sc0(n)      _SC0(0xEF900000+n)
#define sc1(n,a)    _SC1(0xEF900000+n,a)
#define sc2(n,a,b)  _SC2(0xEF900000+n,a,b)
#define sc3(n,a,b,c) _SC3(0xEF900000+n,a,b,c)
#define sc4(n,a,b,c,d) _SC4(0xEF900000+n,a,b,c,d)
#define sc5(n,a,b,c,d,e) _SC5(0xEF900000+n,a,b,c,d,e)

/* functions not macros: macro args feeding asm-bound registers get clobbered
   when an arg expression is itself a call (strlen ran AFTER r0 was bound) */
static int sys_exit(int x){return sc1(1,x);}
static int sys_fork(void){return sc0(2);}
static int sys_read(int f,void*b,int n){return sc3(3,f,(int)b,n);}
static int sys_write(int f,const void*b,int n){return sc3(4,f,(int)b,n);}
static int sys_open(const char*p,int f,int m){return sc3(5,(int)p,f,m);}
static int sys_close(int f){return sc1(6,f);}
static int sys_getpid(void){return sc0(20);}
static int sys_time(void){return sc1(13,0);}
static int sys_wait4(int p,int*s,int o){return sc4(114,p,(int)s,o,0);}
static void sys_nanosleep(int sec,int nsec){long ts[2]={sec,nsec};sc2(162,(int)ts,0);}
static int sys_dup2(int o,int n){return sc2(63,o,n);}
static int sys_select(int n,void*r,void*w,void*e,void*t){return sc5(142,n,(int)r,(int)w,(int)e,(int)t);}

static int socketcall(int c,int*a){return sc2(102,c,(int)a);}
static int sys_socket(int d,int t,int p){int x[3]={d,t,p};return socketcall(1,x);}
static int sys_bind(int f,void*a,int l){int x[3]={f,(int)a,l};return socketcall(2,x);}
static int sys_connect(int f,void*a,int l){int x[3]={f,(int)a,l};return socketcall(3,x);}
static int sys_listen(int f,int b){int x[2]={f,b};return socketcall(4,x);}
static int sys_accept(int f,void*a,int l){int x[3]={f,(int)a,l};return socketcall(5,x);}
static int sys_setsockopt(int f,int l,int o,void*v,int n){int x[5]={f,l,o,(int)v,n};return socketcall(14,x);}
static int ssend(int f,const void*b,int n){int x[4]={f,(int)b,n,0};return socketcall(9,x);}
static int srecv(int f,void*b,int n){int x[4]={f,(int)b,n,0};return socketcall(10,x);}
static int ssendto(int f,const void*b,int n,void*a,int al){int x[6]={f,(int)b,n,0,(int)a,al};return socketcall(11,x);}
static int srecvfrom(int f,void*b,int n){int x[6]={f,(int)b,n,0,0,0};return socketcall(12,x);}
static void shrink_bufs(int f){int b=4096;sys_setsockopt(f,1,7,&b,4);sys_setsockopt(f,1,8,&b,4);}
/* SO_RCVTIMEO=20 / SO_SNDTIMEO=21 (SOL_SOCKET=1); tv={sec,usec} */
static void set_to(int f,int sec){int tv[2]={sec,0};sys_setsockopt(f,1,20,tv,8);sys_setsockopt(f,1,21,tv,8);}

/* ---------- mini libc ---------- */
/* __aeabi division helpers — no libgcc */
static unsigned __udiv(unsigned a,unsigned b){
 unsigned q=0,r=0;if(!b)return 0;
 for(int i=31;i>=0;i--){r=(r<<1)|((a>>i)&1);if(r>=b){r-=b;q|=1u<<i;}}
 return q;}
static int __idiv(int a,int b){
 int sg=(a<0)^(b<0);unsigned ua=a<0?-(unsigned)a:(unsigned)a,ub=b<0?-(unsigned)b:(unsigned)b;
 unsigned q=__udiv(ua,ub);return sg?-(int)q:(int)q;}
int __aeabi_idiv(int a,int b){return __idiv(a,b);}
unsigned __aeabi_uidiv(unsigned a,unsigned b){return __udiv(a,b);}
/* AEABI: r0=quot, r1=rem — must be asm, a C struct-return uses a hidden ptr arg */
__asm__(".text\n.global __aeabi_idivmod,__aeabi_uidivmod\n__aeabi_idivmod:\n push {r4-r6,lr}\n mov r4,r0\n mov r5,r1\n bl __aeabi_idiv\n mov r6,r0\n mul r0,r5,r6\n sub r1,r4,r0\n mov r0,r6\n pop {r4-r6,pc}\n__aeabi_uidivmod:\n push {r4-r6,lr}\n mov r4,r0\n mov r5,r1\n bl __aeabi_uidiv\n mov r6,r0\n mul r0,r5,r6\n sub r1,r4,r0\n mov r0,r6\n pop {r4-r6,pc}\n");

int strlen(const char*s){int n=0;while(s[n])n++;return n;}
static int slen(const char*s){return strlen(s);}
static void scopy(char*d,const char*s){while(*s)*d++=*s++;*d=0;}
static int seq(const char*a,const char*b){while(*a&&*a==*b){a++;b++;}return *a-*b;}
static int sncmp(const char*a,const char*b,int n){for(int i=0;i<n;i++){if(a[i]!=b[i])return a[i]-b[i];if(!a[i])return 0;}return 0;}
static char* sfind(const char*h,const char*n){int nl=slen(n);for(int i=0;h[i];i++){if(h[i]==n[0]&&!sncmp(h+i,n,nl))return (char*)h+i;}return 0;}
void* memset(void*d,int c,unsigned n){u8*p=d;while(n--)*p++=c;return d;}
void* memcpy(void*d,const void*s,unsigned n){u8*a=d;const u8*b=s;while(n--)*a++=*b++;return d;}
static void* mset(void*d,int c,int n){return memset(d,c,n);}
static void* mcpy(void*d,const void*s,int n){return memcpy(d,s,n);}
static int memcmp(const void*a,const void*b,int n){const u8*x=a,*y=b;for(int i=0;i<n;i++)if(x[i]!=y[i])return x[i]-y[i];return 0;}
static void put(const char*s){sys_write(2,s,slen(s));}
static void itoa(int v,char*b){if(v<0){*b++='-';v=-v;}char t[11];int i=10;t[i]=0;if(!v)t[--i]='0';while(v){t[--i]='0'+v%10;v/=10;}scopy(b,t+i);}
static void uhex(unsigned v,char*b){const char*h="0123456789abcdef";int i=8;b[i]=0;while(i--){b[i]=h[v&15];v>>=4;}}
static int patoi(const char*s){int v=0;while(*s>='0'&&*s<='9')v=v*10+*s++-'0';return v;}

/* ---------- SHA1 + HMAC ---------- */
typedef struct{u32 h[5];u64 len;u8 buf[64];int blen;}SHA1;
static void shablk(SHA1*c,const u8*p){
 u32 w[80],a,b,cc,d,e,f,k,tmp;int t;
 for(t=0;t<16;t++)w[t]=(p[t*4]<<24)|(p[t*4+1]<<16)|(p[t*4+2]<<8)|p[t*4+3];
 for(t=16;t<80;t++){w[t]=w[t-3]^w[t-8]^w[t-14]^w[t-16];w[t]=(w[t]<<1)|(w[t]>>31);}
 a=c->h[0];b=c->h[1];cc=c->h[2];d=c->h[3];e=c->h[4];
 for(t=0;t<80;t++){
  if(t<20){f=(b&cc)|(~b&d);k=0x5A827999;}
  else if(t<40){f=b^cc^d;k=0x6ED9EBA1;}
  else if(t<60){f=(b&cc)|(b&d)|(cc&d);k=0x8F1BBCDC;}
  else{f=b^cc^d;k=0xCA62C1D6;}
  tmp=((a<<5)|(a>>27))+f+e+k+w[t];
  e=d;d=cc;cc=(b<<30)|(b>>2);b=a;a=tmp;}
 c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;}
static void shainit(SHA1*c){c->h[0]=0x67452301;c->h[1]=0xEFCDAB89;c->h[2]=0x98BADCFE;c->h[3]=0x10325476;c->h[4]=0xC3D2E1F0;c->len=0;c->blen=0;}
static void shaupd(SHA1*c,const u8*p,int n){
 c->len+=n;
 while(n){int t=c->blen?(64-c->blen):64;if(t>n)t=n;
  mcpy(c->buf+c->blen,p,t);c->blen+=t;p+=t;n-=t;
  if(c->blen==64){shablk(c,c->buf);c->blen=0;}}}
static void shafin(SHA1*c,u8 out[20]){
 u32 bits=(u32)(c->len*8);u8 lb[8];u32 bb=bits;
 for(int i=7;i>=0;i--){lb[i]=(u8)(bb&0xff);bb>>=8;}
 u8 pad=0x80;shaupd(c,&pad,1);
 pad=0;while(c->blen!=56)shaupd(c,&pad,1);
 shaupd(c,lb,8);
 for(int i=0;i<5;i++){out[i*4]=c->h[i]>>24;out[i*4+1]=c->h[i]>>16;out[i*4+2]=c->h[i]>>8;out[i*4+3]=c->h[i];}}
static void sha1(const u8*p,int n,u8 out[20]){SHA1 c;shainit(&c);shaupd(&c,p,n);shafin(&c,out);}
/* hmac-sha1: key <= 64B (IPMI passwords fit; longer keys truncated per RFC for our use) */
static void hmac_sha1(const u8*key,int klen,const u8*msg,int mlen,u8 out[20]){
 u8 k[64],ipad[64],opad[64];mset(k,0,64);mcpy(k,key,klen>64?64:klen);
 for(int i=0;i<64;i++){ipad[i]=k[i]^0x36;opad[i]=k[i]^0x5c;}
 SHA1 c;shainit(&c);shaupd(&c,ipad,64);shaupd(&c,msg,mlen);shafin(&c,out);
 shainit(&c);shaupd(&c,opad,64);shaupd(&c,out,20);shafin(&c,out);}

static const char b64t[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void b64e(const u8*in,int n,char*out){
 int i,j=0;
 for(i=0;i<n;i+=3){
  int v=in[i]<<16|((i+1<n?in[i+1]:0)<<8)|(i+2<n?in[i+2]:0);
  out[j++]=b64t[v>>18];out[j++]=b64t[(v>>12)&63];
  out[j++]=i+1<n?b64t[(v>>6)&63]:'=';
  out[j++]=i+2<n?b64t[v&63]:'=';}
 out[j]=0;}

struct sockaddr_in_min{u16 fam;u16 port;u32 addr;u8 pad[8];};
#define HTONS(p) ((((p)&0xff)<<8)|(((p)>>8)&0xff))
#define LO_IP 0x0100007f /* 127.0.0.1 network order on LE */

/* discover our own LAN ip (replies to external ip are ~instant; loopback is slow) */
static u32 lan_ip(void){
 static const char ifs[4][7]={"eth0","br0","bond0","eth1"};
 int f=sys_socket(2,1,0);if(f<0)return LO_IP;
 for(int i=0;i<4;i++){
  u8 ifr[40];mset(ifr,0,sizeof ifr);mcpy(ifr,ifs[i],slen(ifs[i])+1);
  if(sc3(54,f,0x8915,(int)ifr)==0){sys_close(f);return *(u32*)(ifr+20);}}
 sys_close(f);return LO_IP;}

static int udp_rx(int fd,u8*b,int cap,int timeout_ms){
 /* select with timeout then recv */
 u32 rset[32];mset(rset,0,sizeof rset);rset[fd>>5]|=1u<<(fd&31);
 struct {int sec,usec;} tv;tv.sec=timeout_ms/1000;tv.usec=(timeout_ms%1000)*1000;
 if(sys_select(fd+1,rset,0,0,&tv)<=0)return-1;
 return srecvfrom(fd,b,cap);}

/* ---------- random ---------- */
static void rnd(u8*b,int n){
 int f=sys_open("/dev/urandom",0,0);
 if(f>=0){int g=0;while(g<n){int r=sys_read(f,b+g,n-g);if(r<=0)break;g+=r;}sys_close(f);return;}
 u32 v=sys_time()^((int)b);for(int i=0;i<n;i++){v=v*1103515245+12345;b[i]=v>>16;}}

/* ---------- RMCP+ client (integrity-only, conf=none) ---------- */
typedef struct{
 int sock;u32 lip;         /* local ipmi ip (127.0.0.1) */
 u32 localsid,mgmtsid;u8 crand[16],brand[16],guid[16];
 u8 k1[20];u32 seq;u8 rqseq,tag,confalg;
}RMCP;
static void rmcp_tx(RMCP*r,u8*pkt,int n){ /* send + resend until reply */
 struct sockaddr_in_min a;mset(&a,0,sizeof a);a.fam=2;a.port=HTONS(623);a.addr=r->lip;
 ssendto(r->sock,pkt,n,(void*)&a,sizeof a);}
static int rmcp_rx(RMCP*r,u8*b,int cap,int ms){return udp_rx(r->sock,b,cap,ms);}
static void wr32le(u8*p,u32 v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void wr16le(u8*p,int v){p[0]=v;p[1]=v>>8;}

/* send rmcp+ packet (no integrity) and wait for reply payload; returns payload len */
static int rmcp_call(RMCP*r,int ptype,const u8*payload,int plen,u8 sessid_be_unused,u8*out,int cap){
 u8 pkt[512];int o=0;
 mcpy(pkt+o,"\x06\x00\xff\x07",4);o+=4;
 pkt[o++]=6;pkt[o++]=(u8)ptype;
 wr32le(pkt+o,ptype==0x10?0:r->mgmtsid);o+=4;
 wr32le(pkt+o,0);o+=4;
 wr16le(pkt+o,plen);o+=2;
 mcpy(pkt+o,payload,plen);o+=plen;
 for(int t=0;t<3;t++){
  rmcp_tx(r,pkt,o);
  int n=rmcp_rx(r,out,cap,800);
  if(n>16)break;
  if(t==2)return -1;}
 int n2=((out[14]|(out[15]<<8))); /* payload len */
 if(n2>cap-16)n2=cap-16;
 if(n2<0)return -1;
 mcpy(out,out+16,n2); /* shift payload to front */
 return n2;}

static int rmcp_open(RMCP*r){
 r->sock=sys_socket(2,2,0); /* AF_INET,SOCK_DGRAM */
 if(r->sock<0)return -1;
 shrink_bufs(r->sock);set_to(r->sock,3);
 rnd((u8*)&r->localsid,4);r->tag=0;r->seq=0;r->rqseq=1;r->confalg=0;
 u8 p[40],out[300];
 p[0]=++r->tag;p[1]=0;p[2]=0;p[3]=0;wr32le(p+4,r->localsid);
 u8 algs[24]={0,0,0,8,1,0,0,0, 1,0,0,8,1,0,0,0, 2,0,0,8,0,0,0,0};
 mcpy(p+8,algs,24);
 int n=rmcp_call(r,0x10,p,32,0,out,sizeof out);
 if(n<12||out[1]!=0)return -2;
 r->mgmtsid=out[8]|out[9]<<8|out[10]<<16|out[11]<<24;
 if(n>=36)r->confalg=out[12+8+8+4];
 return 0;}

/* rakp1+rakp3 combined: verify password (RAKP2 authcode). returns 0 ok, -3 bad pass */
static int rmcp_auth(RMCP*r,const char*user,const char*pass){
 int ulen=slen(user);if(ulen>16)ulen=16;
 int plen=slen(pass);if(plen>20)plen=20;
 u8 p[64],out[300];
 rnd(r->crand,16);
 p[0]=++r->tag;p[1]=0;p[2]=0;p[3]=0;wr32le(p+4,r->mgmtsid);
 mcpy(p+8,r->crand,16);
 p[24]=4;p[25]=0;p[26]=0;p[27]=ulen;
 mcpy(p+28,user,ulen);
 int n=rmcp_call(r,0x12,p,28+ulen,0,out,sizeof out);
 if(n<40||out[0]!=r->tag||out[1]!=0)return -3;
 mcpy(r->brand,out+8,16);mcpy(r->guid,out+24,16);
 /* verify RAKP2 authcode: HMAC(pass, localsid|mgmtsid|crand|brand|guid|priv|ulen|user) */
 u8 hd[96];int o=0;
 wr32le(hd+o,r->localsid);o+=4;wr32le(hd+o,r->mgmtsid);o+=4;
 mcpy(hd+o,r->crand,16);o+=16;mcpy(hd+o,r->brand,16);o+=16;mcpy(hd+o,r->guid,16);o+=16;
 hd[o++]=4;hd[o++]=ulen;mcpy(hd+o,user,ulen);o+=ulen;
 u8 dig[20];hmac_sha1((u8*)pass,plen,hd,o,dig);
 if(memcmp(dig,out+40,20))return -3; /* bad password */
 /* SIK, K1 */
 u8 sk[64];o=0;mcpy(sk,r->crand,16);o+=16;mcpy(sk+o,r->brand,16);o+=16;
 sk[o++]=4;sk[o++]=ulen;mcpy(sk+o,user,ulen);o+=ulen;
 hmac_sha1((u8*)pass,plen,sk,o,dig); /* dig = SIK */
 {u8 ones[20];mset(ones,1,20);hmac_sha1(dig,20,ones,20,r->k1);}
 /* RAKP3 */
 u8 p3[64];u8 a3[20];
 o=0;mcpy(hd,r->brand,16);o+=16;wr32le(hd+o,r->localsid);o+=4;hd[o++]=4;hd[o++]=ulen;mcpy(hd+o,user,ulen);o+=ulen;
 hmac_sha1((u8*)pass,plen,hd,o,a3);
 p3[0]=++r->tag;p3[1]=0;p3[2]=0;p3[3]=0;wr32le(p3+4,r->mgmtsid);mcpy(p3+8,a3,20);
 n=rmcp_call(r,0x14,p3,28,0,out,sizeof out);
 if(n<8||out[1]!=0)return -4;
 /* verify RAKP4 authcode = HMAC(SIK, crand|mgmtsid|guid)[:12] */
 o=0;mcpy(hd,r->crand,16);o+=16;wr32le(hd+o,r->mgmtsid);o+=4;mcpy(hd+o,r->guid,16);o+=16;
 hmac_sha1(dig,20,hd,o,a3);
 if(n>=20&&memcmp(a3,out+8,12))return -4;
 return 0;}

/* in-session IPMI command. returns response data len or -1 / -cc */
static int rmcp_ipmi(RMCP*r,int netfn,int cmd,const u8*data,int dlen,u8*out,int cap){
 u8 pkt[512];int o=0;
 u8 rq[300];rq[0]=0x20;rq[1]=netfn<<2;
 int s1=(-(rq[0]+rq[1]))&0xff;rq[2]=s1;
 rq[3]=0x81;rq[4]=r->rqseq<<2;rq[5]=cmd;
 mcpy(rq+6,data,dlen);
 int s2=0;for(int i=3;i<6+dlen;i++)s2+=rq[i];rq[6+dlen]=(-s2)&0xff;
 int rqlen=7+dlen;
 r->rqseq=(r->rqseq+1)&0x3f;
 r->seq++;
 mcpy(pkt+o,"\x06\x00\xff\x07",4);o+=4;
 pkt[o++]=6;pkt[o++]=0x40; /* IPMI + integrity */
 wr32le(pkt+o,r->mgmtsid);o+=4;
 wr32le(pkt+o,r->seq);o+=4;
 wr16le(pkt+o,rqlen);o+=2;
 mcpy(pkt+o,rq,rqlen);o+=rqlen;
 int np=(o-2)%4;if(np)np=4-np;
 for(int i=0;i<np;i++)pkt[o++]=0xff;
 pkt[o++]=np;pkt[o++]=7;
 u8 dig[20];hmac_sha1(r->k1,20,pkt+4,o-4,dig);
 mcpy(pkt+o,dig,12);o+=12;
 u8 rb[600];
 for(int t=0;t<3;t++){
  rmcp_tx(r,pkt,o);
  int n=rmcp_rx(r,rb,sizeof rb,3000);
  if(n>30){
   /* verify hmac trailer: covers bytes 4..n-12 */
   u8 dg[20];hmac_sha1(r->k1,20,rb+4,n-4-12,dg);
   if(!memcmp(dg,rb+n-12,12))goto got;}
  if(t==2)return -1;}
 return -1;
got:;
 int plen=rb[14]|(rb[15]<<8);
 u8*pl=rb+16;
 if(plen<8||pl[0]!=0x81)return -1;
 int cc=pl[6];
 if(cc)return -0x100-cc;
 int dl=plen-8;if(dl>cap)dl=cap;
 mcpy(out,pl+7,dl);
 return dl;}

static int rmcp_init(RMCP*r,u32 ip){
 mset(r,0,sizeof *r);r->lip=ip;
 if(rmcp_open(r)<0)return -1;
 return 0;}
static void rmcp_close(RMCP*r){
 if(r->sock<0)return;
 u8 sid[4],out[32];wr32le(sid,r->mgmtsid);
 rmcp_ipmi(r,6,0x3c,sid,4,out,sizeof out);
 sys_close(r->sock);r->sock=-1;}

/* ---------- API session tokens ---------- */
/* token = b64(user|expiry) + "." + b64(hmac(bootkey, user|expiry)) — stateless */
static void bootkey(u8 k[20]){
 int f=sys_open("/var/ikvmkey",0,0);
 if(f>=0){int n=sys_read(f,k,20);sys_close(f);if(n==20)return;}
 rnd(k,20);
 f=sys_open("/var/ikvmkey",1|0x40,0600); /* O_WRONLY|O_CREAT */
 if(f>=0){sys_write(f,k,20);sys_close(f);}}
static void sess_make(char*out,const char*user,int ttl){
 u8 key[20];bootkey(key);
 char raw[64];int o=0;
 o+=slen(user)>16?16:slen(user);
 mcpy(raw,user,o);
 int exp=sys_time()+ttl;
 raw[o++]=0;
 char eb[16];itoa(exp,eb);scopy(raw+o,eb);o+=slen(eb);
 u8 dig[20];hmac_sha1(key,20,(u8*)raw,o,dig);
 char b1[64];b64e((u8*)raw,o,b1);
 char b2[40];b64e(dig,20,b2);
 scopy(out,b1);scopy(out+slen(out),"~");scopy(out+slen(out),b2);}
static int sess_check(const char*tok){
 const char*t=sfind(tok,"~");if(!t)return 0;
 int dl=(int)(t-tok);if(dl<3||dl>40)return 0;
 u8 raw[48];char db[64];
 int n=dl*3/4+4;
 /* decode part1 */
 {static const char*B="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int tbl[256];for(int i=0;i<256;i++)tbl[i]=-1;for(int i=0;i<64;i++)tbl[(u8)B[i]]=i;
  int acc=0,bits=0,j=0;
  for(int i=0;i<dl;i++){int v=tbl[(u8)tok[i]];if(v<0)break;acc=(acc<<6)|v;bits+=6;
   if(bits>=8){bits-=8;raw[j++]=acc>>bits;if(j>=(int)sizeof raw)break;}}
  n=j;}
 /* verify sig: find the NUL separator inside decoded blob */
 int si;for(si=0;si<n;si++)if(!raw[si])break;
 if(si>=n||si+1>=n)return 0;
 int exp=patoi((char*)raw+si+1);
 u8 key[20],dig[20];bootkey(key);hmac_sha1(key,20,raw,n,dig);
 char b2[40];b64e(dig,20,b2);
 if(seq((char*)t+1,b2))return 0;
 if(sys_time()>exp)return -1;
 return 1;}

/* ---------- http helpers ---------- */
static int sfull(int fd,const u8*b,int n){int o=0;while(o<n){int w=ssend(fd,b+o,n-o);if(w<=0)return-1;o+=w;}return 0;}
static void hdrs(int fd,int code,const char*ctype,int clen,const char*extra){
 char b[512];scopy(b,"HTTP/1.1 ");
 if(code==200)scopy(b+9,"200 OK");
 else if(code==302)scopy(b+9,"302 Found");
 else if(code==401)scopy(b+9,"401 Unauthorized");
 else if(code==404)scopy(b+9,"404 Not Found");
 else if(code==500)scopy(b+9,"500 Internal Error");
 scopy(b+slen(b),"\r\nContent-Type: ");scopy(b+slen(b),ctype);
 scopy(b+slen(b),"\r\nContent-Length: ");
 char cb[12];itoa(clen,cb);scopy(b+slen(b),cb);
 scopy(b+slen(b),"\r\nConnection: close\r\n");
 if(extra)scopy(b+slen(b),extra);
 scopy(b+slen(b),"\r\n");
 sfull(fd,(u8*)b,slen(b));}
static void resp_json(int fd,const char*j){
 hdrs(fd,200,"application/json",slen(j),0);
 sfull(fd,(u8*)j,slen(j));}
static void resp_err(int fd,int code,const char*msg){
 char j[128];scopy(j,"{\"error\":\"");scopy(j+slen(j),msg);scopy(j+slen(j),"\"}");
 hdrs(fd,code,"application/json",slen(j),0);sfull(fd,(u8*)j,slen(j));}

/* read headers; returns index of body start or -1; req buffer NUL-terminated */
static int http_hdrs(int fd,char*req,int cap){
 int n=0;
 while(n<cap-1){
  int r=srecv(fd,req+n,cap-1-n);
  if(r<=0)return-1;
  n+=r;req[n]=0;
  if(sfind(req,"\r\n\r\n"))return n;}
 return-1;}
static int hdr_val(const char*req,const char*name,char*out,int cap){
 /* header name must start a line and be followed by ':' */
 int nl=slen(name);
 const char*p=req;
 for(;;){
  p=sfind(p,name);
  if(!p)return -1;
  if((p==req||p[-1]=='\n')&&p[nl]==':')break;
  p++;}
 p+=nl+1;while(*p==' ')p++;
 int i=0;while(p[i]&&p[i]!='\r'&&p[i]!='\n'&&i<cap-1){out[i]=p[i];i++;}out[i]=0;
 return i;}
static int content_len(const char*req){
 char b[16];if(hdr_val(req,"Content-Length",b,sizeof b)<0)return 0;
 return patoi(b);}
static int cookie_val(const char*req,const char*name,char*out,int cap){
 char nm[48];scopy(nm,name);scopy(nm+slen(nm),"=");
 const char*p=sfind(req,"Cookie:");if(!p)return -1;
 const char*e=sfind(p,"\r\n");if(!e)e=p+slen(p);
 p=sfind(p,nm);if(!p||p>=e)return -1;
 p+=slen(nm);int i=0;
 while(p[i]&&p[i]!=';'&&p[i]!='\r'&&i<cap-1){out[i]=p[i];i++;}out[i]=0;
 return i;}

/* ---------- JSON builder ---------- */
typedef struct{char*b;int cap,len;}JS;
static void jb(JS*j,const char*s){int n=slen(s);if(j->len+n<j->cap-1){mcpy(j->b+j->len,s,n);j->len+=n;j->b[j->len]=0;}}
static void jc(JS*j,char c){if(j->len<j->cap-1){j->b[j->len++]=c;j->b[j->len]=0;}}
static void jnum(JS*j,int v){char b[12];itoa(v,b);jb(j,b);}
static void junum(JS*j,u32 v){char b[12],t[11];int i=10;t[i]=0;if(!v)t[--i]='0';while(v){t[--i]='0'+v%10;v/=10;}scopy(b,t+i);jb(j,b);}
static void jesc(JS*j,const char*s){for(;*s;s++){if(*s=='"'||*s=='\\')jc(j,'\\');jc(j,*s);}}

/* ---------- units / sensor tables ---------- */
static const char*unit_name(int u){
 switch(u){case 1:return "degC";case 2:return "degF";case 4:return "Volts";
 case 5:return "Amps";case 18:return "RPM";case 20:return "Watts";default:return "";}}
static int s10(int v){return v&0x200?v-1024:v;}
static int s8(int v){return v&0x80?v-256:v;}
static int s4(int v){return v&8?v-16:v;}

/* ---- GoAhead loopback proxy helpers (flash path + kvm token) ---- */
static int ga_conn(void){
 int f=sys_socket(2,1,0);if(f<0){put("ga sock fail\n");return-1;}
 shrink_bufs(f);set_to(f,10);
 struct sockaddr_in_min a;mset(&a,0,sizeof a);a.fam=2;a.port=HTONS(8080);a.addr=lan_ip();
 int c=sys_connect(f,(void*)&a,sizeof a);
 if(c<0){put("ga connect fail\n");sys_close(f);return-1;}
 return f;}
/* request to goahead; read full response into buf (small replies) */
static int ga_req(int post,const char*path,const char*cookie,const u8*body,int blen,u8*out,int cap){
 int f=ga_conn();if(f<0){put("ga conn fail\n");return-1;}
 char h[640];
 u32 lip=lan_ip();
 char ipb[20];{int i=0;for(int k=0;k<4;k++){itoa((lip>>(8*k))&0xff,ipb+i);i=slen(ipb);if(k<3)ipb[i++]='.';ipb[i]=0;}}
 scopy(h,post?"POST ":"GET ");scopy(h+slen(h),path);scopy(h+slen(h)," HTTP/1.1\r\nHost: ");scopy(h+slen(h),ipb);scopy(h+slen(h),":8080\r\nUser-Agent: bmcweb\r\nAccept: */*\r\nConnection: close\r\n");
 if(post){scopy(h+slen(h),"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: ");
  char cb[12];itoa(blen,cb);scopy(h+slen(h),cb);scopy(h+slen(h),"\r\n");}
 if(cookie&&*cookie){scopy(h+slen(h),"Cookie: SessionCookie=");scopy(h+slen(h),cookie);scopy(h+slen(h),"\r\n");}
 scopy(h+slen(h),"\r\n");
 int hl=slen(h);
 int merged=0;
 if(post&&blen&&hl+blen<(int)sizeof h){mcpy(h+hl,body,blen);hl+=blen;merged=1;} /* single write — goahead reads once */
 {char b[300];int m=hl>280?280:hl;for(int i=0;i<m;i++){char c=h[i];b[i]=(c>=32&&c<127)?c:'.';}b[m]=0;scopy(b+m,"\n");put("gaQ:");put(b);}
 if(sfull(f,(u8*)h,hl)<0){put("ga send fail\n");sys_close(f);return-1;}
 if(post&&blen&&!merged&&sfull(f,body,blen)<0){put("ga bodysend fail\n");sys_close(f);return-1;}
 int n=0;
 while(n<cap-1){int r=srecv(f,out+n,cap-1-n);if(r<=0)break;n+=r;}
 sys_close(f);out[n]=0;
 {char b[140];scopy(b,"ga ");scopy(b+slen(b),path);scopy(b+slen(b)," n=");itoa(n,b+slen(b));scopy(b+slen(b)," [");
  int m=n>40?40:n;for(int i=0;i<m;i++){char c=out[i];b[slen(b)]=(c>=32&&c<127)?c:'.';}
  scopy(b+slen(b),"]\n");put(b);}
 return n;}
#define ga_post(p,c,b,l,o,cap) ga_req(1,p,c,b,l,o,cap)
#define ga_get(p,c,o,cap) ga_req(0,p,c,0,0,o,cap)
/* extract "NAME' : 'val'" from WEBVAR reply */
static int wv_get(const u8*rsp,const char*name,char*out,int cap){
 char nm[64];scopy(nm,name);scopy(nm+slen(nm),"' : '");
 const char*p=sfind((char*)rsp,nm);if(!p)return-1;
 p+=slen(nm);int i=0;while(p[i]&&p[i]!='\''&&i<cap-1){out[i]=p[i];i++;}out[i]=0;
 return i;}

/* ---- per-request GoAhead session (for kvmtoken + flash) ---- */
/* stored in /var/ga_<ourtoken> so forked children can find it */
static int ga_login(const char*user,const char*pass,char*gacookie,int cap){
 u8 body[96],rsp[2048];
 scopy((char*)body,"WEBVAR_USERNAME=");scopy((char*)body+slen((char*)body),user);
 scopy((char*)body+slen((char*)body),"&WEBVAR_PASSWORD=");scopy((char*)body+slen((char*)body),pass);
 int n=ga_post("/rpc/WEBSES/create.asp",0,body,slen((char*)body),rsp,sizeof rsp);
 if(n>0&&wv_get(rsp,"SESSION_COOKIE",gacookie,cap)>=0)return 0;
 /* fallback: query-string variant */
 char q[160];scopy(q,"/rpc/WEBSES/create.asp?USER_NAME=");
 scopy(q+slen(q),user);scopy(q+slen(q),"&PASSWORD=");scopy(q+slen(q),pass);
 n=ga_get(q,0,rsp,sizeof rsp);
 if(n<0)return-1;
 return wv_get(rsp,"SESSION_COOKIE",gacookie,cap);}
static void ga_save(const char*tok,const char*ga){
 char p[80];scopy(p,"/var/ga_");int i=0;while(tok[i]&&tok[i]!='~'&&i<32){p[8+i]=tok[i];i++;}p[8+i]=0;
 int f=sys_open(p,1|0x40,0600);if(f>=0){sys_write(f,ga,slen(ga));sys_close(f);}}
static int ga_load(const char*tok,char*out,int cap){
 char p[80];scopy(p,"/var/ga_");int i=0;while(tok[i]&&tok[i]!='~'&&i<32){p[8+i]=tok[i];i++;}p[8+i]=0;
 int f=sys_open(p,0,0);if(f<0)return-1;
 int n=sys_read(f,out,cap-1);sys_close(f);if(n<=0)return-1;out[n]=0;return n;}

/* ---------- handlers ---------- */
#include "spa.inc" /* generated: static const char SPA[], #define SPA_LEN */

static void h_spa(int fd){
 hdrs(fd,200,"text/html",SPA_LEN,0);
 sfull(fd,(u8*)SPA,SPA_LEN);}

static void cred_save(const char*,const char*,const char*);
static void ga_save(const char*,const char*);
/* read request body: reuse bytes already received after headers (have-boff) */
static int body_read(int fd,const char*req,int boff,int have,char*b,int want){
 int pre=have-boff;if(pre<0)pre=0;if(pre>want)pre=want;
 mcpy(b,req+boff,pre);
 int got=pre;
 while(got<want){int r=srecv(fd,(u8*)b+got,want-got);if(r<=0)break;got+=r;}
 return got;}
static void h_login(int fd,const char*req,int bodyoff,int have){
 char u[24]={0},p[24]={0},ga[48]={0};
 /* body: u=..&p=.. (plain, small) */
 char b[128];int bl=content_len(req);if(bl>(int)sizeof b-1)bl=sizeof b-1;
 int got=body_read(fd,req,bodyoff,have,b,bl);
 b[got]=0;
 const char*ep=sfind(b,"&p=");int ul=ep?ep-(b+2):0;
 if(ul>0&&ul<24){mcpy(u,b+2,ul);u[ul]=0;}
 if(ep){int i=0;const char*q=ep+3;while(q[i]&&q[i]!='&'&&i<23){p[i]=q[i];i++;}p[i]=0;}
 if(!*u||!*p){resp_err(fd,401,"bad credentials");return;}
 /* password check = RAKP2 verify against the BMC's own user db */
 RMCP r;
 if(rmcp_init(&r,lan_ip())<0||rmcp_auth(&r,u,p)<0){if(r.sock>0)rmcp_close(&r);resp_err(fd,401,"invalid username or password");return;}
 rmcp_close(&r); /* never leak the session — BMC caps concurrent sessions */
 /* GoAhead session for kvm token + flash + legacy */
 if(ga_login(u,p,ga,sizeof ga)>=0){/* ok */}else ga[0]=0;
 char tok[160];sess_make(tok,u,8*3600);
 if(*ga)ga_save(tok,ga);
 cred_save(tok,u,p);
 char extra[260];
 scopy(extra,"Set-Cookie: IKVMSESS=");scopy(extra+slen(extra),tok);scopy(extra+slen(extra),";path=/\r\n");
 if(*ga){scopy(extra+slen(extra),"Set-Cookie: SessionCookie=");scopy(extra+slen(extra),ga);scopy(extra+slen(extra),";path=/\r\n");}
 char j[96];scopy(j,"{\"ok\":1,\"user\":\"");scopy(j+slen(j),u);scopy(j+slen(j),"\"}");
 hdrs(fd,200,"application/json",slen(j),extra);
 sfull(fd,(u8*)j,slen(j));}

static void h_logout(int fd,const char*req){
 char tok[200];
 if(cookie_val(req,"IKVMSESS",tok,sizeof tok)>=0){
  char pth[80];scopy(pth,"/var/ga_");int i=0;while(tok[i]&&tok[i]!='~'&&i<32){pth[8+i]=tok[i];i++;}pth[8+i]=0;
  sc1(87,(int)pth);} /* unlink */
 hdrs(fd,200,"application/json",7,"Set-Cookie: IKVMSESS=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/\r\nSet-Cookie: SessionCookie=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/\r\n");
 sfull(fd,(u8*)"{\"ok\":1}",7);}

static int authed(int fd,const char*req,char*tok){
 if(cookie_val(req,"IKVMSESS",tok,200)<0||sess_check(tok)<=0){resp_err(fd,401,"unauthorized");return 0;}
 return 1;}

static void cred_save(const char*tok,const char*user,const char*pass){
 u8 key[20];bootkey(key);
 char p[80];scopy(p,"/var/cr_");int i=0;while(tok[i]&&tok[i]!='~'&&i<32){p[8+i]=tok[i];i++;}p[8+i]=0;
 char buf[80];int o=slen(user);mcpy(buf,user,o);buf[o++]='|';
 for(int k=0;pass[k]&&o<79;k++)buf[o++]=pass[k]^key[k%20];
 int f=sys_open(p,1|0x40,0600);if(f>=0){sys_write(f,buf,o);sys_close(f);}}
static int cred_load(const char*tok,char*user,char*pass){
 u8 key[20];bootkey(key);
 char p[80];scopy(p,"/var/cr_");int i=0;while(tok[i]&&tok[i]!='~'&&i<32){p[8+i]=tok[i];i++;}p[8+i]=0;
 int f=sys_open(p,0,0);if(f<0)return-1;
 char buf[80];int n=sys_read(f,buf,sizeof buf-1);sys_close(f);if(n<=0)return-1;
 int u=0;while(u<n&&buf[u]!='|'){user[u]=buf[u];u++;}user[u]=0;
 int k=0;for(int i=u+1;i<n;i++)pass[k++]=buf[i]^key[(i-u-1)%20];pass[k]=0;
 return 0;}

static int ipmi_sess(RMCP*r,const char*tok){
 char u[24],p[24];
 if(cred_load(tok,u,p)<0)return-1;
 if(rmcp_init(r,lan_ip())<0)return-2;
 if(rmcp_auth(r,u,p)<0){rmcp_close(r);return-3;}
 return 0;}

static void h_host(int fd,const char*tok){
 RMCP r;char jb_[256];JS j={jb_,sizeof jb_,0};
 if(ipmi_sess(&r,tok)<0){resp_err(fd,500,"ipmi");return;}
 u8 d[64];int n=rmcp_ipmi(&r,0,0x01,0,0,d,sizeof d);
 jb(&j,"{\"power\":");if(n>0&&(d[0]&1))jb(&j,"\"on\"");else jb(&j,"\"off\"");
 jc(&j,',');
 jb(&j,"\"raw\":");jnum(&j,n>0?d[0]:-1);jc(&j,'}');
 rmcp_close(&r);resp_json(fd,jb_);}

static void h_sensors2(int fd,const char*tok){
 RMCP r;u8 d[600];u8 out[16*1024];JS j={(char*)out,sizeof out,0};
 if(ipmi_sess(&r,tok)<0){resp_err(fd,500,"ipmi");return;}
 jb(&j,"[");
 int recid=0,cnt=0,first=1;
 while(recid!=0xffff&&cnt<64){
  u8 rq[8];wr16le(rq,0);wr16le(rq+2,recid);rq[4]=0;rq[5]=255;
  /* need reservation id first */
  u8 rv[8];if(rmcp_ipmi(&r,0x0a,0x22,0,0,rv,sizeof rv)<2)break;
  wr16le(rq,rv[0]|rv[1]<<8);
  int n=rmcp_ipmi(&r,0x0a,0x23,rq,6,d,sizeof d);
  if(n<6)break;
  recid=d[0]|d[1]<<8;
  u8*rec=d+2;
  if(n<7||rec[3]!=1){cnt++;continue;}
  int sensnum=rec[7],stype=rec[12],unit2=rec[21];
  int M=s10(rec[24]|(rec[25]&3)<<8),B=s10(rec[26]|(rec[27]&3)<<8);
  int k1=s4(rec[29]&0xf),k2=s4(rec[29]>>4);
  int nl=rec[47]&0x3f;char name[20];if(nl>15)nl=15;mcpy(name,rec+48,nl);name[nl]=0;
  u8 rd[8];int rn=rmcp_ipmi(&r,0x04,0x2d,(u8[]){sensnum},1,rd,sizeof rd);
  int raw=rn>0?rd[0]:-1;
  /* value = (M*raw + B*10^k1)*10^k2 as fixed milli */
  int mv=M*raw*1000;
  int i;for(i=0;i<k1;i++)B*=10;for(i=0;i<-k1;i++)B/=10;
  mv+=B*1000;
  for(i=0;i<k2;i++)mv*=10;for(i=0;i<-k2;i++)mv/=10;
  if(!first)jc(&j,',');first=0;
  jb(&j,"{\"n\":");jnum(&j,sensnum);
  jb(&j,",\"name\":\"");jesc(&j,name);jc(&j,'"');
  jb(&j,",\"type\":");jnum(&j,stype);
  jb(&j,",\"raw\":");jnum(&j,raw);
  jb(&j,",\"mv\":");{char b[16];itoa((int)mv,b);jb(&j,b);}
  jb(&j,",\"u\":\"");jb(&j,unit_name(unit2));jc(&j,'"');
  if(rn>1){jb(&j,",\"evt\":");jnum(&j,rd[1]);}
  jc(&j,'}');
  cnt++;}
 jb(&j,"]");
 rmcp_close(&r);resp_json(fd,(char*)out);}

static void h_sel(int fd,const char*tok){
 put("sel0\n");
 RMCP r;u8 out[12*1024];JS j={(char*)out,sizeof out,0};
 if(ipmi_sess(&r,tok)<0){put("selE\n");resp_err(fd,500,"ipmi");return;}
 u8 info[32];int n=rmcp_ipmi(&r,0x0a,0x40,0,0,info,sizeof info);
 int total=n>3?(info[2]<<8|info[3]):0; /* bmc reports entries BE */
 if(total>512)total=0;
 {char b[24];scopy(b,"selinfo n=");itoa(n,b+slen(b));scopy(b+slen(b)," tot=");itoa(total,b+slen(b));scopy(b+slen(b),"\n");put(b);}
 jb(&j,"{\"total\":");jnum(&j,total);jb(&j,",\"events\":[");
 u8 rv[8];rmcp_ipmi(&r,0x0a,0x42,0,0,rv,sizeof rv); /* reserve sel */
 int resid=rv[0]|rv[1]<<8;
 int recid=0,cnt=0,first=1;
 while(recid!=0xffff&&cnt<256){
  u8 rq[8];wr16le(rq,resid);wr16le(rq+2,recid);rq[4]=0;rq[5]=16;
  u8 d[32];int m=rmcp_ipmi(&r,0x0a,0x43,rq,6,d,sizeof d);
  if(cnt<8){char b[40];scopy(b,"sel i=");itoa(cnt,b+slen(b));scopy(b+slen(b)," m=");itoa(m,b+slen(b));scopy(b+slen(b)," nxt=");itoa(m>1?(d[0]|d[1]<<8):-1,b+slen(b));scopy(b+slen(b),"\n");put(b);}
  if(m<18){char b[24];scopy(b,"selrec m=");itoa(m,b+slen(b));scopy(b+slen(b)," cnt=");itoa(cnt,b+slen(b));scopy(b+slen(b),"\n");put(b);break;}
  recid=d[0]|d[1]<<8;
  u8*e=d+2;
  int rid=e[0]|e[1]<<8;u32 ts=e[2]|e[3]<<8|e[4]<<16|e[5]<<24;
  int genid=e[6]|e[7]<<8,etype=e[9],snum=e[10],edir=e[11];
  if(!first)jc(&j,',');first=0;
  jb(&j,"{\"id\":");jnum(&j,rid);
  jb(&j,",\"ts\":");junum(&j,ts);
  jb(&j,",\"gen\":");jnum(&j,genid);
  jb(&j,",\"type\":");jnum(&j,etype);
  jb(&j,",\"snr\":");jnum(&j,snum);
  jb(&j,",\"d\":");jnum(&j,edir);jc(&j,'}');
  cnt++;}
 jb(&j,"]}");
 rmcp_close(&r);put("seldone\n");resp_json(fd,(char*)out);}

static void h_selclear(int fd,const char*tok){
 /* LAN refuses SEL-clear (cc=0xc7) — go via goahead's internal IPC */
 char ga[48];
 if(ga_load(tok,ga,sizeof ga)<0){resp_err(fd,500,"no bmc session");return;}
 u8 rsp[2048];
 int n=ga_get("/rpc/clearsel.asp",ga,rsp,sizeof rsp);
 int ok=(n>0&&sfind((char*)rsp,"HAPI_STATUS:0"))?1:0;
 resp_json(fd,ok?"{\"ok\":1}":"{\"ok\":0}");}

static void h_power(int fd,const char*tok,const char*req,int boff,int have){
 char b[32];int bl=content_len(req);if(bl>31)bl=31;
 int got=body_read(fd,req,boff,have,b,bl);b[got]=0;
 int act=patoi(sfind(b,"=")?sfind(b,"=")+1:b);
 RMCP r;
 if(ipmi_sess(&r,tok)<0){resp_err(fd,500,"ipmi");return;}
 u8 out[8];int rc=rmcp_ipmi(&r,0,0x02,(u8[]){(u8)act},1,out,sizeof out);
 rmcp_close(&r);
 resp_json(fd,rc>=0?"{\"ok\":1}":"{\"ok\":0}");}

static void h_identify(int fd,const char*tok,const char*req,int boff,int have){
 char b[32];int bl=content_len(req);if(bl>31)bl=31;
 int got=body_read(fd,req,boff,have,b,bl);b[got]=0;
 int sec=patoi(sfind(b,"=")?sfind(b,"=")+1:b);if(sec>255)sec=255;
 RMCP r;if(ipmi_sess(&r,tok)<0){resp_err(fd,500,"ipmi");return;}
 u8 out[8];rmcp_ipmi(&r,0,0x04,(u8[]){(u8)sec,0},2,out,sizeof out);
 rmcp_close(&r);resp_json(fd,"{\"ok\":1}");}

static void h_sys(int fd,const char*tok){
 RMCP r;u8 out[1024];JS j={(char*)out,sizeof out,0};
 if(ipmi_sess(&r,tok)<0){resp_err(fd,500,"ipmi");return;}
 u8 d[64];jb(&j,"{");
 if(rmcp_ipmi(&r,6,0x01,0,0,d,sizeof d)>=13){
  jb(&j,"\"fw\":");jc(&j,'"');jnum(&j,d[2]);jc(&j,'.');
  if(d[3]<10)jc(&j,'0');jnum(&j,d[3]);jc(&j,'"');
  jb(&j,",\"ipmi\":");jc(&j,'"');jnum(&j,d[4]&15);jc(&j,'.');jnum(&j,d[4]>>4);jc(&j,'"');
  jb(&j,",\"mfg\":");jnum(&j,d[6]|d[7]<<8|d[8]<<16);
  jb(&j,",\"prod\":");jnum(&j,d[9]|d[10]<<8|d[11]<<16|d[12]<<24);
  jb(&j,",\"devid\":");jnum(&j,d[0]);}
 /* FRU 0 */
 if(rmcp_ipmi(&r,0x0a,0x10,(u8[]){0},1,d,sizeof d)>=6){
  int sz=d[1]|d[2]<<8;
  jb(&j,",\"fru_size\":");jnum(&j,sz);
  jb(&j,",\"fru\":\"");
  int off=0;
  while(off<sz&&off<512){
   u8 rq[4];rq[0]=0;wr16le(rq+1,off);rq[3]=32;
   u8 fd2[64];int m=rmcp_ipmi(&r,0x0a,0x11,rq,4,fd2,sizeof fd2);
   if(m<1)break;
   int got=m-1;
   for(int i=0;i<got&&j.len<j.cap-4;i++){u8 c=fd2[1+i];jc(&j,(c>=32&&c<127)?c:'.');}
   off+=got;}
  jc(&j,'"');}
 jc(&j,'}');
 rmcp_close(&r);resp_json(fd,(char*)out);}

static void h_net(int fd,const char*tok){
 RMCP r;u8 out[512];JS j={(char*)out,sizeof out,0};
 if(ipmi_sess(&r,tok)<0){resp_err(fd,500,"ipmi");return;}
 jb(&j,"{");
 /* Get LAN Config: netfn 0x0c cmd 0x02, data: chan,param,revsel=0,blocksel=0 */
 u8 d[32];
 for(int i=0;i<5;i++){
  const char*nm;int sz,p;
  switch(i){case 0:p=3;nm="ip";sz=4;break;case 1:p=4;nm="ipsrc";sz=1;break;
   case 2:p=5;nm="mac";sz=6;break;case 3:p=6;nm="mask";sz=4;break;
   default:p=12;nm="gw";sz=4;break;}
  u8 rq[4]={1,(u8)p,0,0};
  if(rmcp_ipmi(&r,0x0c,0x02,rq,4,d,sizeof d)>=1+sz){
   if(i)jc(&j,',');jc(&j,'"');jb(&j,nm);jb(&j,"\":\"");
   if(sz==4){char b[20];int v=d[1];itoa(v,b);jb(&j,b);for(int k=1;k<4;k++){jc(&j,'.');itoa(d[1+k],b);jb(&j,b);}}
   else if(sz==6){for(int k=0;k<6;k++){if(k)jc(&j,':');char b[4];uhex(d[1+k],b);jb(&j,b+6);}}
   else{jnum(&j,d[1]);}
   jc(&j,'"');}}
 jc(&j,'}');
 rmcp_close(&r);resp_json(fd,(char*)out);}

static void h_kvmtoken(int fd,const char*tok){
 /* adviserd only accepts the jnlp arg[2] token (getsessiontoken's STOKEN is rejected) */
 char ga[48];ga[0]=0;ga_load(tok,ga,sizeof ga); /* optional */
 u8 rsp[4096];
 u32 lip=lan_ip();
 char ipb[20];{int i=0;for(int k=0;k<4;k++){itoa((lip>>(8*k))&0xff,ipb+i);i=slen(ipb);if(k<3)ipb[i++]='.';ipb[i]=0;}}
 char jp[160];scopy(jp,"/Java/jviewer.jnlp?EXTRNIP=");scopy(jp+slen(jp),ipb);scopy(jp+slen(jp),"&JNLPSTR=JViewer");
 int n=ga_get(jp,*ga?ga:0,rsp,sizeof rsp);
 if(n<=0){resp_err(fd,500,"token failed");return;}
 /* third <argument> is the ivtp token */
 char*p=(char*)rsp;char st[64];st[0]=0;
 for(int i=0;i<3&&p;i++){p=sfind(p,"<argument>");if(p)p+=10;}
 if(p){int i=0;while(p[i]&&p[i]!='<'&&i<63){st[i]=p[i];i++;}st[i]=0;}
 if(!st[0]){resp_err(fd,500,"token failed");return;}
 char j[160];scopy(j,"{\"token\":\"");scopy(j+slen(j),st);scopy(j+slen(j),"\"}");
 resp_json(fd,j);}

/* flash endpoints: stream-proxy to GoAhead :8080, identical semantics */
static void h_fwsimple(int fd,const char*tok,const char*garpc){
 char ga[48];
 if(ga_load(tok,ga,sizeof ga)<0){resp_err(fd,500,"no bmc session");return;}
 u8 rsp[4096];
 int n=ga_get(garpc,ga,rsp,sizeof rsp);
 if(n<0){resp_err(fd,500,"bmc rpc fail");return;}
 hdrs(fd,200,"application/octet-stream",n,0);sfull(fd,rsp,n);}

static void h_fwupload(int fd,const char*tok,const char*req,int boff){
 /* stream the multipart/octet body through to the stock upload endpoint 1:1 */
 char ga[48];
 if(ga_load(tok,ga,sizeof ga)<0){resp_err(fd,500,"no bmc session");return;}
 int cl=content_len(req);
 char ct[96];if(hdr_val(req,"Content-Type",ct,sizeof ct)<0)ct[0]=0;
 int g=ga_conn();if(g<0){resp_err(fd,500,"bmc unreachable");return;}
 char h[640];
 u32 lip=lan_ip();
 char ipb[20];{int i=0;for(int k=0;k<4;k++){itoa((lip>>(8*k))&0xff,ipb+i);i=slen(ipb);if(k<3)ipb[i++]='.';ipb[i]=0;}}
 scopy(h,"POST /page/UI_firmware_upload.html HTTP/1.1\r\nHost: ");scopy(h+slen(h),ipb);scopy(h+slen(h),":8080\r\nUser-Agent: bmcweb\r\nAccept: */*\r\nConnection: close\r\nContent-Length: ");
 char cb[16];itoa(cl,cb);scopy(h+slen(h),cb);
 scopy(h+slen(h),"\r\nCookie: SessionCookie=");scopy(h+slen(h),ga);
 if(*ct){scopy(h+slen(h),"\r\nContent-Type: ");scopy(h+slen(h),ct);}
 scopy(h+slen(h),"\r\n\r\n");
 if(sfull(g,(u8*)h,slen(h))<0){sys_close(g);resp_err(fd,500,"upload fail");return;}
 /* stream body: already-consumed tail first, then socket */
 int pre=slen(req)-boff;
 u8 buf[4096];
 int sent=0;
 const u8*bp=(const u8*)req+boff;
 while(sent<cl){
  int chunk;
  if(pre>0){chunk=pre<4096?pre:4096;if(sfull(g,bp,chunk)<0)break;bp+=chunk;pre-=chunk;sent+=chunk;continue;}
  int want=cl-sent;if(want>4096)want=4096;
  int r=srecv(fd,buf,want);
  if(r<=0)break;
  if(sfull(g,buf,r)<0)break;
  sent+=r;}
 if(sent<cl){sys_close(g);resp_err(fd,500,"upload truncated");return;}
 /* relay the (small) reply */
 u8 rsp[8192];int n=0;
 while(n<(int)sizeof rsp-1){int r=srecv(g,rsp+n,sizeof rsp-1-n);if(r<=0)break;n+=r;}
 sys_close(g);
 hdrs(fd,200,"application/octet-stream",n,0);if(n)sfull(fd,rsp,n);}

/* generic authenticated proxy to any goahead rpc/page.
   GET  /api/ga?p=<urlencoded /rpc/... path incl query>
   POST /api/ga  body: "<path>\n<raw body>"
   returns the raw response body (WEBVAR text or binary). */
static int urldec(char*s){char*d=s;while(*s){
 if(*s=='%'&&s[1]&&s[2]){int a=s[1],b=s[2];
  a=a>'9'?((a|32)-'a'+10):a-'0';b=b>'9'?((b|32)-'a'+10):b-'0';
  if(a<0||a>15||b<0||b>15){*d++=*s++;continue;}
  *d++=(a<<4)|b;s+=3;continue;}
 *d++=(*s=='+')?' ':*s;s++;}*d=0;return d-(char*)0;}
static void h_ga(int fd,const char*tok,const char*req,int boff,int have,int post){
 char ga[48];
 if(ga_load(tok,ga,sizeof ga)<0){resp_err(fd,500,"no bmc session");return;}
 u8 rsp[24*1024];
 char path[384];int blen=0;u8*body=0;
 if(post){
  /* body layout: <path>\n<urlencoded body> */
  u8 all[4096];int want=content_len(req);if(want>(int)sizeof all-1)want=sizeof all-1;
  int first=body_read(fd,req,boff,have,(char*)all,want);all[first]=0;
  char*nl=sfind((char*)all,"\n");if(!nl){resp_err(fd,400,"bad body");return;}
  int pl=nl-(char*)all;if(pl>=383)pl=383;mcpy(path,all,pl);path[pl]=0;
  body=nl+1;blen=first-pl-1;
 }else{
  const char*q=sfind(req,"p=");if(!q){resp_err(fd,400,"no path");return;}
  q+=2;int i=0;while(q[i]&&q[i]!=' '&&i<383){path[i]=q[i];i++;}path[i]=0;
  urldec(path);}
 if(!sfind(path,"/rpc/")&&!sfind(path,"/page/")&&!sfind(path,"/Java/")&&!sfind(path,"/cgi-bin/")){
  resp_err(fd,400,"bad path");return;}
 int n=ga_req(post,path,ga,body,blen,rsp,sizeof rsp);
 if(n<0){resp_err(fd,502,"rpc fail");return;}
 /* strip headers, relay body as octet-stream */
 char*bod=sfind((char*)rsp,"\r\n\r\n");
 const char*ct="application/octet-stream";
 if(bod){bod+=4;if(sfind((char*)rsp,"text"))ct="text/plain";}
 else bod=(char*)rsp;
 int bl=n-(bod-(char*)rsp);
 hdrs(fd,200,ct,bl,0);sfull(fd,(u8*)bod,bl);}

static void h_users(int fd,const char*tok){
 RMCP r;u8 out[2048];JS j={(char*)out,sizeof out,0};
 if(ipmi_sess(&r,tok)<0){resp_err(fd,500,"ipmi");return;}
 jb(&j,"[");int first=1;
 for(int uid=1;uid<=15;uid++){
  u8 d[32];
  if(rmcp_ipmi(&r,6,0x46,(u8[]){(u8)uid},1,d,sizeof d)<0)continue;
  d[16]=0;
  u8 acc[16];
  if(rmcp_ipmi(&r,6,0x44,(u8[]){1,(u8)uid},2,acc,sizeof acc)<0)continue;
  if(!first)jc(&j,',');first=0;
  jb(&j,"{\"id\":");jnum(&j,uid);
  jb(&j,",\"name\":\"");jesc(&j,(char*)d);jc(&j,34);
  jb(&j,",\"priv\":");jnum(&j,acc[3]&15);
  jb(&j,",\"en\":");jnum(&j,d[0]?1:0); /* populated account = enabled */
  jc(&j,125);}
 jb(&j,"]");
 rmcp_close(&r);resp_json(fd,(char*)out);}

/* ---------- WS bridge to adviserd ---------- */
static int ws_send(int fd,const u8*d,int len){
 u8 h[10];int hl=0;h[hl++]=0x82;
 if(len<126)h[hl++]=len;
 else if(len<65536){h[hl++]=126;h[hl++]=len>>8;h[hl++]=len;}
 else{h[hl++]=127;h[hl++]=0;h[hl++]=0;h[hl++]=0;h[hl++]=0;
      h[hl++]=(len>>24)&0xff;h[hl++]=(len>>16)&0xff;h[hl++]=(len>>8)&0xff;h[hl++]=len&0xff;}
 if(ssend(fd,h,hl)!=hl)return-1;
 return sfull(fd,d,len);}
static int rdfull(int fd,u8*b,int n){int g=0;while(g<n){int r=srecv(fd,b+g,n-g);if(r<=0)return-1;g+=r;}return g;}
static int ws_recv(int fd,u8*out,int cap){
 u8 h[14];
 if(rdfull(fd,h,2)<0)return-1;
 int op=h[0]&0x0f;u32 len=h[1]&0x7f;int masked=h[1]&0x80;
 int need=2;if(len==126)need+=2;else if(len==127)need+=8;
 if(masked)need+=4;
 if(rdfull(fd,h+2,need-2)<0)return-1;
 int o=2;
 if(len==126){len=(h[o]<<8)|h[o+1];o+=2;}
 else if(len==127){len=0;for(int i=0;i<8;i++)len=(len<<8)|h[o+i];o+=8;}
 u8 mask[4]={0,0,0,0};
 if(masked){mcpy(mask,h+o,4);o+=4;}
 if(len>(u32)cap){u32 left=len;u8 tmp[512];while(left){int w=left>512?512:left;if(rdfull(fd,tmp,w)<0)return-1;left-=w;}return 0;}
 if(rdfull(fd,out,len)<0)return-1;
 if(masked)for(int i=0;i<len;i++)out[i]^=mask[i&3];
 if(op==0x8)return-1;
 if(op==0x9){u8 pong[2]={0x8a,0x00};ssend(fd,pong,2);return 0;}
 if(op==0xA)return 0;
 return len;}

static void ws_bridge(int cfd){
 set_to(cfd,300); /* kvm idle ceiling; adviserd frames keep it alive */
 u8 wsbuf[4096],kbuf[4096];
 int kfd=sys_socket(2,1,0);
 if(kfd<0)goto done;
 shrink_bufs(kfd);shrink_bufs(cfd);
 {struct sockaddr_in_min a;mset(&a,0,sizeof a);a.fam=2;a.port=HTONS(7578);a.addr=LO_IP;
  if(sys_connect(kfd,(void*)&a,sizeof a)<0){
   const char*e="ERR KVM_CONNECT_FAIL";ws_send(cfd,(u8*)e,slen(e));goto done;}}
 {int one=1;sys_setsockopt(kfd,6,1,&one,4);}
 for(;;){
  u32 rset[32];mset(rset,0,sizeof rset);
  rset[cfd>>5]|=1u<<(cfd&31);rset[kfd>>5]|=1u<<(kfd&31);
  int mx=cfd>kfd?cfd:kfd;
  if(sys_select(mx+1,rset,0,0,0)<=0)break;
  if(rset[cfd>>5]&(1u<<(cfd&31))){
   int n=ws_recv(cfd,wsbuf,sizeof wsbuf);
   if(n<0)break;
   if(n>0){int o=0;while(o<n){int w=ssend(kfd,wsbuf+o,n-o);if(w<=0)goto done;o+=w;}}}
  if(rset[kfd>>5]&(1u<<(kfd&31))){
   int n=srecv(kfd,kbuf,sizeof kbuf);
   if(n<=0)break;
   if(ws_send(cfd,kbuf,n)<0)break;}}
done:
 sys_close(cfd);sys_close(kfd);}

/* ---------- router ---------- */
static void handle(int cfd){
 char req[8192];int n=http_hdrs(cfd,req,sizeof req);
 if(n<0)goto out;
 int boff=(int)(sfind(req,"\r\n\r\n")-req)+4;
 char method[8]={0},path[128]={0};
 {int i=0;while(req[i]&&req[i]!=' '&&i<7){method[i]=req[i];i++;}}
 {char*p=sfind(req," ")+1;int i=0;while(p[i]&&p[i]!=' '&&p[i]!='?'&&i<127){path[i]=p[i];i++;}path[i]=0;}
 /* WebSocket? */
 char up[32];
 if(hdr_val(req,"Upgrade",up,sizeof up)>=0&&sfind(up,"websocket")){
  char tok[200];
  /* auth via cookie OR ?sid= query */
  char*q=sfind(req,"sid=");
  int ok=0;
  if(q){q+=4;int i=0;while(q[i]&&q[i]!=' '&&q[i]!='&'&&i<199){tok[i]=q[i];i++;}tok[i]=0;ok=sess_check(tok)>0;}
  if(!ok&&cookie_val(req,"IKVMSESS",tok,sizeof tok)>=0)ok=sess_check(tok)>0;
  if(!ok){resp_err(cfd,401,"unauthorized");goto out;}
  char k[160];if(hdr_val(req,"Sec-WebSocket-Key",k,sizeof k)<0)goto out;
  char magic[220];scopy(magic,k);scopy(magic+slen(magic),"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  u8 dig[20];sha1((u8*)magic,slen(magic),dig);
  char acc[40];b64e(dig,20,acc);
  char rp[320];scopy(rp,"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
  scopy(rp+slen(rp),acc);scopy(rp+slen(rp),"\r\n\r\n");
  if(sfull(cfd,(u8*)rp,slen(rp))<0)goto out;
  ws_bridge(cfd);
  goto out;}
 int ispost=method[0]=='P';
 if(!seq(path,"/api/login")&&ispost){h_login(cfd,req,boff,n);goto out;}
 if(!seq(path,"/api/logout")){h_logout(cfd,req);goto out;}
 if(!seq(path,"/")&&!sncmp(method,"GET",3)){h_spa(cfd);goto out;} /* public */
 char tok[200];
 if(!authed(cfd,req,tok))goto out;
 if(!seq(path,"/api/host"))h_host(cfd,tok);
 else if(!seq(path,"/api/sensors"))h_sensors2(cfd,tok);
 else if(!seq(path,"/api/sel"))h_sel(cfd,tok);
 else if(!seq(path,"/api/sel/clear")&&ispost)h_selclear(cfd,tok);
 else if(!seq(path,"/api/power")&&ispost)h_power(cfd,tok,req,boff,n);
 else if(!seq(path,"/api/identify")&&ispost)h_identify(cfd,tok,req,boff,n);
 else if(!seq(path,"/api/sys"))h_sys(cfd,tok);
 else if(!seq(path,"/api/net"))h_net(cfd,tok);
 else if(!seq(path,"/api/kvmtoken"))h_kvmtoken(cfd,tok);
 else if(!seq(path,"/fw/time"))h_fwsimple(cfd,tok,"/rpc/setTimeEEPROM.asp");
 else if(!seq(path,"/fw/prep"))h_fwsimple(cfd,tok,"/rpc/prepflash.asp");
 else if(!seq(path,"/fw/verify"))h_fwsimple(cfd,tok,"/rpc/verifyimage.asp");
 else if(!seq(path,"/fw/start"))h_fwsimple(cfd,tok,"/rpc/startflash.asp?WEBVAR_PRESERVECFG=1");
 else if(!seq(path,"/fw/status"))h_fwsimple(cfd,tok,"/rpc/flashstatus.asp");
 else if(!seq(path,"/fw/upload")&&ispost)h_fwupload(cfd,tok,req,boff);
 else if(!seq(path,"/api/users"))h_users(cfd,tok);
 else if(!seq(path,"/api/ga"))h_ga(cfd,tok,req,boff,n,ispost);
 else if(!seq(path,"/api/bmc")){
  char j[96];scopy(j,"{\"bmc\":\"bmcweb/1.0\",\"stack\":\"rmcp+\"}");resp_json(cfd,j);}
 else resp_err(cfd,404,"not found");
out:
 sys_close(cfd);}

void _start(void){
 {int f=sys_open("/proc/self/oom_adj",1,0);if(f>=0){sys_write(f,"-17",3);sys_close(f);}}
 int s=sys_socket(2,1,0);
 shrink_bufs(s);
 {int one=1;sys_setsockopt(s,1,2,&one,4);}
 struct sockaddr_in_min a;mset(&a,0,sizeof a);a.fam=2;a.port=HTONS(80);a.addr=0;
 for(;;){
  if(sys_bind(s,(void*)&a,sizeof a)<0){put("bmcweb: bind :80 busy, retry\n");sys_nanosleep(2,0);continue;}
  break;}
 sys_listen(s,8);
 put("bmcweb :80 up\n");
 for(;;){
  while(sys_wait4(-1,0,1)>0){}   /* reap children, WNOHANG */
  int cfd=sys_accept(s,0,0);
  if(cfd<0)continue;
  set_to(cfd,15);
  int pid=sys_fork();
  if(pid==0){sys_close(s);handle(cfd);sys_exit(0);}
  sys_close(cfd);}
}
