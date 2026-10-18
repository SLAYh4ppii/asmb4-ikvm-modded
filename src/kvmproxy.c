/* kvmproxy_min.c — WebSocket <-> TCP bridge for ASMB4 AST2050 BMC, NOLIBC.
 *
 * Same wire behavior as kvmproxy.c but built without libc: direct ARM EABI
 * syscalls only. Static binary target < 16 KiB so it fits the root cramfs
 * free space.
 *
 * Build: arm-linux-gnueabi-gcc -nostdlib -static -Os -o kvmproxy kvmproxy_min.c
 *
 * Listens on :5900 (WS), bridges to KVM_HOST:7578 (local adviserd).
 */
typedef unsigned int u32; typedef unsigned short u16; typedef unsigned char u8;
typedef unsigned long long u64;

/* ---------- raw ARM EABI syscalls (svc #0, nr in r7) ---------- */
#define SYS_exit    1
#define SYS_read    3
#define SYS_write   4
#define SYS_close   6
#define SYS_fcntl   55
#define SYS_select  142   /* _newselect (verified in card's libc: svc 0x90008e) */
#define SYS_socketcall 102 /* OABI socket multiplexer — no native nrs on 2.6.15 */
/* socketcall subfunction codes */
#define SOC_SOCKET     1
#define SOC_BIND       2
#define SOC_CONNECT    3
#define SOC_LISTEN     4
#define SOC_ACCEPT     5
#define SOC_SEND       9
#define SOC_RECV       10
#define SOC_SETSOCKOPT 14

/* OABI kernel (2.6.15): syscall nr is encoded in the svc immediate
   (opcode 0xEF900000+nr) — NOT in r7. Implemented as .word so gas
   evaluates the constant itself. */
#define _SC0(c) ({register int r0 asm("r0");asm volatile(".word " #c :"=r"(r0)::"memory");r0;})
#define _SC1(c,a) ({register int r0 asm("r0")=(a);asm volatile(".word " #c :"=r"(r0):"0"(r0):"memory");r0;})
#define _SC2(c,a,b) ({register int r0 asm("r0")=(a),r1 asm("r1")=(b);asm volatile(".word " #c :"=r"(r0):"0"(r0),"r"(r1):"memory");r0;})
#define _SC3(c,a,b,cc) ({register int r0 asm("r0")=(a),r1 asm("r1")=(b),r2 asm("r2")=(cc);asm volatile(".word " #c :"=r"(r0):"0"(r0),"r"(r1),"r"(r2):"memory");r0;})
#define _SC5(c,a,b,cc,d,e) ({register int r0 asm("r0")=(a),r1 asm("r1")=(b),r2 asm("r2")=(cc),r3 asm("r3")=(d),r4 asm("r4")=(e);asm volatile(".word " #c :"=r"(r0):"0"(r0),"r"(r1),"r"(r2),"r"(r3),"r"(r4):"memory");r0;})
#define sc0(n)      _SC0(0xEF900000+n)
#define sc1(n,a)    _SC1(0xEF900000+n,a)
#define sc2(n,a,b)  _SC2(0xEF900000+n,a,b)
#define sc3(n,a,b,c) _SC3(0xEF900000+n,a,b,c)
#define sc5(n,a,b,c,d,e) _SC5(0xEF900000+n,a,b,c,d,e)

#define sys_exit(x)   sc1(1,x)
#define sys_read(f,b,n) sc3(3,f,(int)b,n)
#define sys_write(f,b,n) sc3(4,f,(int)b,n)
#define sys_close(f)  sc1(6,f)
/* socket ops via socketcall(102) — args passed as pointer to int array */
static int socketcall(int c,int*a){return sc2(102,c,(int)a);}
static int sys_socket(int d,int t,int p){int x[3]={d,t,p};return socketcall(SOC_SOCKET,x);}
static int sys_bind(int f,void*a,int l){int x[3]={f,(int)a,l};return socketcall(SOC_BIND,x);}
static int sys_listen(int f,int b){int x[2]={f,b};return socketcall(SOC_LISTEN,x);}
static int sys_accept(int f,void*a,int l){int x[3]={f,(int)a,l};return socketcall(SOC_ACCEPT,x);}
static int sys_connect(int f,void*a,int l){int x[3]={f,(int)a,l};return socketcall(SOC_CONNECT,x);}
static int sys_setsockopt(int f,int l,int o,void*v,int n){int x[5]={f,l,o,(int)v,n};return socketcall(SOC_SETSOCKOPT,x);}
static void shrink_bufs(int f){int b=4096;sys_setsockopt(f,1,7,&b,4);sys_setsockopt(f,1,8,&b,4);} /* SOL_SOCKET: SO_SNDBUF=7 SO_RCVBUF=8 — kernel alloc pressure on this ~30MB card */
#define sys_select(n,r,w,e,t) sc5(142,n,(int)r,(int)w,(int)e,(int)t)

/* ---------- mini libc ---------- */
int strlen(const char*s){int n=0;while(s[n])n++;return n;}
static int slen(const char*s){return strlen(s);}
static void scopy(char*d,const char*s){while(*s)*d++=*s++;*d=0;}
static int sncmp(const char*a,const char*b,int n){for(int i=0;i<n;i++){if(a[i]!=b[i])return a[i]-b[i];if(!a[i])return 0;}return 0;}
static char* sfind(const char*h,const char*n){int nl=slen(n);for(int i=0;h[i];i++){if(h[i]==n[0]&&!sncmp(h+i,n,nl))return (char*)h+i;}return 0;}
/* gcc may emit implicit calls to these — provide them */
void* memset(void*d,int c,unsigned n){u8*p=d;while(n--)*p++=c;return d;}
void* memcpy(void*d,const void*s,unsigned n){u8*a=d;const u8*b=s;while(n--)*a++=*b++;return d;}
static void* mset(void*d,int c,int n){return memset(d,c,n);}
static void* mcpy(void*d,const void*s,int n){return memcpy(d,s,n);}

static void put(const char*s){sys_write(2,s,slen(s));}
static void putn(unsigned v){char b[11];int i=10;b[i]=0;if(!v){put("0");return;}while(v){b[--i]='0'+v%10;v/=10;}put(b+i);}
/* socket I/O MUST go through socketcall SEND/RECV — sys_write/sys_read on a
   socket fd fail (-EFAULT/-EBADF) in this process context on the 2.6.15-ami
   kernel while socketcall works. Verified on-card: write() lost the 101
   response; socketcall(SEND) delivered it. */
static int ssend(int f,const void*b,int n){int x[4]={f,(int)b,n,0};return socketcall(SOC_SEND,x);}
static int srecv(int f,void*b,int n){int x[4]={f,(int)b,n,0};return socketcall(SOC_RECV,x);}

/* ---------- SHA1 ---------- */
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
 u32 bits=(u32)(c->len*8);          /* messages < 4GB — u32 suffices */
 u8 lb[8];u32 bb=bits;
 for(int i=7;i>=0;i--){lb[i]=(u8)(bb&0xff);bb>>=8;}
 u8 pad=0x80;shaupd(c,&pad,1);
 pad=0;while(c->blen!=56)shaupd(c,&pad,1);
 shaupd(c,lb,8);
 for(int i=0;i<5;i++){out[i*4]=c->h[i]>>24;out[i*4+1]=c->h[i]>>16;out[i*4+2]=c->h[i]>>8;out[i*4+3]=c->h[i];}}
static const char b64t[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void b64e(const u8*in,int n,char*out){
 int i,j=0;
 for(i=0;i<n;i+=3){
  int v=in[i]<<16|((i+1<n?in[i+1]:0)<<8)|(i+2<n?in[i+2]:0);
  out[j++]=b64t[v>>18];out[j++]=b64t[(v>>12)&63];
  out[j++]=i+1<n?b64t[(v>>6)&63]:'=';
  out[j++]=i+2<n?b64t[v&63]:'=';}
 out[j]=0;}

/* ---------- WS framing ---------- */
static int ws_send(int fd,const u8*d,int len){
 u8 h[10];int hl=0;h[hl++]=0x82;
 if(len<126)h[hl++]=len;
 else if(len<65536){h[hl++]=126;h[hl++]=len>>8;h[hl++]=len;}
 else{h[hl++]=127;h[hl++]=0;h[hl++]=0;h[hl++]=0;h[hl++]=0;
      h[hl++]=(len>>24)&0xff;h[hl++]=(len>>16)&0xff;h[hl++]=(len>>8)&0xff;h[hl++]=len&0xff;}
 if(ssend(fd,h,hl)!=hl)return -1;
 int o=0;while(o<len){int w=ssend(fd,d+o,len-o);if(w<=0)return-1;o+=w;}
 return 0;}
static int rdfull(int fd,u8*b,int n){
 int g=0;while(g<n){int r=srecv(fd,b+g,n-g);if(r<=0)return-1;g+=r;}return g;}
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
 if(len>(u32)cap){ /* drain+drop */
  u32 left=len;u8 tmp[512];
  while(left){int w=left>512?512:left;if(rdfull(fd,tmp,w)<0)return-1;left-=w;}
  return 0;}
 if(rdfull(fd,out,len)<0)return-1;
 if(masked)for(int i=0;i<len;i++)out[i]^=mask[i&3];
 if(op==0x8)return-1;
 if(op==0x9){u8 pong[2]={0x8a,0x00};ssend(fd,pong,2);return 0;}
 if(op==0xA)return 0;
 return len;}

/* ---------- server ---------- */
#define BUFSZ 4096  /* stack-local in serve() — NO .bss LOAD segment: the 2.6.15
                     kernel SIGKILLs at exec if the zero-fill bss mapping can't
                     be backed on this ~30MB card (no OOM log, process never runs) */

struct sockaddr_in_min{u16 fam;u16 port;u32 addr;u8 pad[8];};

static int handshake(int fd){
 char req[4096];int n=0;
 while(n<4090){
  int r=srecv(fd,req+n,4090-n);
  if(r<=0)return-1;
  n+=r;req[n]=0;
  if(sfind(req,"\r\n\r\n"))break;}
 const char*k=sfind(req,"Sec-WebSocket-Key");
 if(!k)return-1;
 k+=17;while(*k==' '||*k==':')k++;
 char key[128];int i=0;while(k[i]&&k[i]!='\r'&&i<120){key[i]=k[i];i++;}key[i]=0;
 char magic[160];scopy(magic,key);scopy(magic+slen(magic),"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
 u8 dig[20];SHA1 c;shainit(&c);shaupd(&c,(u8*)magic,slen(magic));shafin(&c,dig);
 char acc[40];b64e(dig,20,acc);
 char resp[300];
 scopy(resp,"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
 scopy(resp+slen(resp),acc);scopy(resp+slen(resp),"\r\n\r\n");
 if(ssend(fd,resp,slen(resp))!=slen(resp))return-1;
 return 0;}

static void serve(int cfd,u32 kvm_ip){
 u8 wsbuf[BUFSZ],kbuf[BUFSZ];
 int kfd=sys_socket(2,1,0);           /* AF_INET=2, SOCK_STREAM=1 */
 if(kfd<0)goto done;
 shrink_bufs(kfd);shrink_bufs(cfd);
 struct sockaddr_in_min a;mset(&a,0,sizeof a);
 a.fam=2;a.port=(7578>>8)|((7578&0xff)<<8);a.addr=kvm_ip; /* BE order */
 if(sys_connect(kfd,(void*)&a,sizeof a)<0){
  const char*e="ERR KVM_CONNECT_FAIL";ws_send(cfd,(u8*)e,slen(e));goto done;}
 int one=1;sys_setsockopt(kfd,6,1,&one,4); /* IPPROTO_TCP,TCP_NODELAY */
 for(;;){
  u32 rset[32];for(int i=0;i<32;i++)rset[i]=0;
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

void _start(void){
 /* protect from oom-killer first: open("/proc/self/oom_adj",O_WRONLY) + write "-17" */
 {int f=sc3(5,(int)"/proc/self/oom_adj",1,0);
  if(f>=0){sc3(4,f,(int)"-17",3);sc1(6,f);}}
 int port=5900;
 u32 kvm_ip=0x0100007f; /* 127.0.0.1 in network byte order on LE cpu */
 int s=sys_socket(2,1,0);
 shrink_bufs(s);
 int one=1;sys_setsockopt(s,1,2,&one,4); /* SOL_SOCKET,SO_REUSEADDR */
 struct sockaddr_in_min a;mset(&a,0,sizeof a);
 a.fam=2;a.port=(5900>>8)|((5900&0xff)<<8);a.addr=0;
 if(sys_bind(s,(void*)&a,sizeof a)<0){put("bind fail\n");sys_exit(1);}
 sys_listen(s,4);
 put("kvmproxy_min :5900 -> 127.0.0.1:7578\n");
 for(;;){
  int cfd=sys_accept(s,0,0);
  if(cfd<0)continue;
  if(handshake(cfd)<0){sys_close(cfd);continue;}
  serve(cfd,kvm_ip);}
}
