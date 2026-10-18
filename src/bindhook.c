/* bindhook final — zero-dep, zero-log: redirect webgo binds 80→8080, 443→8443.
 * Direct OABI socketcall (nr=102) so no libc imports are needed at all. */
struct sockaddr_min { unsigned short fam; unsigned short port; unsigned int addr; char pad[8]; };

__asm__(".text\n"
".globl k_scall\n"
"k_scall: swi 0x900066\n bx lr\n");   /* __NR_socketcall = 102 */
int k_scall(int, void*);

int socket(int d,int t,int p){
    void* a[3]={(void*)(long)d,(void*)(long)t,(void*)(long)p};
    return k_scall(1,a);
}
int bind(int fd,const void* sa,int len){
    struct sockaddr_min t;
    const struct sockaddr_min* s=(const struct sockaddr_min*)sa;
    if(s&&s->fam==2){
        if(s->port==(unsigned short)0x5000){        /* htons(80) */
            __builtin_memcpy(&t,s,sizeof t);
            t.port=(unsigned short)0x901f;          /* htons(8080) */
            sa=&t;
        }else if(s->port==(unsigned short)0xbb01){  /* htons(443) */
            __builtin_memcpy(&t,s,sizeof t);
            t.port=(unsigned short)0x0120;          /* htons(8443) */
            sa=&t;
        }
    }
    void* a[3]={(void*)(long)fd,(void*)sa,(void*)(long)len};
    return k_scall(2,a);
}
int setsockopt(int fd,int l,int o,void*v,int vl){
    void* a[5]={(void*)(long)fd,(void*)(long)l,(void*)(long)o,v,(void*)(long)vl};
    return k_scall(14,a);
}
int listen(int fd,int b){
    void* a[2]={(void*)(long)fd,(void*)(long)b};
    return k_scall(4,a);
}
