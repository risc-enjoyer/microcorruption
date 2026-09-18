#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define BIN "./dec.bin"

#define M430_OPS_MASK 0xFC00U
#define M430_JMP_MASK 0xE000U
#define M430_JMP      0x2000U
#define M430_OPS      0x1000U
#define IS_JMP(code)    ((code&0xE000U) == 0x2000U)
#define IS_SINGLE(code) ((code&0xFC00U) == 0x1000U)

const char *jmp_mnemonics[] = {
    "jnz",
    "jz",
    "jlo",
    "jhs",
    "jn",
    "jge",
    "jl",
    "jmp",
    NULL
};
const char *single_mnemonics[] = {
    "rrc",
    "swpb",
    "rra",
    "sxt",
    "push",
    "call",
    "reti",
    NULL
};
const char *double_mnemonics[] = {
    "mov",
    "add",
    "addc",
    "subc",
    "sub",
    "cmp",
    "dadd",
    "bit",
    "bic",
    "bis",
    "xor",
    "and",
    NULL
};

char asmbuf[64];
char *dis(unsigned short mc){
    memset(asmbuf, 0, sizeof(asmbuf));

    if(IS_SINGLE(mc)){
        strncpy(asmbuf, single_mnemonics[(mc>>0x7)&0x7], sizeof(asmbuf));
        if(mc&(1<<6)) strncat(asmbuf, ".b", sizeof(asmbuf)-strlen(asmbuf));
        snprintf(asmbuf+strlen(asmbuf), sizeof(asmbuf)-strlen(asmbuf), " r%u", mc&0xf);

    }else if(IS_JMP(mc)){
        strncpy(asmbuf, jmp_mnemonics[(mc>>0xa)&0x7], sizeof(asmbuf));
        snprintf(asmbuf+strlen(asmbuf), sizeof(asmbuf)-strlen(asmbuf), " 0x%04x", (mc&0x3ff)*2);
    }else{
        strncpy(asmbuf, double_mnemonics[((mc>>0xc)&0xf)-4], sizeof(asmbuf));
        if(mc&(1<<6)) strncat(asmbuf, ".b", sizeof(asmbuf)-strlen(asmbuf));
        snprintf(asmbuf+strlen(asmbuf), sizeof(asmbuf)-strlen(asmbuf), " r%u, r%u", (mc>>8)&0xf, (mc&0xf));
    }

    return asmbuf;
}

int main(void){
    struct stat bs = {0};
    off_t pc;
    char *buf, *asmstr;
    int fd;

    if(stat(BIN, &bs) < 0) return -1;
    if((fd = open(BIN, O_RDONLY)) < 0) return -1;
    
    if(!(buf = calloc(1, bs.st_size+1))){
        close(fd);
        return -1;
    }

    read(fd, buf, bs.st_size);
    close(fd);

    for(pc = 0; pc < bs.st_size; pc += 2){
        if((asmstr = dis(*(unsigned short *)(&buf[pc]))))
            printf("%08lx:  %s\n", pc, asmstr);
    }

    free(buf);
    return 0;
}
