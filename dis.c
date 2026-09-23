#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <errno.h>
#include <string.h>

#define M430_OPS_MASK 0xFC00U
#define M430_JMP_MASK 0xE000U
#define M430_JMP      0x2000U
#define M430_OPS      0x1000U
#define IS_JMP(code)    ((code&0xE000U) == 0x2000U)
#define IS_SINGLE(code) ((code&0xFC00U) == 0x1000U)

const char *aliases[] = {
	"pc",
	"sp",
	"sr",
	"cg",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
	NULL
};

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

typedef struct {
    char *mnemonic;
    char *operands;
    unsigned int length;
    unsigned short *bytes;
} insn_t;

void free_insn(insn_t *insn);
insn_t *dis_insn(unsigned short *text, unsigned int length);
void disassemble(unsigned short baddr, unsigned char *text, unsigned int length);
char *dis_operands(char **buf, unsigned char r, unsigned char asd, unsigned short **text, unsigned int *length);

char *append_str(char **dst, const char *str){
    char *tp;
    if(!*dst){
        if(!(*dst = malloc(strlen(str)+1))) return NULL;
        strcpy(*dst, str);
        return *dst;
    }
    if(!(tp = realloc(*dst, strlen(*dst)+strlen(str)+1))) return *dst;
    *dst = tp;
    strcpy((*dst)+strlen(*dst), str);
    return *dst;
}

int main(int argc, char **argv){
    struct stat binfo;
    unsigned char *bin;
    int fd;
    if(argc < 2) return 0;

    if(stat(argv[1], &binfo) < 0){
        dprintf(2, "stat(\"%s\"): %s\n", argv[1], strerror(errno));
        return 1;
    }
    if(!(bin = (unsigned char *)malloc(binfo.st_size+1))){
        dprintf(2, "malloc(): %s\n", strerror(errno));
        return 1;
    }

    if((fd = open(argv[1], O_RDONLY)) < 0){
        dprintf(2, "open(\"%s\"): %s\n", argv[1], strerror(errno));
        free(bin);
        return 1;
    }

    read(fd, bin, binfo.st_size);
    close(fd);

    disassemble(0x2400, bin, (unsigned int)binfo.st_size);
 
    free(bin);
    return 0;
}

void free_insn(insn_t *insn){
    if(insn){
        if(insn->mnemonic) free(insn->mnemonic);
        if(insn->operands) free(insn->operands);
        if(insn->bytes) free(insn->bytes);
        free(insn);
    }
}

void disassemble(unsigned short baddr, unsigned char *text, unsigned int length){
    insn_t *insn;   
    for(unsigned int pc = 0; pc < length;){
        if(!(insn = dis_insn((unsigned short *)(&text[pc]), length-pc))) return;
        printf("%04x: %s %s\n", pc+baddr, insn->mnemonic, insn->operands);
        pc += insn->length;
        free_insn(insn);
    }
}

insn_t *dis_insn(unsigned short *text, unsigned int length){
    char buf[16];
    insn_t *insn;
    unsigned int savlen;
    unsigned short cur = *text, offset;
    unsigned char opcode;

    if(length < 2 || !(insn = (insn_t *)calloc(1, sizeof(*insn)))){
        dprintf(2, "calloc(): %s\n", strerror(errno));
        return NULL;
    }
    insn->length = 2; 
    length -= 2;
    text++;
    savlen = length;

    if(IS_SINGLE(cur)){
        opcode = (cur>>7)&7;

        append_str(&insn->mnemonic, single_mnemonics[opcode]);
        if(cur&(1<<6)) append_str(&insn->mnemonic, ".b");

        insn->operands = dis_operands(&insn->operands, (cur&0xf), ((cur>>4)&3), &text, &length);
        if(savlen != length) insn->length += 2;
    }else if(IS_JMP(cur)){
        opcode = (cur>>0xa)&7;
        offset = (cur&0x200) ? 0xfc00|(cur&0x3ff) : (cur&0x3ff);
        offset = (offset*2)+2;

        append_str(&insn->mnemonic, jmp_mnemonics[opcode]);
        snprintf(buf, sizeof(buf), 
            (signed short)(offset) < 0 ? "-0x%x" : "+0x%x",
            (signed short)(offset) < 0 ? ~((signed short)(offset))+1 : offset
        );
        append_str(&insn->operands, buf);
    }else{
        opcode = (cur>>0xc)&0xf;
        if(opcode < 4){
            free(insn);
            return NULL;
        }
        append_str(&insn->mnemonic, double_mnemonics[opcode-4]);
        if(cur&(1<<6)) append_str(&insn->mnemonic, ".b");

        insn->operands = dis_operands(&insn->operands, ((cur>>8)&0xf), ((cur>>4)&3), &text, &length);
        if(savlen != length){
            insn->length += 2;
            savlen = length;
        }
        append_str(&insn->operands, ", ");
        insn->operands = dis_operands(&insn->operands, (cur&0xf), ((cur>>7)&1), &text, &length);
        if(savlen != length) insn->length += 2;
    }
    
    return insn;
}

char *dis_operands(char **buf, unsigned char r, unsigned char asd, unsigned short **text, unsigned int *length){
    unsigned short word;
    char fbuf[32];
    switch(asd){
        case 0:
            if(r == 3) append_str(buf, "#0");
            else append_str(buf, aliases[r]);
            return *buf;
        case 1:
            if(r == 3){
                append_str(buf, "#1");
                return *buf;
            }

            word = **text;
            *text++;
            *length -= 2;
            if(!r) snprintf(fbuf, sizeof(fbuf), "0x%x", word);
            else if(r == 2) snprintf(fbuf, sizeof(fbuf), "&0x%x", word);
            else snprintf(fbuf, sizeof(fbuf), "0x%x(%s)", word, aliases[r]);

            append_str(buf, fbuf);
            return *buf;
        case 2:
            if(r == 2) append_str(buf, "#4");
            else if(r == 3) append_str(buf, "#2");
            else{
                snprintf(fbuf, sizeof(fbuf), "@%s", aliases[r]);
                append_str(buf, fbuf);
            }
            return *buf;
        case 3:
            if(r == 2) append_str(buf, "#8");
            else if(r == 3) append_str(buf, "#-1");
            else if(!r){
                word = **text;
                *text++;
                *length -= 2;

                if((signed short)word < 0){
                    word = (~(signed short)(word))+1;
                    snprintf(fbuf, sizeof(fbuf), "#-0x%x", word);
                }else snprintf(fbuf, sizeof(fbuf), "#0x%x", word);
                append_str(buf, fbuf);
            } else{
                snprintf(fbuf, sizeof(fbuf), "@%s+", aliases[r]);
                append_str(buf, fbuf);
            }
            return *buf;
        default:
            return NULL;
    }
    return NULL;
}
