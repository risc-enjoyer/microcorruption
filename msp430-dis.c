/* Implement proper support for the addressing mode bits As and Ad */
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

char asmbuf[128];
#define add_asmstr(buf, str, bufsz) (strncpy(buf+strlen(buf), str, (bufsz-strlen(buf))))
int dis_operand(unsigned char r, unsigned char asd, unsigned short *text, off_t tlen){
	unsigned char as = asd>>1;
	if(r == 2 && as > 1){
		if(as == 2) add_asmstr(asmbuf, " #4", sizeof(asmbuf));
		else add_asmstr(asmbuf, " #8", sizeof(asmbuf));
		return 0;
	}else if(r == 3){
		switch(as){
			case 1:
				add_asmstr(asmbuf, " #1", sizeof(asmbuf));
				break;
			case 2:
				add_asmstr(asmbuf, " #2", sizeof(asmbuf));
				break;
			case 3:
				add_asmstr(asmbuf, " #0xffff", sizeof(asmbuf));
				break;
			default:
				add_asmstr(asmbuf, " #0", sizeof(asmbuf));
				break;
		}
		return 0;
	}

	if(!asd){
		snprintf(asmbuf+strlen(asmbuf), sizeof(asmbuf)-strlen(asmbuf), " %s", aliases[r]);
		return 0;
	}else if(asd == 3){
		if(tlen < 2) return -1;
		switch(r){
			case 0:
				snprintf(asmbuf+strlen(asmbuf), sizeof(asmbuf)-strlen(asmbuf), " 0x%x", *text);
				break;
			case 2:
				snprintf(asmbuf+strlen(asmbuf), sizeof(asmbuf)-strlen(asmbuf), " &0x%x", *text);
				break;
			default:
				snprintf(asmbuf+strlen(asmbuf), sizeof(asmbuf)-strlen(asmbuf), " 0x%x(%s)", *text, aliases[r]);
				break;
		}
		return 1;
	}

	if(as == 2) snprintf(asmbuf+strlen(asmbuf), sizeof(asmbuf)-strlen(asmbuf), " @%s", aliases[r]);
	else if(as == 3){
		if(!r){
			snprintf(asmbuf+strlen(asmbuf), sizeof(asmbuf)-strlen(asmbuf),
				(*(signed short *)text) < 0 ? " #-0x%x" : " #0x%x",
				(*(signed short *)text) < 0 ? (~(*(signed short *)text))+1 : *(signed short *)text
			);
			return 1;
		}
		snprintf(asmbuf+strlen(asmbuf), sizeof(asmbuf)-strlen(asmbuf), " @%s+", aliases[r]);
	}
	return 0;
}

char *dis(unsigned short *text, off_t tlen, off_t *consumed){
	unsigned char ad, as, opcode, bw;
	unsigned short c, offset, mc = *text;
	unsigned short sreg = 0x10, dreg = 0x10;

	*consumed = 0;
	if(tlen < 2) return NULL;

	memset(asmbuf, 0, sizeof(asmbuf));
	*consumed += 2;
	if(IS_SINGLE(mc)){
		opcode = (mc>>7)&7;
		ad = (mc>>4)&3;
		bw = (mc>>6)&1;
		sreg = mc&0xf;

		strncpy(asmbuf, single_mnemonics[opcode], sizeof(asmbuf));
		if(bw) strncpy(asmbuf+strlen(asmbuf), ".b", (sizeof(asmbuf)-strlen(asmbuf)));
		if(dis_operand(sreg, ad, text+1, tlen-2) > 0) *consumed += 2;
	}else if(IS_JMP(mc)){
		c = (mc>>0xa)&7;
		offset = mc&0x3ff;
		offset = 2+((offset&0x200) ? (offset*2)|0xfc00 : (offset*2));

		strncpy(asmbuf, jmp_mnemonics[c], sizeof(asmbuf));
		snprintf(asmbuf+strlen(asmbuf), (sizeof(asmbuf)-strlen(asmbuf)), 
			((signed short)offset) < 0 ? " -0x%x" : " +0x%x",
			((signed short)offset) < 0 ? (unsigned short)(~offset)+1 : offset
		);
	}else{
		opcode = ((mc>>0xc)&0xf);
		if(opcode < 4) return NULL;
		sreg = (mc>>8)&0xf;
		ad = (mc>>7)&1;
		bw = (mc>>6)&1;
		as = (mc>>4)&3;
		dreg = mc&0xf;

		strncpy(asmbuf, double_mnemonics[opcode-4], sizeof(asmbuf));
		if(bw) strncpy(asmbuf+strlen(asmbuf), ".b", (sizeof(asmbuf)-strlen(asmbuf)));
		if(dis_operand(sreg, (as<<1)|ad, text+1, tlen-2) > 0) *consumed += 2;
		asmbuf[strlen(asmbuf)] = ',';
		if(dis_operand(dreg, ad, text+1, tlen-2) > 0) *consumed += 2;
	}
	return asmbuf;
}

int main(void){
	struct stat bs = {0};
	off_t pc, consumed;
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

	for(pc = 0; pc < bs.st_size;){
		if((asmstr = dis((unsigned short *)&buf[pc], bs.st_size-pc, &consumed)))
			printf("%08lx:  %s\n", 0x2400+pc, asmstr);
		pc += consumed;
	}

	free(buf);
	return 0;
}
