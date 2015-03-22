/*
 *  x86-64 code generator for TCC
 *
 *  Copyright (c) 2008 Shinichiro Hamaji
 *
 *  Based on i386-gen.c by Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef TARGET_DEFS_ONLY

/* number of available registers */
#define NB_REGS         25
#define NB_ASM_REGS     8

/* a register can belong to several classes. The classes must be
   sorted from more general to more precise (see gv2() code which does
   assumptions on it). */
#define RC_INT     0x0001 /* generic integer register */
#define RC_FLOAT   0x0002 /* generic float register */
#define RC_RAX     0x0004
#define RC_RCX     0x0008
#define RC_RDX     0x0010
#define RC_ST0     0x0080 /* only for long double */
#define RC_R8      0x0100
#define RC_R9      0x0200
#define RC_R10     0x0400
#define RC_R11     0x0800
#define RC_XMM0    0x1000
#define RC_XMM1    0x2000
#define RC_XMM2    0x4000
#define RC_XMM3    0x8000
#define RC_XMM4    0x10000
#define RC_XMM5    0x20000
#define RC_XMM6    0x40000
#define RC_XMM7    0x80000
#define RC_FLAGS  0x100000 /* check vtop->r to see which flag */
#define RC_IRET    RC_RAX /* function return: integer register */
#define RC_LRET    RC_RDX /* function return: second integer register */
#define RC_FRET    RC_XMM0 /* function return: float register */
#define RC_QRET    RC_XMM1 /* function return: second float register */

/* pretty names for the registers */
enum {
    TREG_RAX = 0,
    TREG_RCX = 1,
    TREG_RDX = 2,
    TREG_RSP = 4,
    TREG_RSI = 6,
    TREG_RDI = 7,

    TREG_R8  = 8,
    TREG_R9  = 9,
    TREG_R10 = 10,
    TREG_R11 = 11,

    TREG_XMM0 = 16,
    TREG_XMM1 = 17,
    TREG_XMM2 = 18,
    TREG_XMM3 = 19,
    TREG_XMM4 = 20,
    TREG_XMM5 = 21,
    TREG_XMM6 = 22,
    TREG_XMM7 = 23,

    TREG_ST0 = 24,

    TREG_MEM = 0x20,
};

#define REX_BASE(reg) (((reg) >> 3) & 1)
#define REG_VALUE(reg) ((reg) & 7)

/* return registers for function */
#define REG_IRET TREG_RAX /* single word int return register */
#define REG_LRET TREG_RDX /* second word return register (for long long) */
#define REG_FRET TREG_XMM0 /* float return register */
#define REG_QRET TREG_XMM1 /* second float return register */

/* defined if function parameters must be evaluated in reverse order */
#define INVERT_FUNC_PARAMS

/* pointer size, in bytes */
#define PTR_SIZE 8

/* long double size and alignment, in bytes */
#define LDOUBLE_SIZE  16
#define LDOUBLE_ALIGN 16
/* maximum alignment (for aligned attribute support) */
#define MAX_ALIGN     16

/******************************************************/
/* ELF defines */

#define EM_TCC_TARGET EM_X86_64

/* relocation type for 32 bit data relocation */
#define R_DATA_32   R_X86_64_32
#define R_DATA_PTR  R_X86_64_64
#define R_JMP_SLOT  R_X86_64_JUMP_SLOT
#define R_COPY      R_X86_64_COPY

#define ELF_START_ADDR 0x08048000
#define ELF_PAGE_SIZE  0x1000

/******************************************************/
#else /* ! TARGET_DEFS_ONLY */
/******************************************************/
#include "tcc.h"
#include <assert.h>

ST_DATA const int reg_classes[NB_REGS] = {
    /* eax */ RC_INT | RC_RAX,
    /* ecx */ RC_INT | RC_RCX,
    /* edx */ RC_INT | RC_RDX,
    /* rbx, callee-saved */ 0,
    0,
    0,
    RC_INT,
    RC_INT,
    RC_INT | RC_R8,
    RC_INT | RC_R9,
    RC_INT | RC_R10,
    RC_INT | RC_R11,
    /* %r12, callee-saved */ 0,
    /* %r13, callee-saved */ 0,
    /* %r14, callee-saved */ 0,
    /* %r15, callee-saved */ 0,
    /* xmm0 */ RC_FLOAT | RC_XMM0,
    /* xmm1 */ RC_FLOAT | RC_XMM1,
    /* xmm2 */ RC_FLOAT | RC_XMM2,
    /* xmm3 */ RC_FLOAT | RC_XMM3,
    /* xmm4 */ RC_FLOAT | RC_XMM4,
    /* xmm5 */ RC_FLOAT | RC_XMM5,
    /* xmm6 an xmm7 are included so gv() can be used on them,
       but they are not tagged with RC_FLOAT because they are
       callee saved on Windows */
    RC_XMM6,
    RC_XMM7,
    /* st0 */ RC_ST0
};

static unsigned long func_sub_sp_offset;
static int func_ret_sub;

#if 0 /* no last instructions */
#define ib() do { } while(0)
#define check_nth_last_instruction(n, c, length) do { (void)(n); (void)(c); (void)(length); } while(0)
#else

static int last_instruction_boundary[16] = { 0, };

void ib(void)
{
    check_baddies(-1, 0);

    if(last_instruction_boundary[0] == ind)
	return;

    int i;
    for(i=14; i>=0; i--) {
        last_instruction_boundary[i+1] = last_instruction_boundary[i];
    }
    last_instruction_boundary[0] = ind;
}

/* undo count instruction barriers */
void uib(int count)
{
    int i;
    while(count--) {
	ind = last_instruction_boundary[0];
	for(i=0; i<=14; i++) {
	    last_instruction_boundary[i] = last_instruction_boundary[i+1];
	}
	last_instruction_boundary[15] = 0;
    }
}

void commit_instructions(void)
{
    int ind1 = ind;
    uib(16);
    ind = ind1;
    uncache_values();
}

int check_nth_last_instruction_mask(int n, unsigned long long c, unsigned long long mask, int length)
{
    int previb = n ? last_instruction_boundary[n-1] : ind;
    if((previb - last_instruction_boundary[n]) != length) {
        return 0;
    }

    int i=0;

    while(i<length) {
        if((c&mask&0xff) != (cur_text_section->data[last_instruction_boundary[n]+i]&mask&0xff))
            return 0;
        i++;
        c>>=8;
	mask>>=8;
    }

    return 1;
}

int check_nth_last_instruction(int n, unsigned long long c, int length)
{
    int previb = n ? last_instruction_boundary[n-1] : ind;
    if((previb - last_instruction_boundary[n]) != length) {
        return 0;
    }

    int i=0;

    while(i<length) {
        if((c&0xff) != (cur_text_section->data[last_instruction_boundary[n]+i]&0xff))
            return 0;
        i++;
        c>>=8;
    }

    return 1;
}

void dump_ibs(void)
{
    int i=0;
    int n=0;

    int prev_ib = ind;
    for(n=0; n<16 && last_instruction_boundary[n]; n++) {
        int ib = last_instruction_boundary[n];

        fprintf(stderr, "instruction %3d at %5d: ", n, ib);

        while(ib<prev_ib) {
            fprintf(stderr, "%02x ", cur_text_section->data[ib++]);
        }
        prev_ib = last_instruction_boundary[n];

        fprintf(stderr, "\n");
    }
}

static int flags_used_counter = 0;

int flags_used(void)
{
    if(flags_used_counter)
	return 1;

    if (vtop >= vstack && ((vtop->r & VT_VALMASK) == VT_CMP ||
			   (vtop->r & VT_VALMASK) == VT_JMP ||
			   (vtop->r & VT_VALMASK) == VT_JMPI))
	return 1;

    return 1;

    /* XXX can values on the stack further down use flags? */
    return 0;
}

/* returns 1 only if flags_okay, to indicate inverted return value */
int check_baddies(int clobber_reg, int flags_okay)
{
    /* mov $0x0, %eax -> xor %eax,%eax, but only if flags aren't used. */
    if (!flags_used() && check_nth_last_instruction(0, 0xb8, 5)) {
        uib(1);
	memset(cur_text_section->data + ind, 0, 5);
	
        g(0x31);
        g(0xc0);
        ib();
    }

    /*  80886b4:       89 c0                   mov    %eax,%eax */

    if (check_last_instruction(0xc089, 2)) {
	ind -= 2;
	uib(1);
    }

    /*
      * 0x0000000000d6a931:	b8 00 00 00 00		mov    $0x0,%eax
     *  0x0000000000d2b867:	0f 94 c0		sete   %al
     *  0x0000000000d2b86a:	85 c0			test   %eax,%eax
     */
    if (flags_okay &&
	(clobber_reg == TREG_RAX) &&
	check_last_instruction(0xc085, 2) &&
	check_nth_last_instruction(1, 0xc0940f, 3) &&
	check_nth_last_instruction(2, 0xb8, 5)) {

      return 0;
	ind -= 10;
	uib(3);
	
	ib();
	memset(cur_text_section->data + ind, 0, 10);

	return 1;
    }

    /*
     *  0x0000000000d2b862:	b8 00 00 00 00		mov    $0x0,%eax
     *  0x0000000000d2b867:	0f 94 c0		sete   %al
     *  0x0000000000d2b86a:	85 c0			test   %eax,%eax
     *  0x0000000000d2b86c:	0f 84 2a 00 00 00	je     0xd2b89c
     */

    if (check_last_instruction(0x840f, 6) &&
	check_nth_last_instruction(1, 0xc085, 2) &&
	check_nth_last_instruction(2, 0xc0940f, 3) &&
	check_nth_last_instruction(3, 0xb8, 5)) {
    }


    /*
     * 0x0000000001eb4a0c:	b8 00 00 00 00		mov    $0x0,%eax
     * 0x0000000001eb4a11:	0f 94 c0		sete   %al
     * 0x0000000001eb4a14:	85 c0			test   %eax,%eax
     *
     * 0x0000000001eb4a16:	0f 84 27 00 00 00	je     0x1eb4a43
     */

    /* jmpq blah -> jmp blah. Actually difficult to do. */

    /*
     *    0x0000000000fe861f:   0f 84 05 00 00 00       je     0xfe862a
     *    0x0000000000fe8625:   e9 07 00 00 00  jmpq   0xfe8631
     *    0x0000000000fe862a:   31 c0   xor    %eax,%eax
     *    0x0000000000fe862c:   e9 05 00 00 00  jmpq   0xfe8636
     *    0x0000000000fe8631:   b8 01 00 00 00  mov    $0x1,%eax
     *    0x0000000000fe8636:   85 c0   test   %eax,%eax
     *
     *    <check vtop depends only on E flag>
     */

    /*
     *  A very wordy nop:
     *
     * 0x0000000000be82d8:	0f 84 07 00 00 00	je     0xbe82e5
     * 0x0000000000be82de:	b8 00 00 00 00		mov    $0x0,%eax
     * 0x0000000000be82e3:	eb 05			jmp    0xbe82ea
     * 0x0000000000be82e5:	b8 01 00 00 00		mov    $0x1,%eax
     * 0x0000000000be82ea:	85 c0			test   %eax,%eax
     *
     *    <check vtop depends only on E flag>
     * This is generated by Perl expressions of the form if((x) ? 1 : 0) { ... }
     */

    if (check_nth_last_instruction(0, 0xc085, 2) &&
        check_nth_last_instruction(1, 0x01b8, 5) &&
        check_nth_last_instruction(2, 0x05eb, 2) &&
        check_nth_last_instruction(3, 0xb8, 5) &&
        check_nth_last_instruction(4, 0x07840f, 6)) {
      return 0;

        uib(5);
	memset(cur_text_section->data + ind, 0, 6+5+2+5+2);
    }

    /*
     *  A very wordy nop, second variant:
     *
     * 0x0000000000dba323:	0f 84 05 00 00 00	je     0xdba32e
     * 0x0000000000dba329:	e9 07 00 00 00		jmpq   0xdba335
     * 0x0000000000dba32e:	31 c0			xor    %eax,%eax
     * 0x0000000000dba330:	e9 05 00 00 00		jmpq   0xdba33a
     * 0x0000000000dba335:	b8 01 00 00 00		mov    $0x1,%eax
     * 0x0000000000dba33a:	85 c0			test   %eax,%eax
     *
     *    <check vtop depends only on E flag>
     * This is generated by Perl expressions of the form if((x) ? 1 : 0) { ... }
     */

    if (check_nth_last_instruction(0, 0xc085, 2) &&
        check_nth_last_instruction(1, 0x01b8, 5) &&
        check_nth_last_instruction(2, 0x05e9, 5) &&
        check_nth_last_instruction(3, 0xc031, 2) &&
        check_nth_last_instruction(4, 0x07e9, 5) &&
        check_nth_last_instruction(5, 0x05840f, 6)) {

      return 0;
        uib(6);
	memset(cur_text_section->data + ind, 0, 6+5+2+5+5+2);
    }

    /*
     *  A very wordy not. With a t:
     *
     * 0x0000000000b2f9ac:	0f 85 05 00 00 00	jne    0xb2f9b7
     * 0x0000000000b2f9b2:	e9 07 00 00 00		jmpq   0xb2f9be
     * 0x0000000000b2f9b7:	31 c0			xor    %eax,%eax
     * 0x0000000000b2f9b9:	e9 05 00 00 00		jmpq   0xb2f9c3
     * 0x0000000000b2f9be:	b8 01 00 00 00		mov    $0x1,%eax
     * 0x0000000000b2f9c3:	85 c0			test   %eax,%eax
     *
     *    <check vtop depends only on E flag>
     * This is generated by Perl expressions of the form if((x) ? 1 : 0) { ... }
     */

    if (check_nth_last_instruction(0, 0xc085, 2) &&
        check_nth_last_instruction(1, 0x01b8, 5) &&
        check_nth_last_instruction(2, 0x05e9, 5) &&
        check_nth_last_instruction(3, 0xc031, 2) &&
        check_nth_last_instruction(4, 0x07e9, 5) &&
        check_nth_last_instruction(5, 0x05850f, 6)) {
      return 0;

	if (flags_okay) {
	    uib(6);

	    return 1 ^ check_baddies(clobber_reg, 1);
	}
    }

    /*
     * 81c28f2:	48 89 01 111 101 f8          	mov    %rdi,-0x8(%rbp)
     * 81c28f6:	48 8b 01 000 101 f8          	mov    -0x8(%rbp),%rax
     */

    if (0 &&
	check_nth_last_instruction_mask(0, 0x00408b48, 0x00c0ffff, 4) &&
	check_nth_last_instruction_mask(1, 0x00708948, 0x00c0ffff, 4)) {
	int offset1 = cur_text_section->data[ind - 5];
	int offset2 = cur_text_section->data[ind - 1];

	if (offset1 == offset2) {
	    int reg12 = REG_VALUE(cur_text_section->data[ind - 6]);
	    int reg22 = REG_VALUE(cur_text_section->data[ind - 2]);

	    if (reg12 == reg22) {
		int reg11 = REG_VALUE(cur_text_section->data[ind - 6] >> 3);
		int reg21 = REG_VALUE(cur_text_section->data[ind - 2] >> 3);

		uib(1);

		if (reg11 != reg21) {
		    g(0x48);
		    g(0x8b);
		    g(0xc0 | (reg21 << 3) | reg11);
		}
	    }
	}
    }

    /*
     *  81c0d6c:	0f 84 05 00 00 00    	je     81c0d77 <Perl_sv_2num+0x29>
     *  81c0d72:	e9 09 00 00 00       	jmpq   81c0d80 <Perl_sv_2num+0x32>
     *
     * impossible to catch because of committed instructions, but should be jne 81c0d80.
     */

    if(check_nth_last_instruction_mask(0, 0xe9, 0xff, 5) &&
       check_nth_last_instruction_mask(1, 0x05840f, 0xffffff, 6)) {
    }


    return 0;
}

int check_last_instruction(unsigned int c, int length)
{
    if(last_instruction_boundary[0] != ind - length) {
        return 0;
    }

    int i=0;

    while(c) {
        if((c&0xff) != (cur_text_section->data[last_instruction_boundary[0]+i]&0xff))
            return 0;
        i++;
        c>>=8;
    }

    return 1;
}
#endif

/* XXX: make it faster ? */
void g(int c)
{
    int ind1;
    ind1 = ind + 1;
    if (ind1 > cur_text_section->data_allocated)
        section_realloc(cur_text_section, ind1);
    cur_text_section->data[ind] = c;
    ind = ind1;
}

void o(unsigned int c)
{
    while (c) {
        g(c);
        c = c >> 8;
    }
}

void gen_le16(int v)
{
    g(v);
    g(v >> 8);
}

void gen_le32(int c)
{
    g(c);
    g(c >> 8);
    g(c >> 16);
    g(c >> 24);
}

void gen_le64(int64_t c)
{
    g(c);
    g(c >> 8);
    g(c >> 16);
    g(c >> 24);
    g(c >> 32);
    g(c >> 40);
    g(c >> 48);
    g(c >> 56);
}

/* bitsize is the "maximum" bitsize according to 64 > 8 > 32/16 > 0,
   where 0 is for floats and other legacy instructions. */
void orex(int bitsize, int r, int r2, int b)
{
    int emit = bitsize == 64;
    if (bitsize == 8 && r >= 4)
	emit = 1;
    if (bitsize == 8 && r2 >= 4)
	emit = 1;
    int rex = 0x40 | REX_BASE(r) | (REX_BASE(r2) << 2) | ((bitsize == 64) << 3);
    if (rex != 0x40)
	emit = 1;
    ib();
    if ((r & VT_VALMASK) >= VT_CONST)
        r = 0;
    if ((r2 & VT_VALMASK) >= VT_CONST)
        r2 = 0;
    if (emit)
        o(rex);
    o(b);
}

void orex_always(int ll, int r, int r2, int b)
{
    ib();
    if ((r & VT_VALMASK) >= VT_CONST)
        r = 0;
    if ((r2 & VT_VALMASK) >= VT_CONST)
        r2 = 0;
    o(0x40 | REX_BASE(r) | (REX_BASE(r2) << 2) | (ll << 3));
    o(b);
}

/* always emit rex prefix. */
void orex4(int ll, int r3, int r, int r2, int b)
{
    ib();
    if ((r & VT_VALMASK) >= VT_CONST)
        r = 0;
    if ((r2 & VT_VALMASK) >= VT_CONST)
        r2 = 0;
    o(0x40 | REX_BASE(r) | (REX_BASE(r2) << 2) | (ll << 3) | (REX_BASE(r3)<<1));
    o(b);
}

/* output a symbol and patch all calls to it */
int gsym_addr(int t, int a)
{
    int n, *ptr;
    int ret = 0;
    while (t) {
        ptr = (int *)(cur_text_section->data + t);
        n = *ptr; /* next value */
        *ptr = a - t - 4;
        t = n;
	ret++;
    }
    return ret;
}

int gsym(int t)
{
    commit_instructions();

    return gsym_addr(t, ind);
}

int gsym_nocommit(int t)
{
    return gsym_addr(t, ind);
}

/* retrieve the current instruction index, committing all instructions so far to keep it valid */

int get_index(void)
{
    commit_instructions();

    return ind;
}

/* psym is used to put an instruction with a data field which is a
   reference to a symbol. It is in fact the same as oad ! */
#define psym oad

static int is64_type(int t)
{
    return ((t & VT_BTYPE) == VT_PTR ||
            (t & VT_BTYPE) == VT_FUNC ||
            (t & VT_BTYPE) == VT_LLONG);
}

/* instruction + 4 bytes data. Return the address of the data */
ST_FUNC int oad(int c, int s)
{
    int ind1;

    o(c);
    ind1 = ind + 4;
    if (ind1 > cur_text_section->data_allocated)
        section_realloc(cur_text_section, ind1);
    *(int *)(cur_text_section->data + ind) = s;
    s = ind;
    ind = ind1;
    return s;
}

ST_FUNC void gen_addr32(int r, Sym *sym, int c)
{
    if (r & VT_SYM)
        greloc(cur_text_section, sym, ind, R_X86_64_32);
    gen_le32(c);
}

/* output constant with relocation if 'r & VT_SYM' is true */
ST_FUNC void gen_addr64(int r, Sym *sym, int64_t c)
{
    if (r & VT_SYM)
        greloc(cur_text_section, sym, ind, R_X86_64_64);
    gen_le64(c);
}

/* output constant with relocation if 'r & VT_SYM' is true */
ST_FUNC void gen_addrpc32(int r, Sym *sym, int c)
{
    if (r & VT_SYM)
        greloc(cur_text_section, sym, ind, R_X86_64_PC32);
    gen_le32(c-4);
}

/* output got address with relocation */
static void gen_gotpcrel(int r, Sym *sym, int c)
{
#ifndef TCC_TARGET_PE
    Section *sr;
    ElfW(Rela) *rel;
    greloc(cur_text_section, sym, ind, R_X86_64_GOTPCREL);
    sr = cur_text_section->reloc;
    rel = (ElfW(Rela) *)(sr->data + sr->data_offset - sizeof(ElfW(Rela)));
    rel->r_addend = -4;
#else
    printf("picpic: %s %x %x | %02x %02x %02x\n", get_tok_str(sym->v, NULL), c, r,
        cur_text_section->data[ind-3],
        cur_text_section->data[ind-2],
        cur_text_section->data[ind-1]
        );
    greloc(cur_text_section, sym, ind, R_X86_64_PC32);
#endif
    gen_le32(0);
        /* we use add c, %xxx for displacement */
    if (c == 1) {
	orex(64, r, 0, 0xff);
	o(0xc0 + REG_VALUE(r));
    } else if (c == -1) {
	orex(64, r, 0, 0xff);
	o(0xd0 + REG_VALUE(r));
    } else if (c) {
        orex(64, r, 0, 0x81);
        o(0xc0 + REG_VALUE(r));
        gen_le32(c);
    }
}

static void gen_modrm_impl(int op_reg, int r, Sym *sym, int c, int is_got)
{
    op_reg = REG_VALUE(op_reg) << 3;
    if ((r & VT_VALMASK) == VT_CONST) {
        /* constant memory reference */
        o(0x05 | op_reg);
        if (is_got) {
            gen_gotpcrel(r, sym, c);
        } else {
            gen_addrpc32(r, sym, c);
        }
    } else if ((r & VT_VALMASK) == VT_LOCAL) {
        /* currently, we use only ebp as base */
        if (c == (char)c) {
            /* short reference */
            o(0x45 | op_reg);
            g(c);
        } else {
            oad(0x85 | op_reg, c);
        }
    } else if ((r & VT_VALMASK) >= TREG_MEM) {
        if (c) {
            g(0x80 | op_reg | REG_VALUE(r));
            gen_le32(c);
        } else {
            g(0x00 | op_reg | REG_VALUE(r));
        }
    } else {
        g(0x00 | op_reg | REG_VALUE(r));
    }
}

/* generate a modrm reference. 'op_reg' contains the additional 3
   opcode bits */
static void gen_modrm(int op_reg, int r, Sym *sym, int c)
{
    gen_modrm_impl(op_reg, r, sym, c, 0);
}

/* generate a modrm reference. 'op_reg' contains the additional 3
   opcode bits */
static void gen_modrm64(int opcode, int op_reg, int r, Sym *sym, int c)
{
    int is_got;
    is_got = (op_reg & TREG_MEM) && !(sym->type.t & VT_STATIC);
    orex(64, r, op_reg, opcode);
    gen_modrm_impl(op_reg, r, sym, c, is_got);
}

/* load 'r' from value 'sv' */
void load(int r, SValue *sv)
{
    int v, t, ft, fc, fr;
    SValue v1;

    uncache_value_by_register(r);

#ifdef TCC_TARGET_PE
    SValue v2;
    sv = pe_getimport(sv, &v2);
#endif

    fr = sv->r;
    ft = sv->type.t;
    fc = sv->c.ul;

#ifndef TCC_TARGET_PE
    /* we use indirect access via got */
    if ((fr & VT_VALMASK) == VT_CONST && (fr & VT_SYM) &&
        (fr & VT_LVAL) && !(sv->sym->type.t & VT_STATIC)) {
        /* use the result register as a temporal register */
        int tr = r | TREG_MEM;
        if (is_float(ft)) {
            /* we cannot use float registers as a temporal register */
            tr = get_reg(RC_INT) | TREG_MEM;
        }
        gen_modrm64(0x8b, tr, fr, sv->sym, 0);

        /* load from the temporal register */
        fr = tr | VT_LVAL;
    }
#endif

    v = fr & VT_VALMASK;
    if (fr & VT_LVAL) {
        int b, ll, bs;
        if (v == VT_LLOCAL) {
            v1.type.t = VT_PTR;
            v1.r = VT_LOCAL | VT_LVAL;
            v1.c.ul = fc;
            fr = r;
	    /* when we load %r11, use %r11 as a temp register, not another integer register. */
            if (!(reg_classes[fr] & (RC_R11 | RC_INT)))
                fr = get_reg(RC_INT);
            load(fr, &v1);
        }
        ll = 0;
        if ((ft & VT_BTYPE) == VT_FLOAT) {
	    o(0x66);
            b = 0x6e0f;
	    bs = 0;
        } else if ((ft & VT_BTYPE) == VT_DOUBLE) {
	    o(0xf3);
            b = 0x7e0f; /* movq */
	    bs = 0;
        } else if ((ft & VT_BTYPE) == VT_LDOUBLE) {
            b = 0xdb, r = 5; /* fldt */
	    bs = 0;
        } else if ((ft & VT_TYPE) == VT_BYTE || (ft & VT_TYPE) == VT_BOOL) {
            b = 0xbe0f;   /* movsbl */
	    bs = 8;
        } else if ((ft & VT_TYPE) == (VT_BYTE | VT_UNSIGNED)) {
            b = 0xb60f;   /* movzbl */
	    bs = 8;
        } else if ((ft & VT_TYPE) == VT_SHORT) {
            b = 0xbf0f;   /* movswl */
	    bs = 16;
        } else if ((ft & VT_TYPE) == (VT_SHORT | VT_UNSIGNED)) {
            b = 0xb70f;   /* movzwl */
	    bs = 16;
        } else {
            assert(((ft & VT_BTYPE) == VT_INT) || ((ft & VT_BTYPE) == VT_LLONG)
                   || ((ft & VT_BTYPE) == VT_PTR) || ((ft & VT_BTYPE) == VT_ENUM)
                   || ((ft & VT_BTYPE) == VT_FUNC));
            ll = is64_type(ft);
            b = 0x8b;
	    bs = is64_type(ft) ? 64 : 32;
        }
        if (ll) {
            gen_modrm64(b, r, fr, sv->sym, fc);
        } else {
            orex(bs, fr, r, b);
            gen_modrm(r, fr, sv->sym, fc);
        }
	uncache_value_by_register(r);
	cache_value(sv, r);
    } else {
        if (v == VT_CONST) {
            if (fr & VT_SYM) {
#ifdef TCC_TARGET_PE
                orex(64,0,r,0x8d);
                o(0x05 + REG_VALUE(r) * 8); /* lea xx(%rip), r */
                gen_addrpc32(fr, sv->sym, fc);
#else
                if (sv->sym->type.t & VT_STATIC) {
                    orex(64,0,r,0x8d);
                    o(0x05 + REG_VALUE(r) * 8); /* lea xx(%rip), r */
                    gen_addrpc32(fr, sv->sym, fc);
                } else {
                    orex(64,0,r,0x8b);
                    o(0x05 + REG_VALUE(r) * 8); /* mov xx(%rip), r */
                    gen_gotpcrel(r, sv->sym, fc);
                }
#endif
            } else if (is64_type(ft)) {
		if (sv->c.ull) {
		    orex(64,r,0, 0xb8 + REG_VALUE(r)); /* mov $xx, r */
		    gen_le64(sv->c.ull);
		} else {
		    orex(64, r, r, 0x31);
		    o(0xc0 + REG_VALUE(r) + REG_VALUE(r) * 8); /* xor r, r */
		}
            } else {
		if (fc) {
		    orex(32,r,0, 0xb8 + REG_VALUE(r)); /* mov $xx, r */
		    gen_le32(fc);
		} else {
		    orex(32, r, r, 0x31);
		    o(0xc0 + REG_VALUE(r) + REG_VALUE(r) * 8); /* xor r, r */
		}
            }
        } else if (v == VT_LOCAL) {
            orex(64,0,r,0x8d); /* lea xxx(%ebp), r */
            gen_modrm(r, VT_LOCAL, sv->sym, fc);
        } else if (v == VT_CMP) {
	    flags_used_counter++;
	    ib();
            orex(32,r,0,0);
	    if ((fc &  ~0x100) == TOK_NE)
		oad(0xb8 + REG_VALUE(r), 1);
	    else
		oad(0xb8 + REG_VALUE(r), 0); /* mov $0, r */
	    check_baddies(r, 0);
	    ib();
            if (fc & 0x100)
              {
                /* This was a float compare.  If the parity bit is
                   set the result was unordered, meaning false for everything
                   except TOK_NE, and true for TOK_NE.  */
                fc &= ~0x100;
                o(0x047a);
              }
            orex_always(8,r,0, 0x0f); /* setxx %br XXX mov $0,r; setxx %rb -> setxx, and */
            o(fc);
            o(0xc0 + REG_VALUE(r));
	    flags_used_counter--;
        } else if (v == VT_JMP || v == VT_JMPI) {
	    flags_used_counter++;
            t = v & 1;
	    ib();
            orex(32,r,0,0);
            oad(0xb8 + REG_VALUE(r), t); /* mov $1, r */
	    check_baddies(r, 0);
	    ib();
            o(0x06eb); /* jmp after */
            if(gsym_nocommit(fc) > 1)
	      commit_instructions();
	    ib();
            orex_always(0,r,0,0); /* not orex! */
            oad(0xb8 + REG_VALUE(r), t ^ 1); /* mov $0, r */
	    check_baddies(r, 0);
	    flags_used_counter--;
        } else if (v != r) {
            if ((r >= TREG_XMM0) && (r <= TREG_XMM7)) {
                if (v == TREG_ST0) {
		    /* XXX orex */
                    /* gen_cvt_ftof(VT_DOUBLE); */
                    o(0xf0245cdd); /* fstpl -0x10(%rsp) */
                    /* movsd -0x10(%rsp),%xmmN */
                    o(0x100ff2);
                    o(0x44 + REG_VALUE(r)*8); /* %xmmN */
                    o(0xf024);
                } else {
		    /* XXX orex */
                    assert((v >= TREG_XMM0) && (v <= TREG_XMM7));
                    if ((ft & VT_BTYPE) == VT_FLOAT) {
                        o(0x100ff3);
                    } else {
                        assert((ft & VT_BTYPE) == VT_DOUBLE);
                        o(0x100ff2);
                    }
                    o(0xc0 + REG_VALUE(v) + REG_VALUE(r)*8);
                }
            } else if (r == TREG_ST0) {
                assert((v >= TREG_XMM0) || (v <= TREG_XMM7));
                /* gen_cvt_ftof(VT_LDOUBLE); */
                /* movsd %xmmN,-0x10(%rsp) */
                o(0x110ff2);
                o(0x44 + REG_VALUE(r)*8); /* %xmmN */
                o(0xf024);
                o(0xf02444dd); /* fldl -0x10(%rsp) */
            } else {
                orex(64,r,v, 0x89);
                o(0xc0 + REG_VALUE(r) + REG_VALUE(v) * 8); /* mov v, r */
            }
        }
    }
}

void store_pic(int r,SValue *v)
{
    int fr, bt, ft, fc;
    int op64 = 0;
    /* store the REX prefix in this variable when PIC is enabled */
    int pic = 0;
    int pic_reg = -1;
    int bs;

#ifdef TCC_TARGET_PE
    SValue v2;
    v = pe_getimport(v, &v2);
#endif

    ft = v->type.t;
    fc = v->c.ul;
    fr = v->r & VT_VALMASK;
    bt = ft & VT_BTYPE;

    pic_reg = get_reg(RC_INT);
    start_special_use(pic_reg);
    /* mov xx(%rip), %rXX */
    orex(64, 0, pic_reg, 0x8b);
    o(0x05 | REG_VALUE(pic_reg) * 8);
    gen_gotpcrel(pic_reg, v->sym, v->c.ul);
    bs = is64_type(bt) ? 64 : 32;

    /* XXX: incorrect if float reg to reg */
    if (bt == VT_FLOAT) {
	o(0x66);
	orex(0, v->r, r, 0x0f);
	if (r < TREG_XMM0)
	    o(0x7e); /* movd/movq */
	else
	    o(0xd6);
        r = REG_VALUE(r);
    } else if (bt == VT_DOUBLE) {
        o(0x66);
        orex(0, pic_reg, r, 0x0f);
        o(0xd6); /* movq */
        r = REG_VALUE(r);
    } else if (bt == VT_LDOUBLE) {
        o(0xc0d9); /* fld %st(0) */
        r = 7;
        orex(0, pic_reg, r, 0xdb); /* fstpt */
    } else {
        if (bt == VT_SHORT)
	    o(0x66);
        if (bt == VT_BYTE || bt == VT_BOOL) {
            orex(8, pic_reg, r, 0x88);
        } else if (is64_type(bt)) {
	    orex(64, pic_reg, r, 0x89);
        } else {
	    orex(32, pic_reg, r, 0x89);
	}
    }

    g(REG_VALUE(pic_reg) + (REG_VALUE(r) << 3));
    end_special_use(pic_reg);
}

/* store register 'r' in lvalue 'v' */
void store(int r, SValue *v)
{
    int fr, bt, ft, fc;
    int op64 = 0;

#ifdef TCC_TARGET_PE
    SValue v2;
    v = pe_getimport(v, &v2);
#endif

    ft = v->type.t;
    fc = v->c.ul;
    fr = v->r & VT_VALMASK;
    bt = ft & VT_BTYPE;

#ifndef TCC_TARGET_PE
    /* we need to access the variable via got */
    if (fr == VT_CONST && (v->r & VT_SYM)) {
	store_pic(r, v);
	return;
    }
#endif

    /* XXX: incorrect if float reg to reg */
    if (bt == VT_FLOAT) {
	o(0x66);
	orex(0, v->r, r, 0x0f);
	if (v->r < TREG_XMM0 || v->r > TREG_XMM0 + 15)
	    o(0x7e); /* movd/movq */
	else
	    o(0xd6);
    } else if (bt == VT_DOUBLE) {
        o(0x66);
	orex(0, v->r, r, 0x0f);
        o(0xd6); /* movq */
    } else if (bt == VT_LDOUBLE) {
        o(0xc0d9); /* fld %st(0) */
        r = 7;
	orex(0, v->r, 0, 0xdb); /* fstpt */
    } else {
        if (bt == VT_SHORT)
	    o(0x66);
        if (bt == VT_BYTE || bt == VT_BOOL) {
            orex(8, v->r, r, 0x88);
        } else if (is64_type(bt)) {
	    orex(64, v->r, r, 0x89);
        } else {
	    orex(32, v->r, r, 0x89);
	}
    }

    if (fr == VT_CONST || fr == VT_LOCAL || (v->r & VT_LVAL)) {
	gen_modrm(r, v->r, v->sym, fc);
    } else if (fr != r) {
	o(0xc0 + REG_VALUE(fr) + REG_VALUE(r) * 8); /* mov r, fr */
    }
}

/* 'is_jmp' is '1' if it is a jump */
static void gcall_or_jmp(int is_jmp)
{
    int r;
    /* XXXpipcet I think this is the place where we go wrong when running
     * code like
     *    ((int (*)(int))1000000000000)(3).
     * The constant is larger than 32 bits, but the relative call instruction
     * is limited to 32-bit offsets. */
    if (((vtop->r & (VT_VALMASK | VT_LVAL)) == VT_CONST) &&
	((vtop->r & VT_SYM) || ((vtop->c.ll-4) == (int)(vtop->c.ll-4)))) {
        /* constant case */
        if (vtop->r & VT_SYM) {
            /* relocation case */
            greloc(cur_text_section, vtop->sym,
                   get_index() + 1, R_X86_64_PC32);
        } else {
            /* put an empty PC32 relocation */
            put_elf_reloc(symtab_section, cur_text_section,
                          get_index() + 1, R_X86_64_PC32, 0);
        }
        oad(0xe8 + is_jmp, vtop->c.ul - 4); /* call/jmp im */
    } else {
        /* otherwise, indirect call. XXX use gv(RC_INT) instead. */
        r = get_reg(RC_INT);
	save_reg(r);
	start_special_use(r);
        load(r, vtop);
	orex(32 /* XXX or 64? */, r, 0, 0xff);
        o(0xd0 + REG_VALUE(r) + (is_jmp << 4));
	end_special_use(r);
    }
    commit_instructions(); /* all caller-saved registers have been clobbered */
}

#ifdef TCC_TARGET_PE

#define REGN 4
static const uint8_t arg_regs[REGN] = {
    TREG_RCX, TREG_RDX, TREG_R8, TREG_R9
};

/* Prepare arguments in R10 and R11 rather than RCX and RDX
   because gv() will not ever use these */
static int arg_prepare_reg(int idx) {
    return arg_regs[idx];
}

static int func_scratch;

/* Generate function call. The function address is pushed first, then
   all the parameters in call order. This functions pops all the
   parameters and the function address. */

void gen_offs_sp(int b, int r, int d)
{
    orex(64,r,0,b);
    if (d == (char)d) {
        o(0x2444 | (REG_VALUE(r) << 3));
        g(d);
    } else {
        o(0x2484 | (REG_VALUE(r) << 3));
        gen_le32(d);
    }
}

/* Return 1 if this function returns via an sret pointer, 0 otherwise */
ST_FUNC int gfunc_sret(CType *vt, CType *ret, int *ret_align)
{
    int size, align;
    *ret_align = 1; // Never have to re-align return values for x86-64
    size = type_size(vt, &align);
    ret->ref = NULL;
    if (size > 8) {
        return 1;
    } else if (size > 4) {
        ret->t = VT_LLONG;
        return 0;
    } else if (size > 2) {
        ret->t = VT_INT;
        return 0;
    } else if (size > 1) {
        ret->t = VT_SHORT;
        return 0;
    } else {
        ret->t = VT_BYTE;
        return 0;
    }
}

static int is_sse_float(int t) {
    int bt;
    bt = t & VT_BTYPE;
    return bt == VT_DOUBLE || bt == VT_FLOAT;
}

int gfunc_arg_size(CType *type) {
    int align;
    if (type->t & (VT_ARRAY|VT_BITFIELD))
        return 8;
    return type_size(type, &align);
}

void gfunc_call(int nb_args)
{
    int size, r, args_size, i, d, bt, struct_size;
    int arg;

    args_size = (nb_args < REGN ? REGN : nb_args) * PTR_SIZE;
    arg = nb_args;

    /* for struct arguments, we need to call memcpy and the function
       call breaks register passing arguments we are preparing.
       So, we process arguments which will be passed by stack first. */
    struct_size = args_size;
    for(i = 0; i < nb_args; i++) {
        SValue *sv;
        
        --arg;
        sv = &vtop[-i];
        bt = (sv->type.t & VT_BTYPE);
        size = gfunc_arg_size(&sv->type);

        if (size <= 8)
            continue; /* arguments smaller than 8 bytes passed in registers or on stack */

        if (bt == VT_STRUCT) {
            /* align to stack align size */
            size = (size + 15) & ~15;
            /* generate structure store */
            r = get_reg(RC_INT);
            gen_offs_sp(0x8d, r, struct_size);
            struct_size += size;

            /* generate memcpy call */
            vset(&sv->type, r | VT_LVAL, 0);
            vpushv(sv);
            vstore();
            --vtop;
        } else if (bt == VT_LDOUBLE) {
            gv(RC_ST0);
            gen_offs_sp(0xdb, 0x107, struct_size);
            struct_size += 16;
        }
    }

    if (func_scratch < struct_size)
        func_scratch = struct_size;

    arg = nb_args;
    struct_size = args_size;

    for(i = 0; i < nb_args; i++) {
        --arg;
        bt = (vtop->type.t & VT_BTYPE);

        size = gfunc_arg_size(&vtop->type);
        if (size > 8) {
            /* align to stack align size */
            size = (size + 15) & ~15;
            if (arg >= REGN) {
                d = get_reg(RC_INT);
                gen_offs_sp(0x8d, d, struct_size);
                gen_offs_sp(0x89, d, arg*8);
            } else {
                d = arg_prepare_reg(arg);
                gen_offs_sp(0x8d, d, struct_size);
		start_special_use(d);
            }
            struct_size += size;
        } else {
            if (is_sse_float(vtop->type.t)) {
                gv(RC_XMM0); /* only use one float register */
                if (arg >= REGN) {
                    /* movq %xmm0, j*8(%rsp) */
                    gen_offs_sp(0xd60f66, 0x100, arg*8);
                } else {
                    /* movaps %xmm0, %xmmN */
                    o(0x280f);
                    o(0xc0 + (arg << 3));
                    d = arg_prepare_reg(arg);
                    /* mov %xmm0, %rxx */
                    o(0x66);
                    orex(64,d,0, 0x7e0f);
                    o(0xc0 + REG_VALUE(d));
		    start_special_use(d);
                }
            } else {
                if (bt == VT_STRUCT) {
                    vtop->type.ref = NULL;
                    vtop->type.t = size > 4 ? VT_LLONG : size > 2 ? VT_INT
                        : size > 1 ? VT_SHORT : VT_BYTE;
                }
                
                r = gv(RC_INT);
                if (arg >= REGN) {
                    gen_offs_sp(0x89, r, arg*8);
                } else {
                    d = arg_prepare_reg(arg);
                    orex(64,d,r,0x89); /* mov */
                    o(0xc0 + REG_VALUE(r) * 8 + REG_VALUE(d));
		    start_special_use(d);
                }
            }
        }
        vtop--;
    }
    save_regs(0);
    
    /* Copy R10 and R11 into RCX and RDX, respectively */
    if (nb_args > 0) {
        o(0xd1894c); /* mov %r10, %rcx */
        if (nb_args > 1) {
            o(0xda894c); /* mov %r11, %rdx */
        }
    }
    
    gcall_or_jmp(0);
    vtop--;
}


#define FUNC_PROLOG_SIZE 11

/* generate function prolog of type 't' */
void gfunc_prolog(CType *func_type)
{
    int addr, reg_param_index, bt, size;
    Sym *sym;
    CType *type;

    func_ret_sub = 0;
    func_scratch = 0;
    loc = 0;

    addr = PTR_SIZE * 2;
    ind += FUNC_PROLOG_SIZE;
    func_sub_sp_offset = ind;
    reg_param_index = 0;

    sym = func_type->ref;

    /* if the function returns a structure, then add an
       implicit pointer parameter */
    func_vt = sym->type;
    size = gfunc_arg_size(&func_vt);
    if (size > 8) {
        gen_modrm64(0x89, arg_regs[reg_param_index], VT_LOCAL, NULL, addr);
	/* does this not break for nested functions ? */
        func_vc = addr;
        reg_param_index++;
        addr += 8;
    }

    /* define parameters */
    while ((sym = sym->next) != NULL) {
        type = &sym->type;
        bt = type->t & VT_BTYPE;
        size = gfunc_arg_size(type);
        if (size > 8) {
            if (reg_param_index < REGN) {
                gen_modrm64(0x89, arg_regs[reg_param_index], VT_LOCAL, NULL, addr);
            }
            sym_push(sym->v & ~SYM_FIELD, type, VT_LOCAL | VT_LVAL | VT_REF, addr);
        } else {
            if (reg_param_index < REGN) {
                /* save arguments passed by register */
                if ((bt == VT_FLOAT) || (bt == VT_DOUBLE)) {
                    o(0xd60f66); /* movq */
                    gen_modrm(reg_param_index, VT_LOCAL, NULL, addr);
                } else {
                    gen_modrm64(0x89, arg_regs[reg_param_index], VT_LOCAL, NULL, addr);
                }
            }
            sym_push(sym->v & ~SYM_FIELD, type, VT_LOCAL | VT_LVAL, addr);
        }
        addr += 8;
        reg_param_index++;
    }

    while (reg_param_index < REGN) {
        if (func_type->ref->c == FUNC_ELLIPSIS) {
            gen_modrm64(0x89, arg_regs[reg_param_index], VT_LOCAL, NULL, addr);
            addr += 8;
        }
        reg_param_index++;
    }
}

/* generate function epilog */
void gfunc_epilog(void)
{
    int v, saved_ind;

    o(0xc9); /* leave */
    if (func_ret_sub == 0) {
        o(0xc3); /* ret */
    } else {
        o(0xc2); /* ret n */
        g(func_ret_sub);
        g(func_ret_sub >> 8);
    }

    saved_ind = ind;
    ind = func_sub_sp_offset - FUNC_PROLOG_SIZE;
    /* align local size to word & save local variables */
    v = (func_scratch + -loc + 15) & -16;

    if (v >= 4096) {
        Sym *sym = external_global_sym(TOK___chkstk, &func_old_type, 0);
        oad(0xb8, v); /* mov stacksize, %eax */
        oad(0xe8, -4); /* call __chkstk, (does the stackframe too) */
        greloc(cur_text_section, sym, ind-4, R_X86_64_PC32);
        o(0x90); /* fill for FUNC_PROLOG_SIZE = 11 bytes */
    } else {
        o(0xe5894855);  /* push %rbp, mov %rsp, %rbp */
        o(0xec8148);  /* sub rsp, stacksize */
        gen_le32(v);
    }

    cur_text_section->data_offset = saved_ind;
    pe_add_unwind_data(ind, saved_ind, v);
    ind = cur_text_section->data_offset;
}

#else

static void gadd_sp(int val)
{
    if (val == (char)val) {
        o(0xc48348);
        g(val);
    } else {
        oad(0xc48148, val); /* add $xxx, %rsp */
    }
}

typedef enum X86_64_Mode {
  x86_64_mode_none,
  x86_64_mode_memory,
  x86_64_mode_integer,
  x86_64_mode_sse,
  x86_64_mode_x87
} X86_64_Mode;

static X86_64_Mode classify_x86_64_merge(X86_64_Mode a, X86_64_Mode b) {
    if (a == b)
        return a;
    else if (a == x86_64_mode_none)
        return b;
    else if (b == x86_64_mode_none)
        return a;
    else if ((a == x86_64_mode_memory) || (b == x86_64_mode_memory))
        return x86_64_mode_memory;
    else if ((a == x86_64_mode_integer) || (b == x86_64_mode_integer))
        return x86_64_mode_integer;
    else if ((a == x86_64_mode_x87) || (b == x86_64_mode_x87))
        return x86_64_mode_memory;
    else
        return x86_64_mode_sse;
}

static X86_64_Mode classify_x86_64_inner_new(CType *ty, SValue *ret, int nret, int *offset) {
    X86_64_Mode mode;
    Sym *f;
    
    switch (ty->t & VT_BTYPE) {
    case VT_VOID:
	if (nret > 0) {
	    ret[0].type = *ty;
	    ret[0].c.ull = 0;
	    ret[0].r = VT_CONST;
	}
	return x86_64_mode_none;
    
    case VT_INT:
    case VT_BYTE:
    case VT_SHORT:
    case VT_LLONG:
    case VT_BOOL:
    case VT_PTR:
    case VT_FUNC:
    case VT_ENUM:
	if (nret > 0) {
	    int align;
	    ret[0].type = *ty;
	    ret[0].c.ull = 0;
	    ret[0].r = TREG_RAX;
	}
	(*offset)++;
	return x86_64_mode_integer;
    
    case VT_FLOAT:
    case VT_DOUBLE:
	if (nret > 0) {
	    int align;
	    ret[0].type = *ty;
	    ret[0].c.ull = 0;
	    ret[0].r = TREG_XMM0;
	}
	(*offset)++;
	return x86_64_mode_sse;
    
    case VT_LDOUBLE:
	if (nret > 0) {
	    ret[0].type = *ty;
	    ret[0].c.ull = 0;
	    ret[0].r = TREG_ST0;
	}
	(*offset)++;
	return x86_64_mode_x87;
      
    case VT_STRUCT: ;
	int align;
        int size = type_size(ty, &align);
	if (size > 16)
	    return x86_64_mode_memory;
        f = ty->ref;

        mode = x86_64_mode_none;
	int origo = 0, o = 0, eightbyte_o = 0;

        for (; f; f = f->next) {
	    int i;
	    int j = origo;

	    if (f->v & SYM_STRUCT)
		continue;
	    if (!(f->v & SYM_FIELD))
		continue;

            mode = classify_x86_64_merge(mode, classify_x86_64_inner_new(&f->type, ret+o, nret-o, &o));

	    if (mode == x86_64_mode_memory) {
		for(i=origo; i<o; i++) {
		    ret[i].r = VT_CONST;
		}
	    }

	    for(i=origo; i<o; i++) {
		if(i < nret) {
		    ret[i].c.ull += f->c;
		    /* start a new "eightbyte" at an eight-byte boundary... */
		    int new_eightbyte = (ret[i].c.ull & 7ULL) == 0ULL;
		    /* ...but not if it's the same eightbyte we're already in. */
		    if (eightbyte_o < j && (ret[i].c.ull == ret[eightbyte_o].c.ull))
			new_eightbyte = 0;
		    if (new_eightbyte)
			eightbyte_o = j;
		    else {
			/* struct { float x; int y; } is packed into %rax. */
			int j;

			for(j=eightbyte_o; j<i; j++) {
			    if(ret[i].r == TREG_RAX && ret[j].r == TREG_XMM0)
				ret[j].r = TREG_RAX;

			    if(ret[i].r == TREG_XMM0 && ret[j].r == TREG_RAX)
				ret[i].r = TREG_RAX;
			}

			if (mode == x86_64_mode_integer)
			    for(j=eightbyte_o; j<=i; j++)
				assert(ret[j].r != TREG_XMM0);
		    }

		    if (ret[i].type.t != VT_VOID) {
			/* if we're dealing with a structure which
			 * packs two or more data items into the same
			 * eightbyte, copy the entire
			 * eightbyte. That's not absolutely the most
			 * correct thing to do, because the structure
			 * might be as small as two bytes... however,
			 * we're only copying that data to the stack,
			 * and then memcpy()ing it from there to the
			 * original struct, so we should be safe. For
			 * now. */

			if (!new_eightbyte) {
			    ret[i].type.t = VT_VOID;
			    ret[i].r = VT_CONST;
			    ret[eightbyte_o].type.t = (ret[eightbyte_o].r == TREG_XMM0) ? VT_DOUBLE : VT_LLONG;
			}
		    }

		    if(i != j) {
			ret[j] = ret[i];
		    }

		    if(ret[i].type.t != VT_VOID) {
			(*offset)++;
			j++;
		    }
		} else {
		    (*offset)++;
		    j++;
		}
	    }
	    origo = j;
	    o = j;
	}
        
        return mode;
    }
    
    assert(0);
}

static X86_64_Mode classify_x86_64_arg_new(CType *ty, SValue *ret, int nret, int *psize, int *palign, int *offset) {
    X86_64_Mode mode;
    int size, align, ret_t = 0;

    if (nret)
	ret[0].type.ref = ty->ref;
    if (ty->t & (VT_BITFIELD|VT_ARRAY)) {
	if (nret) {
	    ret[0].type.t = ty->t;
	    ret[0].c.ull = 0;
	    ret[0].r = TREG_RAX;
	}
	(*offset)++;

        *psize = 8;
        mode = x86_64_mode_integer;
    } else {
        size = type_size(ty, &align);
        *psize = (size + 7) & ~7;
        *palign = (align + 7) & ~7;

        if (size > 16) {
	    /* we do not support SSEUP-class arguments properly */
            mode = x86_64_mode_memory;
	    (*offset)++;
        } else {
	    /* this breaks for struct { struct { long x } s; long y; }, I think */
            mode = classify_x86_64_inner_new(ty, ret, nret, offset);
        }
    }

    return mode;
}

ST_FUNC int classify_x86_64_va_arg(CType *ty) {
    /* This definition must be synced with stdarg.h */
    enum __va_arg_type {
        __va_gen_reg, __va_float_reg, __va_stack
    };
    int size, align, reg_count = 0;
    X86_64_Mode mode = classify_x86_64_arg_new(ty, NULL, 0, &size, &align, &reg_count);
    switch (mode) {
    default: return __va_stack;
    case x86_64_mode_integer: return __va_gen_reg;
    case x86_64_mode_sse: return __va_float_reg;
    }
}

/* Return 1 if this function returns via an sret pointer, 0 otherwise.
 *
 * Up to two arguments can be returned in registers, but all three
 * combinations (two integer registers, two SSE registers, or one of
 * each) are valid. ret1 and ret2, if non-NULL, will set to the
 * register, struct offset, and type of the corresponding
 * argument. Only ret1 is modified if there is a single argument.
 */
int gfunc_sret_new(CType *vt, SValue *ret, int nret, int *ret_align) {
    int size, align, reg_count = 0;
    X86_64_Mode mode;
    *ret_align = 1; // Never have to re-align return values for x86-64
    mode = classify_x86_64_arg_new(vt, ret, nret, &size, &align, &reg_count);

    if (reg_count >= 2 && ret[0].r == ret[1].r)
	ret[1].r = (ret[0].r == TREG_RAX) ? TREG_RDX : TREG_XMM1;

    int i;
    for (i=reg_count; i<nret; i++) {
	ret[i].type.t = VT_VOID;
	ret[i].r = VT_CONST;
    }

    return (mode == x86_64_mode_memory);
}

#define REGN 6
static const uint8_t arg_regs[REGN] = {
    TREG_RDI, TREG_RSI, TREG_RDX, TREG_RCX, TREG_R8, TREG_R9
};

static int arg_prepare_reg(int idx) {
    return arg_regs[idx];
}

/* Generate function call. The function address is pushed first, then
   all the parameters in call order. This functions pops all the
   parameters and the function address. */
void gfunc_call(int nb_args)
{
    X86_64_Mode mode;
    CType type;
    int size, align, r, args_size, stack_adjust, run_start, run_end, i, j, reg_count;
    int nb_reg_args = 0;
    int nb_sse_args = 0;
    int nb_x87_args = 0;
    // int offsets[nb_args+1]; VLAs broken in upstream
    int offsets[256];
    int offsets2[256];
    int sse_reg, gen_reg;
    SValue ret[256]; /* XXX */
    SValue ret2[256]; /* XXX */
    int nret = 256;
    int off = 0;
    for(i=0; i<nret; i++) {
	ret[i].type.t = VT_VOID;
	ret[i].r = VT_CONST;
	ret[i].sym = NULL;
    }
    for(i=0; i<nret; i++) {
	ret2[i].type.t = VT_VOID;
	ret2[i].r = VT_CONST;
	ret2[i].sym = NULL;
    }

    assert((vtop[-nb_args].type.t & VT_BTYPE) == VT_FUNC);
    /* calculate the number of integer/float register arguments */
    for(i = nb_args-1; i >= 0; i--) {
	int start = off;
	int prel_nb_reg_args = nb_reg_args;
	int prel_nb_sse_args = nb_sse_args;
	int prel_nb_x87_args = nb_x87_args;
	int j;

	offsets[i] = off;
	offsets2[i] = off;
        mode = classify_x86_64_arg_new(&vtop[-nb_args+1+i].type, ret+off, nret-off, &size, &align, &off);

	if (mode == x86_64_mode_memory)
	    continue;

	for(j = start; j<off && j<nret; j++) {
	    if (ret[j].r == TREG_RAX ||
		ret[j].r == TREG_RDX) {
		int idx = prel_nb_reg_args;

		if ((ret[j].c.ull & 7) == 0) {
		    prel_nb_reg_args++;
		}

		if (idx < REGN) {
		    ret[j].r = arg_prepare_reg(idx);
		} else {
		    goto failure;
		}
	    } else if (ret[j].r == TREG_XMM0 ||
		       ret[j].r == TREG_XMM1) {
		int idx = prel_nb_sse_args;

		if ((ret[j].c.ull & 7) == 0) {
		    prel_nb_sse_args++;
		}

		if (idx < 8) {
		    ret[j].r = TREG_XMM0 + idx;
		} else {
		    goto failure;
		}
	    } else if (ret[j].r == TREG_ST0) {
		int idx = prel_nb_x87_args;

		prel_nb_x87_args++;
		if (idx < 0) {
		    ret[j].r = TREG_ST0;
		} else {
		    goto failure;
		}
	    }
	}

    success:
	/* success */
	nb_reg_args = prel_nb_reg_args;
	nb_sse_args = prel_nb_sse_args;
	nb_x87_args = prel_nb_x87_args;
	continue;
    failure:
	for(j = start; j<off && j<nret; j++) {
	    ret[j].r = VT_CONST;
	}
	goto success; /* for now, we're counting integer arguments, not register arguments, in nb_reg_args */
    }
    offsets[nb_args] = off;
    offsets2[nb_args] = off;

    /* arguments are collected in runs. Each run is a collection of 8-byte aligned arguments
       and ended by a 16-byte aligned argument. This is because, from the point of view of
       the callee, argument alignment is computed from the bottom up. */
    /* for struct arguments, we need to call memcpy and the function
       call breaks register passing arguments we are preparing.
       So, we process arguments which will be passed by stack first. */
    gen_reg = nb_reg_args;
    sse_reg = nb_sse_args;
    run_start = 0;
    args_size = 0;
    while (run_start < nb_args) {
        int run_gen_reg = gen_reg, run_sse_reg = sse_reg;
	int new_eightbyte = 1;
        
        run_end = nb_args;
        stack_adjust = 0;
        for(i = run_start; (i < nb_args) && (run_end == nb_args); i++) {
	    int off = 0, j;
	    int arg_gen_reg = gen_reg;
	    int arg_sse_reg = sse_reg;
            mode = classify_x86_64_arg_new(&vtop[-i].type, ret2, nret, &size, &align, &off);
	    for(j=off-1; j>=0; j--) {
		if(ret2[j].c.ull & 7)
		    new_eightbyte = 0;
		else
		    new_eightbyte = 1;

		switch (mode) {
		case x86_64_mode_memory:
		case x86_64_mode_x87:
		stack_arg:
		    //arg_gen_reg = gen_reg;
		    //arg_sse_reg = sse_reg;
		    if (align == 16)
			run_end = i;
		    else
			stack_adjust += size;
		    break;
                
		case x86_64_mode_sse:
		    if (new_eightbyte) {
			arg_sse_reg--;
			if (arg_sse_reg >= 8) goto stack_arg;
		    }

		    break;

		case x86_64_mode_integer:
		    if (new_eightbyte) {
			arg_gen_reg--;
			if (arg_gen_reg >= REGN) goto stack_arg;
			break;
		    default:
			break; /* nothing to be done for x86_64_mode_none */
		    }
		}
            }
	    gen_reg = arg_gen_reg;
	    sse_reg = arg_sse_reg;
        }
        
        gen_reg = run_gen_reg;
        sse_reg = run_sse_reg;
        
        /* adjust stack to align SSE boundary */
        if (stack_adjust &= 15) {
            /* fetch cpu flag before the following sub will change the value. What about VT_JMP[I]? */
            if (vtop >= vstack && (vtop->r & VT_VALMASK) == VT_CMP)
                gv(RC_INT);

            stack_adjust = 16 - stack_adjust;
            o(0x48);
            oad(0xec81, stack_adjust); /* sub $xxx, %rsp */
            args_size += stack_adjust;
        }
        
	reg_count = 0;

        for(i = run_start; i < run_end;) {
            /* Swap argument to top, it will possibly be changed here,
              and might use more temps. At the end of the loop we keep
              it on the stack and swap it back to its original position
              if it is a register. */
	    int idx = -i;
            SValue tmp = vtop[0];
            vtop[0] = vtop[idx];
            vtop[idx] = tmp;
	    int align;
            
	    int off = 0, j;
	    int arg_gen_reg = gen_reg;
	    int arg_sse_reg = sse_reg;
            int arg_stored = 1;
            mode = classify_x86_64_arg_new(&vtop->type, ret2, nret, &size, &align, &off);
	    for(j=off-1; j>=0; j--) {
		if(ret2[j].c.ull & 7)
		    new_eightbyte = 0;
		else
		    new_eightbyte = 1;

		switch (mode) {
		case x86_64_mode_memory:
		case x86_64_mode_x87:
		push_stack_arg:
		    arg_stored = 1;
		    break;
                
		case x86_64_mode_sse:
		    if (new_eightbyte) {
			arg_sse_reg--;
			arg_stored = 0;

			if (arg_sse_reg >= 8) goto push_stack_arg;
		    }

		    break;

		case x86_64_mode_integer:
		    if (new_eightbyte) {
			arg_gen_reg--;
			arg_stored = 0;

			if (arg_gen_reg >= REGN) goto push_stack_arg;
			break;
		    default:
			break; /* nothing to be done for x86_64_mode_none */
		    }
		}
            }

	    gen_reg = arg_gen_reg;
	    sse_reg = arg_sse_reg;

	    if (arg_stored) {
		switch(vtop->type.t & VT_BTYPE) {
		case VT_STRUCT:
		    /* allocate the necessary size on stack */
		    o(0x48);
		    oad(0xec81, size); /* sub $xxx, %rsp */
		    /* generate structure store */
		    r = get_reg(RC_INT);
		    orex(64, r, 0, 0x89); /* mov %rsp, r */
		    o(0xe0 + REG_VALUE(r));
		    vset(&vtop->type, r | VT_LVAL, 0);
		    vswap();
		    vstore();
		    args_size += size;
		    break;

		case VT_LDOUBLE:
		    assert(0);
		    break;

		case VT_FLOAT:
		case VT_DOUBLE:
                    r = gv(RC_FLOAT);
                    o(0x50); /* push $rax */
                    /* movq %xmmN, (%rsp) */
                    o(0xd60f66);
                    o(0x04 + REG_VALUE(r)*8);
                    o(0x24);
                    args_size += size;
		    break;

		default:
		    assert(mode == x86_64_mode_integer);
		    /* simple type */
		    /* XXX: implicit cast ? */
                    r = gv(RC_INT);
                    orex(0,r,0,0x50 + REG_VALUE(r)); /* push r */
                    args_size += size;
		    break;
		}
	    }

            /* And swap the argument back to its original position.  */
            tmp = vtop[0];
            vtop[0] = vtop[idx];
            vtop[idx] = tmp;

            if (arg_stored) {
		vrotb(i+1);
		assert((vtop->type.t == tmp.type.t) && (vtop->r == tmp.r));
		vpop();
		memmove(offsets2+nb_args-1-i, offsets2+nb_args-i, nb_args-i+1 * sizeof(offsets[0]));
		--nb_args;
		--run_end;
            } else {
		++i;
            }
        }

	reg_count = 0;
        /* handle 16 byte aligned arguments at end of run */
        run_start = i = run_end;
        while (i < nb_args) {
            /* Rotate argument to top since it will always be popped */
            mode = classify_x86_64_arg_new(&vtop[-i].type, ret2, nret, &size, &align, &reg_count);
            if (align != 16)
              break;

	    vrotb(i+1);
            
            if ((vtop->type.t & VT_BTYPE) == VT_LDOUBLE) {
                gv(RC_ST0);
                oad(0xec8148, size); /* sub $xxx, %rsp */
                o(0x7cdb); /* fstpt 0(%rsp) */
                g(0x24);
                g(0x00);
                args_size += size;
            } else {
                assert(mode == x86_64_mode_memory);

                /* allocate the necessary size on stack */
                o(0x48);
                oad(0xec81, size); /* sub $xxx, %rsp */
                /* generate structure store */
                r = get_reg(RC_INT);
                orex(64, r, 0, 0x89); /* mov %rsp, r */
                o(0xe0 + REG_VALUE(r));
                vset(&vtop->type, r | VT_LVAL, 0);
                vswap();
                vstore();
                args_size += size;
            }
            
            vpop();
	    memmove(offsets2+nb_args-1-i, offsets2+nb_args-i, nb_args-i+1 * sizeof(offsets[0]));
            --nb_args;
	    assert(nb_args >= 0);
        }
    }
    
    gen_reg = nb_reg_args;
    sse_reg = nb_sse_args;

    if (gen_reg > REGN)
	gen_reg = REGN;

    if (sse_reg > 8)
	sse_reg = 8;

    /* XXX This should be superfluous.  */
    save_regs(0); /* save used temporary registers */

    /* then, we prepare register passing arguments. */
    //assert(nb_args == gen_reg + sse_reg);
    assert(gen_reg <= REGN);
    assert(sse_reg <= 8);
    for(i = 0; i < nb_args; i++) {
	int off = 0, j;
	int arg_gen_reg = gen_reg;
	int arg_sse_reg = sse_reg;
	int arg_stored = 1;
	int shared_eightbyte = 0;
	int new_eightbyte;

	assert(gen_reg >= 0);
	assert(sse_reg >= 0);
	mode = classify_x86_64_arg_new(&vtop->type, ret2, nret, &size, &align, &off);
	for(j=off-1; j>=0; j--) {
	    if(ret2[j].c.ull & 7)
		new_eightbyte = 0;
	    else
		new_eightbyte = 1;

	    switch (ret2[j].r) {
	    case TREG_XMM0:
		if (new_eightbyte) {
		    arg_sse_reg--;
		    assert(arg_sse_reg < 8);
		    if (shared_eightbyte)
			ret2[j].type.t = VT_DOUBLE;
		    ret2[j].r = TREG_XMM0 + arg_sse_reg;
		} else {
		    ret2[j].r = VT_CONST;
		    shared_eightbyte = 1;
		}

		assert (ret2[j].r != TREG_RAX);

		break;

	    case TREG_RAX:
		if (new_eightbyte) {
		    arg_gen_reg--;
		    assert(arg_gen_reg < REGN);
		    if (shared_eightbyte)
			ret2[j].type.t = VT_LLONG;
		    ret2[j].r = arg_prepare_reg(arg_gen_reg);
		} else {
		    ret2[j].r = VT_CONST;
		    shared_eightbyte = 1;
		}

		break;
	    default:
		assert(0);
		break; /* nothing to be done for x86_64_mode_none */
	    }

	    if (new_eightbyte)
		shared_eightbyte = 0;
	}

	assert(!shared_eightbyte);

	gen_reg = arg_gen_reg;
	sse_reg = arg_sse_reg;

	int retj = 0;
	unsigned long long struct_offset = 0;
	int pop_structs = 0;
	if(off > 1)
	    assert((vtop->type.t & VT_BTYPE) == VT_STRUCT);
	for(j=0; retj<off; j++) {
	    if(ret2[retj].r == VT_CONST) {
		assert(0);
	    }

	    if ((vtop->type.t & VT_BTYPE) == VT_STRUCT) {
		pop_structs = 1;
		CType ty = ret2[retj].type;
		vdup();
		gaddrof();
		vtop->type.t = VT_LLONG;
		vpushi(ret2[retj].c.i);
		gen_op('+');
		mk_pointer(&ty);
		vtop->type = ty;
		indir();
	    }


	    int r = gv((ret2[retj].r >= TREG_XMM0) ? (RC_XMM0 << (ret2[retj].r-TREG_XMM0)) : RC_INT);

	    if(r == ret2[retj].r) {
		vtop--;
		/* either we're lucky, or this is the last register. */
		start_special_use(ret2[retj].r);

	    } else {
		save_reg(ret2[retj].r);
		get_specific_reg(ret2[retj].r);
		start_special_use(ret2[retj].r);

		int d = ret2[retj].r;
		orex(64,d,r,0x89); /* mov */
		o(0xc0 + REG_VALUE(r) * 8 + REG_VALUE(d));
		vtop--;
	    }

	    retj++;
	}

	if (pop_structs) {
	    assert((vtop->type.t & VT_BTYPE) == VT_STRUCT);
	    vtop--;
	}
    }
    assert(gen_reg == 0);
    assert(sse_reg == 0);

    assert((vtop->type.t & VT_BTYPE) == VT_FUNC);
    /* We shouldn't have many operands on the stack anymore, but the
       call address itself is still there, and it might be in %eax
       (or edx/ecx) currently, which the below writes would clobber.
       So evict all remaining operands here.  */
    save_regs(0);

    ib();
    if (nb_sse_args)
      oad(0xb8, nb_sse_args < 8 ? nb_sse_args : 8); /* mov nb_sse_args, %eax */
    else {
      o(0xc031); /* xor %eax,%eax */
    }
    save_reg(TREG_RAX);
    get_specific_reg(TREG_RAX);
    start_special_use(TREG_RAX);

    check_baddies(-1, 0);
    ib();
    gcall_or_jmp(0);
    end_special_use(TREG_RAX);
    end_special_use(TREG_RCX);
    end_special_use(TREG_RDX);
    end_special_use(TREG_RSI);
    end_special_use(TREG_RDI);
    end_special_use(TREG_R8);
    end_special_use(TREG_R9);
    end_special_use(TREG_R10);
    end_special_use(TREG_R11);

    end_special_use(TREG_XMM0);
    end_special_use(TREG_XMM1);
    end_special_use(TREG_XMM2);
    end_special_use(TREG_XMM3);
    end_special_use(TREG_XMM4);
    end_special_use(TREG_XMM5);
    end_special_use(TREG_XMM6);
    end_special_use(TREG_XMM7);

    end_special_use(TREG_ST0);
    /* end_special_use(TREG_ST1); for when we support complex args */

    if (args_size)
        gadd_sp(args_size);
    assert((vtop->type.t & VT_BTYPE) == VT_FUNC);
    vtop--;
}


#define FUNC_PROLOG_SIZE 11

static void push_arg_reg(int i) {
    loc -= 8;
    gen_modrm64(0x89, arg_regs[i], VT_LOCAL, NULL, loc);
}

/* generate function prolog of type 't' */
void gfunc_prolog(CType *func_type)
{
    X86_64_Mode mode;
    int i, addr, align, size, reg_count;
    int param_addr = 0, reg_param_index, sse_param_index;
    Sym *sym;
    CType *type;

    sym = func_type->ref;
    addr = PTR_SIZE * 2;
    loc = 0;
    ind += FUNC_PROLOG_SIZE;
    func_sub_sp_offset = ind;
    func_ret_sub = 0;

    if (func_type->ref->c == FUNC_ELLIPSIS) {
        int seen_reg_num, seen_sse_num, seen_stack_size;
        seen_reg_num = seen_sse_num = 0;
        /* frame pointer and return address */
        seen_stack_size = PTR_SIZE * 2;
        /* count the number of seen parameters */
        sym = func_type->ref;
        while ((sym = sym->next) != NULL) {
	    SValue ret[256];
	    int nret = 256;
	    for (i=0; i<nret; i++) {
		ret[i].type.t = VT_VOID;
		ret[i].r = VT_CONST;
	    }
	  
            type = &sym->type;
	    reg_count = 0;
            mode = classify_x86_64_arg_new(type, ret, nret, &size, &align, &reg_count);
	    if (mode != x86_64_mode_memory) {
		int arg_reg_num = seen_reg_num;
		int arg_sse_num = seen_sse_num;

		for(i=0; i<reg_count; i++) {
		    if (ret[i].r == TREG_RAX) {
			arg_reg_num++;
		    } else if (ret[i].r == TREG_XMM0) {
			arg_sse_num++;
		    }
		}
		if (arg_reg_num > REGN ||
		    arg_sse_num > 8) {
		    goto stack_arg;
		} else {
		    seen_reg_num = arg_reg_num;
		    seen_sse_num = arg_sse_num;
		}
	    } else {
	    stack_arg:
		seen_stack_size = ((seen_stack_size + align - 1) & -align) + size;
	    }
        }

        loc -= 16;
        /* movl $0x????????, -0x10(%rbp) */
        o(0xf045c7);
        gen_le32(seen_reg_num * 8);
        /* movl $0x????????, -0xc(%rbp) */
        o(0xf445c7);
        gen_le32(seen_sse_num * 16 + 48);
        /* movl $0x????????, -0x8(%rbp) */
        o(0xf845c7);
        gen_le32(seen_stack_size);

        /* save all register passing arguments */
        for (i = 0; i < 8; i++) {
            loc -= 16;
            o(0xd60f66); /* movq */
            gen_modrm(7 - i, VT_LOCAL, NULL, loc);
            /* movq $0, loc+8(%rbp) */
            o(0x85c748);
            gen_le32(loc + 8);
            gen_le32(0);
        }
        for (i = 0; i < REGN; i++) {
            push_arg_reg(REGN-1-i);
        }
    }

    sym = func_type->ref;
    reg_param_index = 0;
    sse_param_index = 0;

    /* if the function returns a structure, then add an
       implicit pointer parameter */
    func_vt = sym->type;
    mode = classify_x86_64_arg_new(&func_vt, NULL, 0, &size, &align, &reg_count);
    if (mode == x86_64_mode_memory) {
        push_arg_reg(reg_param_index);
        func_vc = loc;
        reg_param_index++;
    }
    /* define parameters */
    while ((sym = sym->next) != NULL) {
	SValue ret[256];
	int nret = 256;
	int i;
	for(i=0; i<nret; i++) {
	    ret[i].type.t = VT_VOID;
	    ret[i].r = VT_CONST;
	}

        type = &sym->type;
	reg_count = 0;
        mode = classify_x86_64_arg_new(type, ret, nret, &size, &align, &reg_count);
        switch (mode) {
        case x86_64_mode_integer:
        case x86_64_mode_sse:
	    for(i=0; i<reg_count; i++) {
		if (ret[i].r == TREG_RAX ||
		    ret[i].r == TREG_RDX /* XXX */) {
		    if (reg_param_index >= REGN) {
			goto revert_assignments;
		    }
		    ret[i].r = arg_regs[reg_param_index];
		    ++reg_param_index;
		} else if (ret[i].r == TREG_XMM0 ||
			   ret[i].r == TREG_XMM1) {
		    if (sse_param_index >= 8) {
			goto revert_assignments;
		    }
		    ret[i].r = TREG_XMM0 + sse_param_index;
		    ++sse_param_index;
		} else {
		    assert(0);
		}
	    }

	    /* save arguments passed by register */
	    loc -= reg_count * 8;
	    param_addr = loc;
	    for (i = 0; i < reg_count; ++i) {
		int r = ret[i].r;

		if (r < 16) {
		    gen_modrm64(0x89, r, VT_LOCAL, NULL, param_addr + ret[i].c.ull);
		} else if (r >= TREG_XMM0 && r <= TREG_XMM7) {
		    /* strictly speaking, we don't need orex here for
		       the default ABI, but in case someone modifies it
		       to pass more than eight SSE arguments ... */
		    o(0x66);
		    orex(0, r, 0, 0xd60f); /* movq */
                    gen_modrm(r, VT_LOCAL, NULL, param_addr + ret[i].c.ull);
		}
	    }
            break;

	revert_assignments:
	    /* fall through to mode_memory case */;
        case x86_64_mode_memory:
        case x86_64_mode_x87:
            addr = (addr + align - 1) & -align;
            param_addr = addr;
            addr += size;
            break;
	default: break; /* nothing to be done for x86_64_mode_none */
        }
        sym_push(sym->v & ~SYM_FIELD, type,
                 VT_LOCAL | VT_LVAL, param_addr);
    }
}

/* generate function epilog */
void gfunc_epilog(void)
{
    int v, saved_ind;

    o(0xc9); /* leave */
    if (func_ret_sub == 0) {
        o(0xc3); /* ret */
    } else {
        o(0xc2); /* ret n */
        g(func_ret_sub);
        g(func_ret_sub >> 8);
    }
    /* align local size to word & save local variables */
    v = (-loc + 15) & -16;
    saved_ind = ind;
    ind = func_sub_sp_offset - FUNC_PROLOG_SIZE;
    o(0xe5894855);  /* push %rbp, mov %rsp, %rbp */
    o(0xec8148);  /* sub rsp, stacksize */
    gen_le32(v);
    ind = saved_ind;
}

#endif /* not PE */

/* generate a jump to a label */
int gjmp(int t)
{
    ib();
    return psym(0xe9, t);
}

/* generate a jump to a fixed address */
void gjmp_addr(int a)
{
    int r;
    r = a - ind - 2;
    ib();
    if (r == (char)r) {
        g(0xeb);
        g(r);
    } else {
        oad(0xe9, a - ind - 5);
    }
}

/* generate a test. set 'inv' to invert test. Stack entry is popped */
int gtst(int inv, int t)
{
    int v, *p;

    v = vtop->r & VT_VALMASK;
    if (v == VT_CMP) {
        /* fast case : can jump directly since flags are set */
	if (vtop->c.i & 0x100)
	  {
	    /* This was a float compare.  If the parity flag is set
	       the result was unordered.  For anything except != this
	       means false and we don't jump (anding both conditions).
	       For != this means true (oring both).
	       Take care about inverting the test.  We need to jump
	       to our target if the result was unordered and test wasn't NE,
	       otherwise if unordered we don't want to jump.  */
	    vtop->c.i &= ~0x100;
	    if (!inv == (vtop->c.i != TOK_NE))
	      o(0x067a);  /* jp +6 */
	    else
	      {
	        g(0x0f);
		t = psym(0x8a, t); /* jp t */
	      }
	  }
	commit_instructions();
	inv ^= check_baddies(-1, 1);
	ib();
        g(0x0f);
        t = psym((vtop->c.i - 16) ^ inv, t);
	commit_instructions();
    } else if (v == VT_JMP || v == VT_JMPI) {
        /* && or || optimization */
        if ((v & 1) == inv) {
            /* insert vtop->c jump list in t */
            p = &vtop->c.i;
            while (*p != 0)
                p = (int *)(cur_text_section->data + *p);
            *p = t;
            t = vtop->c.i;
	    commit_instructions();
        } else {
            t = gjmp(t);
            gsym(vtop->c.i);
	    commit_instructions();
        }
    } else {
	int ll = 0;

        if (is_float(vtop->type.t)) {
            vpushi(0);
            gen_op(TOK_NE);
	}
        if ((vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {
            /* constant jmp optimization */
            if ((vtop->c.i != 0) != inv)
                t = gjmp(t);
        } else {
	    if (is64_type(vtop->type.t))
		ll = 1;
            /* test v,v
             * jXX t */
            v = gv(RC_INT);
            /* and $constant, r */
            int test = 0xe081 + 0x100 * REG_VALUE(v);
            if (check_last_instruction(test, 6)) {
		uib(1);
		ib();
                /* overwrite opcode to turn and $constant,r into test $constant,r */
                orex(32,v,0,0xf7);
                g(0xc0 + REG_VALUE(v));
                ind += 4;
	    } else if (check_last_instruction(0xe083 + 0x100 * REG_VALUE(v), 3)) {
		char c = cur_text_section->data[ind-1];
		/* XXX check necessary? sign extension... */
		if ((c&0x80) == 0) {
		    uib(1);
		    ib();
		    orex(8,v,0,0xf6);
		    g(0xc0 + REG_VALUE(v));
		    g(c);
		}
            } else {
		/* XXX we currently generate code like this:
		 * 81c3d19:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
		 * 81c3d1d:	85 c0                	test   %eax,%eax
		 * 81c3d1f:	0f 84 52 00 00 00    	je     81c3d77 <Perl_sv_2num+0x183>
		 * 81c3d25:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
		 * 81c3d29:	48 83 c0 0c          	add    $0xc,%rax
		 * 81c3d2d:	8b 08                	mov    (%rax),%ecx
		 *
		 * Which is buggy because only the low 32 bits of %rax are checked. */

		ib();
                orex(ll ? 64 : 32,v,v,0x85);
                o(0xc0 + REG_VALUE(v) * 9);
            }
	    /* Perl has lots of expressions of the form x ? 1 : 0. Handle those here. */
	    inv ^= check_baddies(TREG_RAX, 1);
	    ib();
            g(0x0f);
            t = psym(0x85 ^ inv, t);
	    check_baddies(-1, 0);
        }
    }
    vtop--;
    return t;
}

/* generate an integer binary operation */
void gen_opi(int op)
{
    int r, fr, opc, c;
    int ll, uu, cc;

    ll = is64_type(vtop[-1].type.t);
    uu = (vtop[-1].type.t & VT_UNSIGNED) != 0;
    cc = (vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;

    switch(op) {
    case '+':
    case TOK_ADDC1: /* add with carry generation */
        opc = 0;
    gen_op8: ;
	int uncache = 1;
        /* so I assume that's the idiom for checking 32-bit-ness */
        if (cc && (!ll || (int)vtop->c.ll == vtop->c.ll) &&
	    find_cached_value(vtop) == -1) {
            /* constant case */
            vswap();
            r = gv(RC_INT);
            vswap();
            c = vtop->c.i;
	    ib();
	    /* lea 0xXXXX(r), or */
	    if (opc == 0) {
		int or = get_reg(RC_INT);

		uncache_value_by_register(or);

		orex(ll?64:32, r, or, 0x8d);
		oad(0x80 | (REG_VALUE(or) << 3) | REG_VALUE(r), c);

		vtop[-1].r = or;
		cache_value(&vtop[0], vtop[0].r);
		uncache = 0;
	    } else if (c == 1 && opc == 0 || c == -1 && opc == 5) {
                /* inc r */
                orex(ll?64:32, r, 0, 0xff);
                o(0xc0 + REG_VALUE(r));
            } else if (c == -1 && opc == 0 || c == 1 && opc == 5) {
                /* dec r */
                orex(ll?64:32, r, 0, 0xff);
                o(0xc8 + REG_VALUE(r));
            } else if (c == (char)c) {
                orex(ll?64:32, r, 0, 0x83);
                o(0xc0 | (opc << 3) | REG_VALUE(r));
                g(c);
            } else {
                orex(ll?64:32, r, 0, 0x81);
                oad(0xc0 | (opc << 3) | REG_VALUE(r), c);
            }
        } else {
	    if (opc == 0) {
		int or = get_reg(RC_INT);
		gv2(RC_INT, RC_INT);
		r = vtop[-1].r;
		fr = vtop[0].r;
		ib();
		orex4(ll, r, fr, or, 0x8d); /* XXX */
		o(0x04 + REG_VALUE(or) * 8);
		g(0x00 + REG_VALUE(r) * 8 + REG_VALUE(fr));

		vtop[-1].r = or;
		uncache = 0;
	    } else {
		gv2(RC_INT, RC_INT);
		r = vtop[-1].r;
		fr = vtop[0].r;
		ib();
		orex(ll?64:32, r, fr, (opc << 3) | 0x01);
		o(0xc0 + REG_VALUE(r) + REG_VALUE(fr) * 8);
	    }
        }
        vtop--;
	if (uncache)
	    uncache_value(&vtop[0]);
        if (op >= TOK_ULT && op <= TOK_GT) {
            vtop->r = VT_CMP;
            vtop->c.i = op;
        }
        break;
    case '-':
    case TOK_SUBC1: /* sub with carry generation */
        opc = 5;
        goto gen_op8;
    case TOK_ADDC2: /* add with carry use */
        opc = 2;
        goto gen_op8;
    case TOK_SUBC2: /* sub with carry use */
        opc = 3;
        goto gen_op8;
    case '&':
        opc = 4;
        goto gen_op8;
    case '^':
        opc = 6;
        goto gen_op8;
    case '|':
        opc = 1;
        goto gen_op8;
    case '*':
        gv2(RC_INT, RC_INT);
        r = vtop[-1].r;
        fr = vtop[0].r;
        orex(ll?64:32, fr, r, 0xaf0f); /* imul fr, r */
        o(0xc0 + REG_VALUE(fr) + REG_VALUE(r) * 8);
        vtop--;
	uncache_value(&vtop[0]);
        break;
    case TOK_SHL:
        opc = 4;
        goto gen_shift;
    case TOK_SHR:
        opc = 5;
        goto gen_shift;
    case TOK_SAR:
        opc = 7;
    gen_shift:
        opc = 0xc0 | (opc << 3);
        if (cc) {
	    /* XXX cc = 1,2,3 -> lea */
            /* constant case */
            vswap();
            r = gv(RC_INT);
            vswap();
            orex(ll?64:32, r, 0, 0xc1); /* shl/shr/sar $xxx, r */
            o(opc | REG_VALUE(r));
            g(vtop->c.i & (ll ? 63 : 31));
        } else {
            /* we generate the shift in ecx */
            gv2(RC_INT, RC_RCX);
            r = vtop[-1].r;
            orex(ll?64:32, r, 0, 0xd3); /* shl/shr/sar %cl, r */
            o(opc | REG_VALUE(r));
        }
        vtop--;
	uncache_value_by_register(r);
	uncache_value(&vtop[0]);
        break;
    case TOK_UDIV:
    case TOK_UMOD:
        uu = 1;
        goto divmod;
    case '/':
    case '%':
    case TOK_PDIV:
        uu = 0;
    divmod:
        /* first operand must be in eax */
        /* XXX: need better constraint for second operand */
        gv2(RC_RAX, RC_RCX);
        r = vtop[-1].r;
        fr = vtop[0].r;
        vtop--;
        save_reg(TREG_RDX);
        orex(ll?64:32, 0, 0, uu ? 0xd231 : 0x99); /* xor %edx,%edx : cqto */
        orex(ll?64:32, fr, 0, 0xf7); /* div fr, %eax */
        o((uu ? 0xf0 : 0xf8) + REG_VALUE(fr));
        if (op == '%' || op == TOK_UMOD)
            r = TREG_RDX;
        else
            r = TREG_RAX;
        vtop->r = r;
	uncache_value(&vtop[0]);
        break;
    default:
        opc = 7;
        goto gen_op8;
    }
}

void gen_opl(int op)
{
    gen_opi(op);
}

/* generate a floating point operation 'v = t1 op t2' instruction. The
   two operands are guaranted to have the same floating point type */
/* XXX: need to use ST1 too */
void gen_opf(int op)
{
    int a, ft, fc, swapped, r;
    int float_type =
        (vtop->type.t & VT_BTYPE) == VT_LDOUBLE ? RC_ST0 : RC_FLOAT;

    /* convert constants to memory references */
    if ((vtop[-1].r & (VT_VALMASK | VT_LVAL)) == VT_CONST) {
        vswap();
        gv(float_type);
        vswap();
    }
    if ((vtop[0].r & (VT_VALMASK | VT_LVAL)) == VT_CONST)
        gv(float_type);

    /* must put at least one value in the floating point register */
    if ((vtop[-1].r & VT_LVAL) &&
        (vtop[0].r & VT_LVAL)) {
        vswap();
        gv(float_type);
        vswap();
    }
    swapped = 0;
    /* swap the stack if needed so that t1 is the register and t2 is
       the memory reference */
    if (vtop[-1].r & VT_LVAL) {
        vswap();
        swapped = 1;
    }
    if ((vtop->type.t & VT_BTYPE) == VT_LDOUBLE) {
        if (op >= TOK_ULT && op <= TOK_GT) {
            /* load on stack second operand */
            load(TREG_ST0, vtop);
            save_reg(TREG_RAX); /* eax is used by FP comparison code */
            if (op == TOK_GE || op == TOK_GT)
                swapped = !swapped;
            else if (op == TOK_EQ || op == TOK_NE)
                swapped = 0;
            if (swapped)
                o(0xc9d9); /* fxch %st(1) */
            o(0xe9da); /* fucompp */
            o(0xe0df); /* fnstsw %ax */
            if (op == TOK_EQ) {
                o(0x45e480); /* and $0x45, %ah */
                o(0x40fC80); /* cmp $0x40, %ah */
            } else if (op == TOK_NE) {
                o(0x45e480); /* and $0x45, %ah */
                o(0x40f480); /* xor $0x40, %ah */
                op = TOK_NE;
            } else if (op == TOK_GE || op == TOK_LE) {
                o(0x05c4f6); /* test $0x05, %ah */
                op = TOK_EQ;
            } else {
                o(0x45c4f6); /* test $0x45, %ah */
                op = TOK_EQ;
            }
            vtop--;
            vtop->r = VT_CMP;
            vtop->c.i = op;
        } else {
            /* no memory reference possible for long double operations */
            load(TREG_ST0, vtop);
            swapped = !swapped;

            switch(op) {
            default:
            case '+':
                a = 0;
                break;
            case '-':
                a = 4;
                if (swapped)
                    a++;
                break;
            case '*':
                a = 1;
                break;
            case '/':
                a = 6;
                if (swapped)
                    a++;
                break;
            }
            ft = vtop->type.t;
            fc = vtop->c.ul;
            o(0xde); /* fxxxp %st, %st(1) */
            o(0xc1 + (a << 3));
            vtop--;
        }
    } else {
        if (op >= TOK_ULT && op <= TOK_GT) {
            /* if saved lvalue, then we must reload it */
            r = vtop->r;
            fc = vtop->c.ul;
            if ((r & VT_VALMASK) == VT_LLOCAL) {
                SValue v1;
                r = get_reg(RC_INT);
                v1.type.t = VT_PTR;
                v1.r = VT_LOCAL | VT_LVAL;
                v1.c.ul = fc;
                load(r, &v1);
                fc = 0;
            }

            if (op == TOK_EQ || op == TOK_NE) {
                swapped = 0;
            } else {
                if (op == TOK_LE || op == TOK_LT)
                    swapped = !swapped;
                if (op == TOK_LE || op == TOK_GE) {
                    op = 0x93; /* setae */
                } else {
                    op = 0x97; /* seta */
                }
            }

            if (swapped) {
                gv(RC_FLOAT);
                vswap();
            }
            assert(!(vtop[-1].r & VT_LVAL));
            
            if ((vtop->type.t & VT_BTYPE) == VT_DOUBLE)
                o(0x66);
            
            if (vtop->r & VT_LVAL) {
		orex(0, r, vtop[-1].r, 0x2e0f); /* ucomisd */
                gen_modrm(vtop[-1].r, r, vtop->sym, fc);
            } else {
		orex(0, vtop[0].r, vtop[-1].r, 0x2e0f); /* ucomisd */
                o(0xc0 + REG_VALUE(vtop[0].r) + REG_VALUE(vtop[-1].r)*8);
            }

            vtop--;
            vtop->r = VT_CMP;
            vtop->c.i = op | 0x100;
        } else {
            assert((vtop->type.t & VT_BTYPE) != VT_LDOUBLE);
            switch(op) {
            default:
            case '+':
                a = 0;
                break;
            case '-':
                a = 4;
                break;
            case '*':
                a = 1;
                break;
            case '/':
                a = 6;
                break;
            }
            ft = vtop->type.t;
            fc = vtop->c.ul;
            assert((ft & VT_BTYPE) != VT_LDOUBLE);
            
            r = vtop->r;
            /* if saved lvalue, then we must reload it */
            if ((vtop->r & VT_VALMASK) == VT_LLOCAL) {
                SValue v1;
                r = get_reg(RC_INT);
                v1.type.t = VT_PTR;
                v1.r = VT_LOCAL | VT_LVAL;
                v1.c.ul = fc;
                load(r, &v1);
                fc = 0;
            }
            
            assert(!(vtop[-1].r & VT_LVAL));
            if (swapped) {
                assert(vtop->r & VT_LVAL);
                gv(RC_FLOAT);
                vswap();
            }
            
            if ((ft & VT_BTYPE) == VT_DOUBLE) {
                o(0xf2);
            } else {
                o(0xf3);
            }
            if (vtop->r & VT_LVAL) {
		orex(0, r, vtop[-1].r, 0);
            } else {
		orex(0, vtop[-1].r, vtop[0].r, 0);
            }

            o(0x0f);
            o(0x58 + a);
            
            if (vtop->r & VT_LVAL) {
                gen_modrm(vtop[-1].r, r, vtop->sym, fc);
            } else {
                o(0xc0 + REG_VALUE(vtop[0].r) + REG_VALUE(vtop[-1].r)*8);
            }

            vtop--;
        }
    }
}

/* convert integers to fp 't' type. Must handle 'int', 'unsigned int'
   and 'long long' cases. */
void gen_cvt_itof(int t)
{
    if ((t & VT_BTYPE) == VT_LDOUBLE) {
        save_reg(TREG_ST0);
        gv(RC_INT);
        if ((vtop->type.t & VT_BTYPE) == VT_LLONG) {
            /* signed long long to float/double/long double (unsigned case
               is handled generically) */
	    orex(0, vtop->r, 0, 0);
            o(0x50 + REG_VALUE(vtop->r)); /* push r */
            o(0x242cdf); /* fildll (%rsp) */
            o(0x08c48348); /* add $8, %rsp */
        } else if ((vtop->type.t & (VT_BTYPE | VT_UNSIGNED)) ==
                   (VT_INT | VT_UNSIGNED)) {
            /* unsigned int to float/double/long double */
            o(0x6a); /* push $0 */
            g(0x00);
	    orex(0, vtop->r, 0, 0);
            o(0x50 + REG_VALUE(vtop->r)); /* push r */
            o(0x242cdf); /* fildll (%rsp) */
            o(0x10c48348); /* add $16, %rsp */
        } else {
            /* int to float/double/long double */
	    orex(0, vtop->r, 0, 0);
            o(0x50 + REG_VALUE(vtop->r)); /* push r */
            o(0x2404db); /* fildl (%rsp) */
            o(0x08c48348); /* add $8, %rsp */
        }
        vtop->r = TREG_ST0;
    } else {
        int r = get_reg(RC_FLOAT);
	int bs = 32;
        gv(RC_INT);
        o(0xf2 + ((t & VT_BTYPE) == VT_FLOAT?1:0));
        if ((vtop->type.t & (VT_BTYPE | VT_UNSIGNED)) ==
            (VT_INT | VT_UNSIGNED) ||
            (vtop->type.t & VT_BTYPE) == VT_LLONG) {
	    bs = 64;
        }
	orex(bs, vtop->r, r, 0x2a0f);
        o(0xc0 + REG_VALUE(vtop->r & VT_VALMASK) + REG_VALUE(r)*8); /* cvtsi2sd */
        vtop->r = r;
    }
}

/* convert from one floating point type to another */
void gen_cvt_ftof(int t)
{
    int ft, bt, tbt;

    ft = vtop->type.t;
    bt = ft & VT_BTYPE;
    tbt = t & VT_BTYPE;
    
    if (bt == VT_FLOAT) {
        gv(RC_FLOAT);
        if (tbt == VT_DOUBLE) {
	    orex(0, vtop->r, vtop->r, 0);
            o(0x140f); /* unpcklps */
            o(0xc0 + REG_VALUE(vtop->r)*9);
	    orex(0, vtop->r, vtop->r, 0);
            o(0x5a0f); /* cvtps2pd */
            o(0xc0 + REG_VALUE(vtop->r)*9);
        } else if (tbt == VT_LDOUBLE) {
            save_reg(RC_ST0);
            /* movss %xmm0,-0x10(%rsp) */
            o(0x110ff3);
	    orex(0, vtop->r, 0, 0);
            o(0x44 + REG_VALUE(vtop->r)*8);
            o(0xf024);
            o(0xf02444d9); /* flds -0x10(%rsp) */
            vtop->r = TREG_ST0;
        }
    } else if (bt == VT_DOUBLE) {
        gv(RC_FLOAT);
        if (tbt == VT_FLOAT) {
	    orex(0, vtop->r, vtop->r, 0);
            o(0x140f66); /* unpcklpd */
            o(0xc0 + REG_VALUE(vtop->r)*9);
	    orex(0, vtop->r, vtop->r, 0);
            o(0x5a0f66); /* cvtpd2ps */
            o(0xc0 + REG_VALUE(vtop->r)*9);
        } else if (tbt == VT_LDOUBLE) {
            save_reg(RC_ST0);
            /* movsd %xmm0,-0x10(%rsp) */
	    orex(0, 0, vtop->r, 0);
            o(0x110ff2);
            o(0x44 + REG_VALUE(vtop->r)*8);
            o(0xf024);
            o(0xf02444dd); /* fldl -0x10(%rsp) */
            vtop->r = TREG_ST0;
        }
    } else {
        int r;
        gv(RC_ST0);
        r = get_reg(RC_FLOAT);
        if (tbt == VT_DOUBLE) {
            o(0xf0245cdd); /* fstpl -0x10(%rsp) */
            /* movsd -0x10(%rsp),%xmm0 */
	    orex(0, 0, r, 0);
            o(0x100ff2);
            o(0x44 + REG_VALUE(r)*8);
            o(0xf024);
            vtop->r = r;
        } else if (tbt == VT_FLOAT) {
            o(0xf0245cd9); /* fstps -0x10(%rsp) */
            /* movss -0x10(%rsp),%xmm0 */
	    orex(0, 0, r, 0);
            o(0x100ff3);
            o(0x44 + REG_VALUE(r)*8);
            o(0xf024);
            vtop->r = r;
        }
    }
}

/* convert fp to int 't' type */
void gen_cvt_ftoi(int t)
{
    int ft, bt, size, r;
    ft = vtop->type.t;
    bt = ft & VT_BTYPE;
    if (bt == VT_LDOUBLE) {
        gen_cvt_ftof(VT_DOUBLE);
        bt = VT_DOUBLE;
    }

    gv(RC_FLOAT);
    if (t != VT_INT)
        size = 8;
    else
        size = 4;

    r = get_reg(RC_INT);
    if (bt == VT_FLOAT) {
        o(0xf3);
    } else if (bt == VT_DOUBLE) {
        o(0xf2);
    } else {
        assert(0);
    }
    orex(size * 8, vtop->r&8, r, 0); /* cvttss2si or cvttsd2si */
    o(0x2c0f);
    o(0xc0 + REG_VALUE(vtop->r) + REG_VALUE(r)*8);
    vtop->r = r;
}

/* computed goto support */
void ggoto(void)
{
    gcall_or_jmp(1);
    vtop--;
}

/* Save the stack pointer onto the stack and return the location of its address */
ST_FUNC void gen_vla_sp_save(int addr) {
    /* mov %rsp,addr(%rbp)*/
    gen_modrm64(0x89, TREG_RSP, VT_LOCAL, NULL, addr);
}

/* Restore the SP from a location on the stack */
ST_FUNC void gen_vla_sp_restore(int addr) {
    gen_modrm64(0x8b, TREG_RSP, VT_LOCAL, NULL, addr);
}

/* Subtract from the stack pointer, and push the resulting value onto the stack */
ST_FUNC void gen_vla_alloc(CType *type, int align) {
#ifdef TCC_TARGET_PE
    /* alloca does more than just adjust %rsp on Windows */
    vpush_global_sym(&func_old_type, TOK_alloca);
    vswap(); /* Move alloca ref past allocation size */
    gfunc_call(1);
    vset(type, REG_IRET, 0);
#else
    int r;
    r = gv(RC_INT); /* allocation size */
    /* sub r,%rsp */
    orex(64, r, 0, 0x2b);
    o(0xe0 | REG_VALUE(r));
    /* We align to 16 bytes rather than align */
    /* and ~15, %rsp */
    o(0xf0e48348);
    /* mov %rsp, r */
    orex(64, r, 0, 0x89);
    o(0xe0 | REG_VALUE(r));
    vpop();
    vset(type, r, 0);
#endif
}


/* end of x86-64 code generator */
/*************************************************************/
#endif /* ! TARGET_DEFS_ONLY */
/******************************************************/
