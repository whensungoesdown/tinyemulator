#include "xed/xed-interface.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
//-----------------------------------------------------------------------------//
#define TE_SUCCESS		0x0
#define TE_EMULATION_END	0x8001
#define TE_JUMP			0x1002
#define TE_JMP_REL32		0x1003
#define TE_JMP_RM64		0x1004
#define TE_CALL_NEAR		0x1005
//-----------------------------------------------------------------------------//
#define GENERAL_REGISTERS 16


typedef unsigned char Bit8u;
typedef signed char Bit8s;
typedef unsigned short Bit16u;
typedef signed short Bit16s;
typedef unsigned long Bit32u;
typedef signed long Bit32s;
typedef unsigned long long int Bit64u;
typedef signed long long int Bit64s;


typedef struct {
	union {
		struct {
			union {
				Bit16u rx;
				struct {
					Bit8u rl;
					Bit8u rh;
				} byte;
			};
			Bit16u  word_filler;
			Bit32u dword_filler;
		} word;
		Bit64u rrx;
		struct {
			Bit32u erx;  // lo 32 bits
			Bit32u hrx;  // hi 32 bits
		} dword;
	};
} gen_reg_t;

typedef struct 
{
	Bit64u CF 		:1;
	Bit64u reserved0	:1;
	Bit64u PF		:1;
	Bit64u reserved1	:1;
	Bit64u AF		:1;
	Bit64u reserved2	:1;
	Bit64u ZF		:1;
	Bit64u SF		:1;
	Bit64u TF		:1;
	Bit64u IF		:1;
	Bit64u DF		:1;
	Bit64u OF		:1;
	Bit64u IOPL		:2;
	Bit64u NT		:1;
	Bit64u reserved3	:1;

	Bit64u RF		:1;
	Bit64u VM		:1;
	Bit64u AC		:1;
	Bit64u VIF		:1;
	Bit64u VIP		:1;
	Bit64u ID		:1;
	Bit64u reserved4	:10;

	Bit64u reserved5	:32;	
} flags_reg_t;

enum Regs64 {
	REG_RAX,
	REG_RCX,
	REG_RDX,
	REG_RBX,
	REG_RSP,
	REG_RBP,
	REG_RSI,
	REG_RDI,
	REG_R8,
	REG_R9,
	REG_R10,
	REG_R11,
	REG_R12,
	REG_R13,
	REG_R14,
	REG_R15,
};

static const unsigned REG_RIP = (GENERAL_REGISTERS);

typedef struct {
	// General register set
	// rax: accumulator
	// rbx: base
	// rcx: count
	// rdx: data
	// rbp: base pointer
	// rsi: source index
	// rdi: destination index
	// esp: stack pointer
	// r8..r15 x86-64 extended registers
	// rip: instruction pointer
	// tmp: temp register
	// nil: null register
	gen_reg_t gen_reg[GENERAL_REGISTERS+3];
	
	Bit64u pseudo_fs; // contain virtual address of fs base

	flags_reg_t rflags;

	void* stack_buf;
	int stack_buf_len;
} cpu_t;
//-----------------------------------------------------------------------------//
// memory content
typedef struct {
	Bit64u address;
	Bit64u value;
} mc_t;


typedef struct {
	union {
		struct {
			Bit8u rm	: 3;
			Bit8u reg	: 3;
			Bit8u mod	: 2;
		};
		Bit8u byte;
	};
} modrm_t;

typedef struct
{
	union
	{
		struct
		{
			Bit8u base	:3;
			Bit8u index	:3;
			Bit8u scale	:2;
		};
		Bit8u byte;
	};
} sib_t;
//-----------------------------------------------------------------------------//
cpu_t g_cpu = {0};
//-----------------------------------------------------------------------------//
// glibc does not support arch_prctl
int arch_prctl (int code, unsigned long long* addr)
{    
	    return syscall(SYS_arch_prctl, code, addr);
}
//-----------------------------------------------------------------------------//
int isValidPtr(const void*p, int len) {
	if (!p) {
		return 0;
	}
	int ret = 1;
	int nullfd = open("/dev/random", O_WRONLY);
	if (write(nullfd, p, len) < 0) {
		ret = 0;
		/* Not OK */
	}
	close(nullfd);
	return ret;
}
int isValidOrNullPtr(const void*p, int len) {
	return !p||isValidPtr(p, len);
}
//-----------------------------------------------------------------------------//
int try_read_memory8 (xed_uint64_t address, xed_uint8_t* pret_value, mc_t* mc, int mc_max_cnt)
{
	// first check mc
	// if not there, read the real memory within try catch
	int i = 0;

	for (i = 0; i < mc_max_cnt; i++)
	{
		if (address == mc->address)
		{
			*pret_value = mc->value;
			return 0;
		}
	}

	if (isValidPtr((void*)address, 4))
	{
		*pret_value = *(xed_uint8_t*)address;
	}
	else
	{
		return -1;
	}
	return 0;
}
//-----------------------------------------------------------------------------//
int try_read_memory16 (xed_uint64_t address, xed_uint16_t* pret_value, mc_t* mc, int mc_max_cnt)
{
	// first check mc
	// if not there, read the real memory within try catch
	int i = 0;

	for (i = 0; i < mc_max_cnt; i++)
	{
		if (address == mc->address)
		{
			*pret_value = mc->value;
			return 0;
		}
	}

	if (isValidPtr((void*)address, 4))
	{
		*pret_value = *(xed_uint16_t*)address;
	}
	else
	{
		return -1;
	}
	return 0;
}
//-----------------------------------------------------------------------------//	
int try_read_memory32 (xed_uint64_t address, xed_uint32_t* pret_value, mc_t* mc, int mc_max_cnt)
{
	// first check mc
	// if not there, read the real memory within try catch
	int i = 0;

	for (i = 0; i < mc_max_cnt; i++)
	{
		if (address == mc->address)
		{
			*pret_value = mc->value;
			return 0;
		}
	}

	if (isValidPtr((void*)address, 4))
	{
		*pret_value = *(xed_uint32_t*)address;
	}
	else
	{
		return -1;
	}
	return 0;
}
//-----------------------------------------------------------------------------//
int try_read_memory64 (xed_uint64_t address, xed_uint64_t* pret_value, mc_t* mc, int mc_max_cnt)
{
	// first check mc
	// if not there, read the real memory within try catch
	int i = 0;

	for (i = 0; i < mc_max_cnt; i++)
	{
		if (address == mc->address)
		{
			*pret_value = mc->value;
			return 0;
		}
	}

	if (isValidPtr((void*)address, 8))
	{
		*pret_value = *(xed_uint64_t*)address;
	}
	else
	{
		return -1;
	}
	return 0;
}
//-----------------------------------------------------------------------------//
xed_uint64_t get_sib (xed_decoded_inst_t* xedd, cpu_t* cpu, modrm_t modrm)
{
	xed_uint64_t ret_value;
	sib_t sib;
	int i = 0;
	xed_uint8_t byte;
	int found = 0;
	xed_uint64_t base_value;
	xed_uint64_t index_value;
	xed_uint8_t scale_value;
	xed_int64_t disp = 0;


	for (i = 1; i < 15; i++)
	{
		byte = xed_decoded_inst_get_byte(xedd, i);
		if (modrm.byte == byte)
		{
			// found modrm, next byte is sib
			found = 1;
			break;
		}
	}

	if (!found)
	{
		printf("Error in get_sib!!!!!\n");
		// throw exception
		return -1;
	}

	sib.byte = xed_decoded_inst_get_byte(xedd, i + 1);
	printf("get sib:%x at byte %d\t", sib.byte, i + 1);

	if (xed_operand_values_has_memory_displacement(xedd))
	{
		xed_uint_t disp_bits =
			xed_decoded_inst_get_memory_displacement_width(xedd, 0);
		if (disp_bits)
		{
			printf("DISPLACEMENT_BYTES= %u ", disp_bits);
			disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
			printf("0x" XED_FMT_LX16 " base10=" XED_FMT_LD "\t", disp, disp);
		}
	}

	printf("SCALE:%x, BASE:%x, INDEX:%x\t", sib.scale, sib.base, sib.index);


	switch (sib.scale)
	{
		case 0:
			scale_value = 1;
			break;
		case 1:
			scale_value = 2;
			break;
		case 2:
			scale_value = 4;
			break;
		case 3:
			scale_value = 8;
			break;
	}

	if (4 == sib.index) // it means none
	{
		//printf("Error RSP not allowed in SIB\t");
		//return -1;
		index_value = 0;
	}
	else
	{
		index_value = cpu->gen_reg[sib.index].rrx;
	}

	if (5 == sib.base && 0 == modrm.mod) // rbp
	{
		base_value = 0;
	}
	else
	{
		base_value = cpu->gen_reg[sib.base].rrx;
	}


	printf("INDEX * SCALE + BASE + DISP (%lx * %x + %lx + %lx)\t", index_value, scale_value, base_value, disp);
	ret_value = index_value * scale_value + base_value + disp;

	return ret_value;
}
//-----------------------------------------------------------------------------//

xed_uint32_t get_r32 (cpu_t* cpu, modrm_t modrm)
{
	switch (modrm.reg)
	{
		case 0:
			printf("EAX: 0x%lx\t", cpu->gen_reg[REG_RAX].dword.erx);
			return cpu->gen_reg[REG_RAX].dword.erx;
		case 1:
			printf("ECX: 0x%lx\t", cpu->gen_reg[REG_RCX].dword.erx);
			return cpu->gen_reg[REG_RCX].dword.erx;
		case 2:
			printf("EDX: 0x%lx\t", cpu->gen_reg[REG_RDX].dword.erx);
			return cpu->gen_reg[REG_RDX].dword.erx;
		case 3:
			printf("EBX: 0x%lx\t", cpu->gen_reg[REG_RBX].dword.erx);
			return cpu->gen_reg[REG_RBX].dword.erx;
		case 4:
			printf("ESP: 0x%lx\t", cpu->gen_reg[REG_RSP].dword.erx);
			return cpu->gen_reg[REG_RSP].dword.erx;
		case 5:
			printf("EBP: 0x%lx\t", cpu->gen_reg[REG_RBP].dword.erx);
			return cpu->gen_reg[REG_RBP].dword.erx;
		case 6:
			printf("ESI: 0x%lx\t", cpu->gen_reg[REG_RSI].dword.erx);
			return cpu->gen_reg[REG_RSI].dword.erx;
		case 7:
			printf("EDI: 0x%lx\t", cpu->gen_reg[REG_RDI].dword.erx);
			return cpu->gen_reg[REG_RDI].dword.erx;
	}

}
//-----------------------------------------------------------------------------//
xed_uint8_t get_rm8 (xed_decoded_inst_t* xedd, cpu_t* cpu, modrm_t modrm, mc_t* mc, int mc_max_cnt)
{
	xed_int64_t address = 0;
	xed_int64_t disp = 0;
	xed_uint8_t ret_value = 0;

	switch (modrm.mod)
	{
		case 0:
		case 1:
		case 2:
			{
				if (xed_operand_values_has_memory_displacement(xedd))
				{
					xed_uint_t disp_bits =
						xed_decoded_inst_get_memory_displacement_width(xedd, 0);
					if (disp_bits)
					{
						printf("DISPLACEMENT_BYTES= %u ", disp_bits);
						disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
						printf("0x" XED_FMT_LX16 " base10=" XED_FMT_LD "\t", disp, disp);
					}
				}

				switch (modrm.rm)
				{
					case 0:
						address = cpu->gen_reg[REG_RAX].rrx + disp;
						break;
					case 1:
						address = cpu->gen_reg[REG_RCX].rrx + disp;
						break;
					case 2:
						address = cpu->gen_reg[REG_RDX].rrx + disp;
						break;
					case 3:
						address = cpu->gen_reg[REG_RBX].rrx + disp;
						break;
					case 4:
						printf("SIB unimplemented!!!!!!!!!!!\n");
						break;
					case 5:
						if (0 == modrm.mod)
						{
							printf("mod 0, RM 101 SIB unimplemented!!!!!!!!!!!\n");
						}
						else
						{
							address = cpu->gen_reg[REG_RBP].rrx + disp;
						}
						break;
					case 6:
						address = cpu->gen_reg[REG_RSI].rrx + disp;
						break;
					case 7: 
						address = cpu->gen_reg[REG_RDI].rrx + disp;
						break;
				}

				// if it's on the stack buffer, overwrite directly, no mc needed
				if ((address >= (xed_uint64_t)cpu->stack_buf) && (address <= (xed_uint64_t)cpu->stack_buf + cpu->stack_buf_len))
				{
					ret_value =  *(xed_uint8_t*)address;
				}
				else
				{
					int ret = 0;
					// wait for testcase
					printf("Read memory outside of current stack, address 0x%lx\t", address);
					ret = try_read_memory8(address, &ret_value, mc, mc_max_cnt);
					if (-1 == ret)
					{
						printf("address invalid, emulated program should crash or throw sigfault\t");
					}
				}
				printf("address: 0x%lx value: 0x%x\t", address, ret_value);
			}
			break;
		case 3:
			{
				switch (modrm.rm)
				{
					case 0:
						ret_value = cpu->gen_reg[REG_RAX].word.byte.rl;
						printf("AL: 0x%x\t", ret_value);
						break;
					case 1:
						ret_value = cpu->gen_reg[REG_RCX].word.byte.rl;
						printf("CL: 0x%x\t", ret_value);
						break;
					case 2:
						ret_value = cpu->gen_reg[REG_RDX].word.byte.rl;
						printf("DL: 0x%x\t", ret_value);
						break;
					case 3:
						ret_value = cpu->gen_reg[REG_RBX].word.byte.rl;
						printf("BL: 0x%x\t", ret_value);
						break;
					case 4: // AH
						ret_value = cpu->gen_reg[REG_RAX].word.byte.rh;
						printf("AH: 0x%x\t", ret_value);
						break;
					case 5: // CH
						ret_value = cpu->gen_reg[REG_RCX].word.byte.rh;
						printf("CH: 0x%x\t", ret_value);
						break;
					case 6: // DH
						ret_value = cpu->gen_reg[REG_RDX].word.byte.rh;
						printf("DH: 0x%x\t", ret_value);
						break;
					case 7: // BH
						ret_value = cpu->gen_reg[REG_RBX].word.byte.rh;
						printf("BH: 0x%x\t", ret_value);
						break;
				}
			}
			break;
	}


	return ret_value;

}
//-----------------------------------------------------------------------------//
xed_uint16_t get_rm16 (xed_decoded_inst_t* xedd, cpu_t* cpu, modrm_t modrm, mc_t* mc, int mc_max_cnt)
{
	xed_int64_t address = 0;
	xed_int64_t disp = 0;
	xed_uint16_t ret_value = 0;

	switch (modrm.mod)
	{
		case 0:
		case 1:
		case 2:
			{
				if (xed_operand_values_has_memory_displacement(xedd))
				{
					xed_uint_t disp_bits =
						xed_decoded_inst_get_memory_displacement_width(xedd, 0);
					if (disp_bits)
					{
						printf("DISPLACEMENT_BYTES= %u ", disp_bits);
						disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
						printf("0x" XED_FMT_LX16 " base10=" XED_FMT_LD "\t", disp, disp);
					}
				}

				switch (modrm.rm)
				{
					case 0:
						address = cpu->gen_reg[REG_RAX].rrx + disp;
						break;
					case 1:
						address = cpu->gen_reg[REG_RCX].rrx + disp;
						break;
					case 2:
						address = cpu->gen_reg[REG_RDX].rrx + disp;
						break;
					case 3:
						address = cpu->gen_reg[REG_RBX].rrx + disp;
						break;
					case 4:
						printf("SIB unimplemented!!!!!!!!!!!\n");
						break;
					case 5:
						if (0 == modrm.mod)
						{
							printf("mod 0, RM 101 SIB unimplemented!!!!!!!!!!!\n");
						}
						else
						{
							address = cpu->gen_reg[REG_RBP].rrx + disp;
						}
						break;
					case 6:
						address = cpu->gen_reg[REG_RSI].rrx + disp;
						break;
					case 7: 
						address = cpu->gen_reg[REG_RDI].rrx + disp;
						break;
				}

				// if it's on the stack buffer, overwrite directly, no mc needed
				if ((address >= (xed_uint64_t)cpu->stack_buf) && (address <= (xed_uint64_t)cpu->stack_buf + cpu->stack_buf_len))
				{
					ret_value =  *(xed_uint16_t*)address;
				}
				else
				{
					int ret = 0;
					// wait for testcase
					printf("Read memory outside of current stack, address 0x%lx\t", address);
					ret = try_read_memory16(address, &ret_value, mc, mc_max_cnt);
					if (-1 == ret)
					{
						printf("address invalid, emulated program should crash or throw sigfault\t");
					}
				}
				printf("address: 0x%lx value: 0x%x\t", address, ret_value);
			}
			break;
		case 3:
			{
				switch (modrm.rm)
				{
					case 0:
						ret_value = cpu->gen_reg[REG_RAX].word.rx;
						printf("AX: 0x%x\t", ret_value);
						break;
					case 1:
						ret_value = cpu->gen_reg[REG_RCX].word.rx;
						printf("CX: 0x%x\t", ret_value);
						break;
					case 2:
						ret_value = cpu->gen_reg[REG_RDX].word.rx;
						printf("DX: 0x%x\t", ret_value);
						break;
					case 3:
						ret_value = cpu->gen_reg[REG_RBX].word.rx;
						printf("BX: 0x%x\t", ret_value);
						break;
					case 4: 
						ret_value = cpu->gen_reg[REG_RSP].word.rx;
						printf("SP: 0x%x\t", ret_value);
						break;
					case 5: 
						ret_value = cpu->gen_reg[REG_RBP].word.rx;
						printf("BP: 0x%x\t", ret_value);
						break;
					case 6: 
						ret_value = cpu->gen_reg[REG_RSI].word.rx;
						printf("SI: 0x%x\t", ret_value);
						break;
					case 7:
						ret_value = cpu->gen_reg[REG_RDI].word.rx;
						printf("DI: 0x%x\t", ret_value);
						break;
				}
			}
			break;
	}


	return ret_value;
}
//-----------------------------------------------------------------------------//
xed_uint32_t get_rm32 (xed_decoded_inst_t* xedd, cpu_t* cpu, modrm_t modrm, mc_t* mc, int mc_max_cnt)
{
	xed_int64_t address = 0;
	xed_int64_t disp = 0;
	xed_uint32_t ret_value = 0;

	switch (modrm.mod)
	{
		case 0:
		case 1:
		case 2:
			{
				if (xed_operand_values_has_memory_displacement(xedd))
				{
					xed_uint_t disp_bits =
						xed_decoded_inst_get_memory_displacement_width(xedd, 0);
					if (disp_bits)
					{
						printf("DISPLACEMENT_BYTES= %u ", disp_bits);
						disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
						printf("0x" XED_FMT_LX16 " base10=" XED_FMT_LD "\t", disp, disp);
					}
				}

				switch (modrm.rm)
				{
					case 0:
						address = cpu->gen_reg[REG_RAX].rrx + disp;
						break;
					case 1:
						address = cpu->gen_reg[REG_RCX].rrx + disp;
						break;
					case 2:
						address = cpu->gen_reg[REG_RDX].rrx + disp;
						break;
					case 3:
						address = cpu->gen_reg[REG_RBX].rrx + disp;
						break;
					case 4:
						{
							// mod 00 rm 100    SIB
							// mod 01 rm 100    SIB + disp8
							// mod 02 rm 100    SIB + disp32	
							
							//xed_reg_enum_t base;
							//xed_reg_enum_t index;
							//xed_int_t scale;

							// incorrect when having FS segment override 0x64

							//base = xed_decoded_inst_get_base_reg(xedd, 0);
							//printf("BASE= %3s %d\t", xed_reg_enum_t2str(base), base - XED_REG_RAX);
							//index = xed_decoded_inst_get_index_reg(xedd, 0);
							//printf("INDEX= %3s %d\t", xed_reg_enum_t2str(index), index - XED_REG_RAX);
							//scale = xed_decoded_inst_get_scale(xedd, 0);
							//printf("SCALE= %d\t", scale);


							address = get_sib(xedd, cpu, modrm);
						}
						break;
					case 5:
						if (0 == modrm.mod)
						{
							printf("mod 0, RM 101 SIB unimplemented!!!!!!!!!!!\n");
						}
						else
						{
							address = cpu->gen_reg[REG_RBP].rrx + disp;
						}
						break;
					case 6:
						address = cpu->gen_reg[REG_RSI].rrx + disp;
						break;
					case 7: 
						address = cpu->gen_reg[REG_RDI].rrx + disp;
						break;
				}

				// if it's on the stack buffer, overwrite directly, no mc needed
				if ((address >= (xed_uint64_t)cpu->stack_buf) && (address <= (xed_uint64_t)cpu->stack_buf + cpu->stack_buf_len))
				{
					ret_value =  *(xed_uint32_t*)address;
				}
				else
				{
					int ret = 0;
					// wait for testcase
					printf("Read memory outside of current stack, address 0x%lx\t", address);
					ret = try_read_memory32(address, &ret_value, mc, mc_max_cnt);
					if (-1 == ret)
					{
						printf("address invalid, emulated program should crash or throw sigfault\t");
					}
				}
				printf("address: 0x%lx value: 0x%x\t", address, ret_value);
			}
			break;
		case 3:
			{
				switch (modrm.rm)
				{
					case 0:
						ret_value = cpu->gen_reg[REG_RAX].dword.erx;
						printf("EAX: 0x%x\t", ret_value);
						break;
					case 1:
						ret_value = cpu->gen_reg[REG_RCX].dword.erx;
						printf("ECX: 0x%x\t", ret_value);
						break;
					case 2:
						ret_value = cpu->gen_reg[REG_RDX].dword.erx;
						printf("EDX: 0x%x\t", ret_value);
						break;
					case 3:
						ret_value = cpu->gen_reg[REG_RBX].dword.erx;
						printf("EBX: 0x%x\t", ret_value);
						break;
					case 4:
						ret_value = cpu->gen_reg[REG_RSP].dword.erx;
						printf("ESP: 0x%x\t", ret_value);
						break;
					case 5:
						ret_value = cpu->gen_reg[REG_RBP].dword.erx;
						printf("EBP: 0x%x\t", ret_value);
						break;
					case 6:
						ret_value = cpu->gen_reg[REG_RSI].dword.erx;
						printf("ESI: 0x%x\t", ret_value);
						break;
					case 7:
						ret_value = cpu->gen_reg[REG_RDI].dword.erx;
						printf("EDI: 0x%x\t", ret_value);
						break;
				}
			}
			break;
	}


	return ret_value;
}
//-----------------------------------------------------------------------------//
xed_uint64_t get_m64 (xed_decoded_inst_t* xedd, cpu_t* cpu, modrm_t modrm)
{
	xed_uint64_t address = 0;
	xed_int64_t disp = 0;

	switch (modrm.mod)
	{
		case 0:
		case 1:
		case 2:
			{
				if (xed_operand_values_has_memory_displacement(xedd))
				{
					xed_uint_t disp_bits =
						xed_decoded_inst_get_memory_displacement_width(xedd, 0);
					if (disp_bits)
					{
						printf("DISPLACEMENT_BYTES= %u ", disp_bits);
						disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
						printf("0x" XED_FMT_LX16 " base10=" XED_FMT_LD "\t", disp, disp);
					}
				}

				switch (modrm.rm)
				{
					case 0:
						if (1 == modrm.mod)
						{
							printf("SIB Unimplemented!!!!!!!!!!!\n");
							break;
						}
						address = cpu->gen_reg[REG_RAX].rrx + disp;
						printf("RAX:0x%llx + disp:0x%lx\t", cpu->gen_reg[REG_RAX].rrx, disp);
						break;
					case 1:
						address = cpu->gen_reg[REG_RCX].rrx + disp;
						printf("RCX:0x%llx + disp:0x%lx\t", cpu->gen_reg[REG_RCX].rrx, disp);
						break;
					case 2:
						address = cpu->gen_reg[REG_RDX].rrx + disp;
						printf("RDX:0x%llx + disp:0x%lx\t", cpu->gen_reg[REG_RDX].rrx, disp);
						break;
					case 3:
						address = cpu->gen_reg[REG_RBX].rrx + disp;
						printf("RBX:0x%llx + disp:0x%lx\t", cpu->gen_reg[REG_RBX].rrx, disp);
						break;
					case 4:
						printf("SIB Unimplemented!!!!!!!!!!!\n");
						break;
					case 5:
						if (0 == modrm.mod)
						{	// 2.2.1.6 RIP-Relative Addressing  64-bit mode
							printf("mod 0, RM 101 SIB, RIP:0x%llx disp32:0x%lx\t", cpu->gen_reg[REG_RIP].rrx, disp);
							address = cpu->gen_reg[REG_RIP].rrx + disp;
						}
						else
						{
							address = cpu->gen_reg[REG_RBP].rrx + disp;
							printf("RBP:0x%llx + disp:0x%lx\t", cpu->gen_reg[REG_RBP].rrx, disp);
						}
						break;
					case 6:
						address = cpu->gen_reg[REG_RSI].rrx + disp;
						printf("RSI:0x%llx + disp:0x%lx\t", cpu->gen_reg[REG_RSI].rrx, disp);
						break;
					case 7: 
						address = cpu->gen_reg[REG_RDI].rrx + disp;
						printf("RDI:0x%llx + disp:0x%lx\t", cpu->gen_reg[REG_RDI].rrx, disp);
						break;
				}

				printf("Effective address: 0x%lx\t", address);

			}
			break;
		case 3:
			{
				printf("ERROR !!!!! get_m64, effective address should not use this mod\t");
				return 0;
			}
			break;
	}

	return address;
}
//-----------------------------------------------------------------------------//
xed_uint64_t get_rm64 (xed_decoded_inst_t* xedd, cpu_t* cpu, modrm_t modrm, mc_t* mc, int mc_max_cnt)
{
	xed_uint64_t address = 0;
	xed_int64_t disp = 0;
	xed_uint64_t ret_value = 0;
	xed_uint64_t segbase = 0;

	if (xed_operand_values_has_segment_prefix(xedd))
	{
		xed_reg_enum_t seg;

		seg = xed_operand_values_get_seg_reg(xedd, 0); // only memop 0?
		printf("memop 0 seg:%s\t", xed_reg_enum_t2str(seg));
		switch (seg)
		{
			case XED_REG_FS:
				segbase = cpu->pseudo_fs;
				printf("pseduo_fs:0x%lx\t", segbase);
			       break;
			case XED_REG_CS:
			case XED_REG_SS:	       
			case XED_REG_DS:
			case XED_REG_ES:
			case XED_REG_GS:
			       segbase = 0;
			       break;
			default:
			       printf("ERROR: wrong seg code\n\n");
			       break;
		}

	}

	switch (modrm.mod)
	{
		case 0:
		case 1:
		case 2:
			{
				if (xed_operand_values_has_memory_displacement(xedd))
				{
					xed_uint_t disp_bits =
						xed_decoded_inst_get_memory_displacement_width(xedd, 0);
					if (disp_bits)
					{
						printf("DISPLACEMENT_BYTES= %u ", disp_bits);
						disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
						printf("0x" XED_FMT_LX16 " base10=" XED_FMT_LD "\t", disp, disp);
					}
				}

				switch (modrm.rm)
				{
					case 0:
						address = cpu->gen_reg[REG_RAX].rrx + disp;
						break;
					case 1:
						address = cpu->gen_reg[REG_RCX].rrx + disp;
						break;
					case 2:
						address = cpu->gen_reg[REG_RDX].rrx + disp;
						break;
					case 3:
						address = cpu->gen_reg[REG_RBX].rrx + disp;
						break;
					case 4:
						{	
							// mod 00 rm 100    SIB
							// mod 01 rm 100    SIB + disp8
							// mod 02 rm 100    SIB + disp32	
							
							//xed_reg_enum_t base;
							//xed_reg_enum_t index;
							//xed_int_t scale;

							// incorrect when having FS segment override 0x64

							//base = xed_decoded_inst_get_base_reg(xedd, 0);
							//printf("BASE= %3s %d\t", xed_reg_enum_t2str(base), base - XED_REG_RAX);
							//index = xed_decoded_inst_get_index_reg(xedd, 0);
							//printf("INDEX= %3s %d\t", xed_reg_enum_t2str(index), index - XED_REG_RAX);
							//scale = xed_decoded_inst_get_scale(xedd, 0);
							//printf("SCALE= %d\t", scale);


							address = get_sib(xedd, cpu, modrm);
						}
						break;
					case 5:
						if (0 == modrm.mod)
						{
							printf("mod 0, RM 101 SIB unimplemented!!!!!!!!!!!\n");
						}
						else
						{
							address = cpu->gen_reg[REG_RBP].rrx + disp;
						}
						break;
					case 6:
						address = cpu->gen_reg[REG_RSI].rrx + disp;
						break;
					case 7: 
						address = cpu->gen_reg[REG_RDI].rrx + disp;
						break;
				}


				address += segbase;

				// if it's on the stack buffer, overwrite directly, no mc needed
				if ((address >= (xed_uint64_t)cpu->stack_buf) && (address <= (xed_uint64_t)cpu->stack_buf + cpu->stack_buf_len))
				{
					ret_value =  *(xed_uint64_t*)address;
				}
				else
				{
					int ret = 0;
					// wait for testcase
					printf("Read memory outside of current stack, address 0x%lx\t", address);
					ret = try_read_memory64(address, &ret_value, mc, mc_max_cnt);
					if (-1 == ret)
					{
						printf("address invalid, emulated program should crash or throw sigfault\t");
					}
				}
				printf("address: 0x%lx value: 0x%lx\t", address, ret_value);

			}
			break;
		case 3:
			{
				switch (modrm.rm)
				{
					case 0:
						ret_value = cpu->gen_reg[REG_RAX].rrx;
						printf("RAX: 0x%lx\t", ret_value);
						break;
					case 1:
						ret_value = cpu->gen_reg[REG_RCX].rrx;
						printf("RCX: 0x%lx\t", ret_value);
						break;
					case 2:
						ret_value = cpu->gen_reg[REG_RDX].rrx;
						printf("RDX: 0x%lx\t", ret_value);
						break;
					case 3:
						ret_value = cpu->gen_reg[REG_RBX].rrx;
						printf("RBX: 0x%lx\t", ret_value);
						break;
					case 4:
						ret_value = cpu->gen_reg[REG_RSP].rrx;
						printf("RSP: 0x%lx\t", ret_value);
						break;
					case 5:
						ret_value = cpu->gen_reg[REG_RBP].rrx;
						printf("RBP: 0x%lx\t", ret_value);
						break;
					case 6:
						ret_value = cpu->gen_reg[REG_RSI].rrx;
						printf("RSI: 0x%lx\t", ret_value);
						break;
					case 7:
						ret_value = cpu->gen_reg[REG_RDI].rrx;
						printf("RDI: 0x%lx\t", ret_value);
						break;
				}

			}
			break;
	}

	return ret_value;
}
//-----------------------------------------------------------------------------//
xed_uint64_t get_r64 (cpu_t* cpu, modrm_t modrm)
{
	switch (modrm.reg)
	{
		case 0:
			printf("RAX: 0x%llx\t", cpu->gen_reg[REG_RAX].rrx);
			return cpu->gen_reg[REG_RAX].rrx;
		case 1:
			printf("RCX: 0x%llx\t", cpu->gen_reg[REG_RCX].rrx);
			return cpu->gen_reg[REG_RCX].rrx;
		case 2:
			printf("RDX: 0x%llx\t", cpu->gen_reg[REG_RDX].rrx);
			return cpu->gen_reg[REG_RDX].rrx;
		case 3:
			printf("RBX: 0x%llx\t", cpu->gen_reg[REG_RBX].rrx);
			return cpu->gen_reg[REG_RBX].rrx;
		case 4:
			printf("RSP: 0x%llx\t", cpu->gen_reg[REG_RSP].rrx);
			return cpu->gen_reg[REG_RSP].rrx;
		case 5:
			printf("RBP: 0x%llx\t", cpu->gen_reg[REG_RBP].rrx);
			return cpu->gen_reg[REG_RBP].rrx;
		case 6:
			printf("RSI: 0x%llx\t", cpu->gen_reg[REG_RSI].rrx);
			return cpu->gen_reg[REG_RSI].rrx;
		case 7:
			printf("RDI: 0x%llx\t", cpu->gen_reg[REG_RDI].rrx);
			return cpu->gen_reg[REG_RDI].rrx;
	}
}
//-----------------------------------------------------------------------------//
int set_rm32 (xed_decoded_inst_t* xedd, cpu_t* cpu, modrm_t modrm, xed_uint32_t value, mc_t* mc, int mc_max_cnt)
{
	xed_int64_t address = 0;
	xed_int64_t disp = 0;

	switch (modrm.mod)
	{
		case 0:
		case 1:
		case 2:
			{
				if (xed_operand_values_has_memory_displacement(xedd))
				{
					xed_uint_t disp_bits =
						xed_decoded_inst_get_memory_displacement_width(xedd, 0);
					if (disp_bits)
					{
						printf("DISPLACEMENT_BYTES= %u ", disp_bits);
						disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
						printf("0x" XED_FMT_LX16 " base10=" XED_FMT_LD "\t", disp, disp);
					}
				}

				switch (modrm.rm)
				{
					case 0:
						address = cpu->gen_reg[REG_RAX].rrx + disp;
						break;
					case 1:
						address = cpu->gen_reg[REG_RCX].rrx + disp;
						break;
					case 2:
						address = cpu->gen_reg[REG_RDX].rrx + disp;
						break;
					case 3:
						address = cpu->gen_reg[REG_RBX].rrx + disp;
						break;
					case 4:
						printf("SIB unimplemented!!!!!!!!!!!\n");
						break;
					case 5:
						if (0 == modrm.mod)
						{
							printf("mod 0, RM 101 SIB unimplemented!!!!!!!!!!!\n");
						}
						else
						{
							address = cpu->gen_reg[REG_RBP].rrx + disp;
						}
						break;
					case 6:
						address = cpu->gen_reg[REG_RSI].rrx + disp;
						break;
					case 7: 
						address = cpu->gen_reg[REG_RDI].rrx + disp;
						break;
				}

				// if it's on the stack buffer, overwrite directly, no mc needed
				if ((address >= (xed_uint64_t)cpu->stack_buf) && (address <= (xed_uint64_t)cpu->stack_buf + cpu->stack_buf_len))
				{
					*(xed_uint32_t*)address = value;
					printf("Write on stack, address 0x%lx value 0x%x\t", address, value);
				}
				else
				{
					mc_t* pmc = NULL;

					int i = 0;

					for (i = 0; i < mc_max_cnt; i++)
					{
						if (-1 == mc[i].address)
						{
							pmc = &mc[i];
						}
					}

					if (NULL == pmc)
					{
						printf("ERROR: more mc!!!\n");
						exit(1);
					}


					printf("Write memory outside of current stack, (to mc), address 0x%lx, value 0x%x\t", address, value);
					pmc->address = address;
					pmc->value = value;
				}

			}
			break;
		case 3:
			{
				switch (modrm.rm)
				{
					case 0:
						cpu->gen_reg[REG_RAX].rrx = 0;
						cpu->gen_reg[REG_RAX].dword.erx = value;
						printf("EAX<-0x%x\t", value);
						break;
					case 1:
						cpu->gen_reg[REG_RCX].rrx = 0;
						cpu->gen_reg[REG_RCX].dword.erx = value;
						printf("ECX<-0x%x\t", value);
						break;
					case 2:
						cpu->gen_reg[REG_RDX].rrx = 0;
						cpu->gen_reg[REG_RDX].dword.erx = value;
						printf("EDX<-0x%x\t", value);
						break;
					case 3:
						cpu->gen_reg[REG_RBX].rrx = 0;
						cpu->gen_reg[REG_RBX].dword.erx = value;
						printf("EBX<-0x%x\t", value);
						break;
					case 4:
						cpu->gen_reg[REG_RSP].rrx = 0;
						cpu->gen_reg[REG_RSP].dword.erx = value;
						printf("ESP<-0x%x\t", value);
						break;
					case 5:
						cpu->gen_reg[REG_RBP].rrx = 0;
						cpu->gen_reg[REG_RBP].dword.erx = value;
						printf("EBP<-0x%x\t", value);
						break;
					case 6:
						cpu->gen_reg[REG_RSI].rrx = 0;
						cpu->gen_reg[REG_RSI].dword.erx = value;
						printf("ESI<-0x%x\t", value);
						break;
					case 7:
						cpu->gen_reg[REG_RDI].rrx = 0;
						cpu->gen_reg[REG_RDI].dword.erx = value;
						printf("EDI<-0x%x\t", value);
						break;
				}
			}
			break;
	}





	return 0;
}
//-----------------------------------------------------------------------------//
int set_rm64 (xed_decoded_inst_t* xedd, cpu_t* cpu, modrm_t modrm, xed_uint64_t value, mc_t* mc, int mc_max_cnt)
{
	xed_uint64_t address = 0;
	xed_uint64_t disp = 0;

	switch (modrm.mod)
	{
		case 0:
		case 1:
		case 2:
			{
				if (xed_operand_values_has_memory_displacement(xedd))
				{
					xed_uint_t disp_bits =
						xed_decoded_inst_get_memory_displacement_width(xedd, 0);
					if (disp_bits)
					{
						printf("DISPLACEMENT_BYTES= %u ", disp_bits);
						disp = xed_decoded_inst_get_memory_displacement(xedd, 0);
						printf("0x" XED_FMT_LX16 " base10=" XED_FMT_LD "\t", disp, disp);
					}
				}

				switch (modrm.rm)
				{
					case 0:
						address = cpu->gen_reg[REG_RAX].rrx + disp;
						break;
					case 1:
						address = cpu->gen_reg[REG_RCX].rrx + disp;
						break;
					case 2:
						address = cpu->gen_reg[REG_RDX].rrx + disp;
						break;
					case 3:
						address = cpu->gen_reg[REG_RBX].rrx + disp;
						break;
					case 4:
						address = get_sib(xedd, cpu, modrm);
						break;
					case 5:
						if (0 == modrm.mod)
						{
							printf("mod 0, RM 101 SIB unimplemented!!!!!!!!!!!\n");
						}
						else
						{
							address = cpu->gen_reg[REG_RBP].rrx + disp;
						}
						break;
					case 6:
						address = cpu->gen_reg[REG_RSI].rrx + disp;
						break;
					case 7: 
						address = cpu->gen_reg[REG_RDI].rrx + disp;
						break;
				}

				// if it's on the stack buffer, overwrite directly, no mc needed
				if ((address >= (xed_uint64_t)cpu->stack_buf) && (address <= (xed_uint64_t)cpu->stack_buf + cpu->stack_buf_len))
				{
					*(xed_uint64_t*)address = value;
					printf("Write on stack, address 0x%lx value 0x%lx\t", address, value);
				}
				else
				{
					mc_t* pmc = NULL;

					int i = 0;

					for (i = 0; i < mc_max_cnt; i++)
					{
						if (-1 == mc[i].address)
						{
							pmc = &mc[i];
						}
					}

					if (NULL == pmc)
					{
						printf("ERROR: more mc!!!\n");
						exit(1);
					}


					printf("Write memory outside of current stack, (to mc), address 0x%lx, value 0x%lx\t", address, value);
					pmc->address = address;
					pmc->value = value;
				}

			}
			break;
		case 3:
			{
				switch (modrm.rm)
				{
					case 0:
						cpu->gen_reg[REG_RAX].rrx = value;
						printf("RAX<-0x%lx\t", value);
						break;
					case 1:
						cpu->gen_reg[REG_RCX].rrx = value;
						printf("RCX<-0x%lx\t", value);
						break;
					case 2:
						cpu->gen_reg[REG_RDX].rrx = value;
						printf("RDX<-0x%lx\t", value);
						break;
					case 3:
						cpu->gen_reg[REG_RBX].rrx = value;
						printf("RBX<-0x%lx\t", value);
						break;
					case 4:
						cpu->gen_reg[REG_RSP].rrx = value;
						printf("RSP<-0x%lx\t", value);
						break;
					case 5:
						cpu->gen_reg[REG_RBP].rrx = value;
						printf("RBP<-0x%lx\t", value);
						break;
					case 6:
						cpu->gen_reg[REG_RSI].rrx = value;
						printf("RSI<-0x%lx\t", value);
						break;
					case 7:
						cpu->gen_reg[REG_RDI].rrx = value;
						printf("RDI<-0x%lx\t", value);
						break;
				}

			}
			break;
	}

	return 0;
}
//-----------------------------------------------------------------------------//
int set_r32 (cpu_t* cpu, modrm_t modrm, xed_uint32_t value)
{
	switch (modrm.reg)
	{
		case 0:
			cpu->gen_reg[REG_RAX].rrx = 0;
			cpu->gen_reg[REG_RAX].dword.erx = value;
			printf("EAX<-0x%x\t", value);
			break;	
		case 1:
			cpu->gen_reg[REG_RCX].rrx = 0;
			cpu->gen_reg[REG_RCX].dword.erx = value;
			printf("ECX<-0x%x\t", value);
			break;	
		case 2:
			cpu->gen_reg[REG_RDX].rrx = 0;
			cpu->gen_reg[REG_RDX].dword.erx = value;
			printf("EDX<-0x%x\t", value);
			break;	
		case 3:
			cpu->gen_reg[REG_RBX].rrx = 0;
			cpu->gen_reg[REG_RBX].dword.erx = value;
			printf("EBX<-0x%x\t", value);
			break;	
		case 4:
			cpu->gen_reg[REG_RSP].rrx = 0;
			cpu->gen_reg[REG_RSP].dword.erx = value;
			printf("ESP<-0x%x\t", value);
			break;	
		case 5:
			cpu->gen_reg[REG_RBP].rrx = 0;
			cpu->gen_reg[REG_RBP].dword.erx = value;
			printf("EBP<-0x%x\t", value);
			break;	
		case 6:
			cpu->gen_reg[REG_RSI].rrx = 0;
			cpu->gen_reg[REG_RSI].dword.erx = value;
			printf("ESI<-0x%x\t", value);
			break;	
		case 7:
			cpu->gen_reg[REG_RDI].rrx = 0;
			cpu->gen_reg[REG_RDI].dword.erx = value;
			printf("EDI<-0x%x\t", value);
			break;	
	}

	return 0;
}
//-----------------------------------------------------------------------------//
int set_r64 (cpu_t* cpu, modrm_t modrm, xed_uint64_t value)
{
	// looks lik %lx and PRIx64 both can print uint64_t
	switch (modrm.reg)
	{
		case 0:
			cpu->gen_reg[REG_RAX].rrx = value;
			//printf("RAX<= 0x%"PRIx64"\t", value);
			printf("RAX<= 0x%lx\t", value);
			break;	
		case 1:
			cpu->gen_reg[REG_RCX].rrx = value;
			printf("RCX<= 0x%"PRIx64"\t", value);
			break;	
		case 2:
			cpu->gen_reg[REG_RDX].rrx = value;
			printf("RDX<= 0x%"PRIx64"\t", value);
			break;	
		case 3:
			cpu->gen_reg[REG_RBX].rrx = value;
			printf("RBX<= 0x%"PRIx64"\t", value);
			break;	
		case 4:
			cpu->gen_reg[REG_RSP].rrx = value;
			printf("RSP<= 0x%"PRIx64"\t", value);
			break;	
		case 5:
			cpu->gen_reg[REG_RBP].rrx = value;
			printf("RBP<= 0x%"PRIx64"\t", value);
			break;	
		case 6:
			cpu->gen_reg[REG_RSI].rrx = value;
			printf("RSI<= 0x%"PRIx64"\t", value);
			break;	
		case 7:
			cpu->gen_reg[REG_RDI].rrx = value;
			printf("RDI<= 0x%"PRIx64"\t", value);
			break;	
	}

	return 0;
}
//-----------------------------------------------------------------------------//
int push64 (cpu_t* cpu, xed_uint64_t value)
{
	xed_uint64_t* p = NULL;

	cpu->gen_reg[REG_RSP].rrx -= 8;

	p = (xed_uint64_t*)cpu->gen_reg[REG_RSP].rrx;

	if (isValidPtr(p, 8))
	{
		*p = value;
		return 0;
	}
	else
	{
		return -1;
	}
}
//-----------------------------------------------------------------------------//
int pop64 (cpu_t* cpu, xed_uint64_t* pvalue)
{
	xed_uint64_t* p = NULL;

	p = (xed_uint64_t*)cpu->gen_reg[REG_RSP].rrx;

	cpu->gen_reg[REG_RSP].rrx += 8;

	if (isValidPtr(p, 8))
	{
		*pvalue = *p;
		return 0;
	}
	else
	{
		return -1;
	}

	return 0;
}
//-----------------------------------------------------------------------------//
int emulate_push (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	xed_uint8_t op_byte;
	xed_uint8_t prefix;
	xed_uint_t np;
	np = xed_decoded_inst_get_nprefixes(xedd);
	op_byte = xed_decoded_inst_get_byte(xedd, np);
	int i = 0;
	xed_bool_t extended_gpr = 0;

	if (0 != np) 
	{
		printf("PREFIX");
		for (i = 0; i < np; i++) {
			printf(" %2x", xed_decoded_inst_get_byte(xedd, i));
		}
		printf("\t");
	}

	if (0 != np)
	{
		prefix = xed_decoded_inst_get_byte(xedd, 0);
		// REX.B
		if (0x41 == prefix)
		{
			extended_gpr = 1;
			printf("REX.B\t");
		}
		else
		{
			printf("Unimplemented PREFIX %2x!!!!!\t", prefix);
			return 0;
		}
	}

	switch (op_byte & 0xf8)
	{
		case 0x50:
			{
				int reg = op_byte & 0x7;
				xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
				xed_uint64_t value;

				printf("%2x PUSH %s\t", op_byte, xed_reg_enum_t2str(r0));

				if (extended_gpr)
				{
					switch (reg)
					{
						case 0:
							value = cpu->gen_reg[REG_R8].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 1:
							value = cpu->gen_reg[REG_R9].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 2:
							value = cpu->gen_reg[REG_R10].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 3:
							value = cpu->gen_reg[REG_R11].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 4:
							value = cpu->gen_reg[REG_R12].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 5:
							value = cpu->gen_reg[REG_R13].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 6:
							value = cpu->gen_reg[REG_R14].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 7:
							value = cpu->gen_reg[REG_R15].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;

					}
				}
				else
				{

					switch (reg)
					{
						case 0:
							value = cpu->gen_reg[REG_RAX].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 1:
							value = cpu->gen_reg[REG_RCX].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 2:
							value = cpu->gen_reg[REG_RDX].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 3:
							value = cpu->gen_reg[REG_RBX].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 4:
							value = cpu->gen_reg[REG_RSP].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 5:
							value = cpu->gen_reg[REG_RBP].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 6:
							value = cpu->gen_reg[REG_RSI].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
						case 7:
							value = cpu->gen_reg[REG_RDI].rrx;
							push64(cpu, value);
							printf("0x%lx\t", value);
							break;
					}
				}

			}

			break;
		default:
			printf("%2x PUSH unhandled!!!!!!!!!\t", op_byte);
			break;
	}

	return 0;
}
//-----------------------------------------------------------------------------//
int emulate_pop (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	xed_uint8_t op_byte;
	xed_uint_t np;
	int i = 0;

	np = xed_decoded_inst_get_nprefixes(xedd);
	op_byte = xed_decoded_inst_get_byte(xedd, np);

	if (0 != np) 
	{
		printf("PREFIX");
		for (i = 0; i < np; i++) {
			printf(" %2x", xed_decoded_inst_get_byte(xedd, i));
		}
		printf("\t");
		printf("Unimplemented!!!!!\t");
		return 0;
	}


	if (0x58 == (op_byte & 0xf8))
	{
		// 58+rd 	pop r64
		//
		int reg = op_byte & 0x7;
		xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
		xed_uint64_t value;

		printf("%2x POP %s\t", op_byte, xed_reg_enum_t2str(r0));

		switch (reg)
		{
			case 0:
				pop64(cpu, &value);
				cpu->gen_reg[REG_RAX].rrx = value;
				printf("RAX<-0x%lx\t", value);
				break;
			case 1:
				pop64(cpu, &value);
				cpu->gen_reg[REG_RCX].rrx = value;
				printf("RCX<-0x%lx\t", value);
				break;
			case 2:
				pop64(cpu, &value);
				cpu->gen_reg[REG_RDX].rrx = value;
				printf("RDX<-0x%lx\t", value);
				break;
			case 3:
				pop64(cpu, &value);
				cpu->gen_reg[REG_RBX].rrx = value;
				printf("RBX<-0x%lx\t", value);
				break;
			case 4:
				pop64(cpu, &value);
				cpu->gen_reg[REG_RSP].rrx = value;
				printf("RSP<-0x%lx\t", value);
				break;
			case 5:
				pop64(cpu, &value);
				cpu->gen_reg[REG_RBP].rrx = value;
				printf("RBP<-0x%lx\t", value);
				break;
			case 6:
				pop64(cpu, &value);
				cpu->gen_reg[REG_RSI].rrx = value;
				printf("RSI<-0x%lx\t", value);
				break;
			case 7: 
				pop64(cpu, &value);
				cpu->gen_reg[REG_RDI].rrx = value;
				printf("RDI<-0x%lx\t", value);
				break;
		}

	}
	else
	{
		printf("Unimplemented POP %2x\t", op_byte);
	}

	return 0;


}
//-----------------------------------------------------------------------------//
int emulate_mov (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	int i = 0;
	xed_uint8_t op_byte;
	xed_uint_t np;
	const xed_operand_values_t* ov;

	np = xed_decoded_inst_get_nprefixes(xedd);
	op_byte = xed_decoded_inst_get_byte(xedd, np);
	ov = xed_decoded_inst_operands_const(xedd);


	if (0 != np) 
	{
		printf("PREFIX");
		for (i = 0; i < np; i++) {
			printf(" %2x", xed_decoded_inst_get_byte(xedd, i));
		}
		printf("\t");
	}
	switch (op_byte)
	{
		case 0x88:
			printf("88 MOV\t");
			break;
		case 0x89:
			{
				// 89/r			MOV r/m32, r32
				// REX.W + 89/r		MOV r/m64, r64
				//
				modrm_t modrm;
				//const xed_operand_t* op = xed_inst_operand(xi, 1);
				//xed_operand_enum_t op_name = xed_operand_name(op);
				xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
				//xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);

				modrm.byte = xed_decoded_inst_get_modrm(xedd);
				printf("89 MOV,  ModR/M %2x\t", modrm.byte);
				printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);

				if (3 == modrm.mod)
				{
					// mov reg, reg
					if (xed_operand_values_has_rexw_prefix (ov))
					{

						// 64
						xed_uint64_t value;
						xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
						printf("mov %s, %s\t", xed_reg_enum_t2str(r0), xed_reg_enum_t2str(r1));
						value = get_r64(cpu, modrm);
						set_rm64(xedd, cpu, modrm, value, mc, mc_max_cnt);
					}
					else
					{
						// 32
						xed_uint32_t value;
						value = get_r32(cpu, modrm);
						xed_reg_enum_t r1 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG1);
						printf("mov %s, %s\t", xed_reg_enum_t2str(r0), xed_reg_enum_t2str(r1));
						switch (modrm.rm)
						{
							case 0:
								cpu->gen_reg[REG_RAX].dword.erx = value;
								printf("EAX<-0x%x\t", value);
								break;
							case 1:
								cpu->gen_reg[REG_RCX].dword.erx = value;
								printf("ECX<-0x%x\t", value);
								break;
							case 2:
								cpu->gen_reg[REG_RDX].dword.erx = value;
								printf("EDX<-0x%x\t", value);
								break;
							case 3:
								cpu->gen_reg[REG_RBX].dword.erx = value;
								printf("EBX<-0x%x\t", value);
								break;
							case 4:
								cpu->gen_reg[REG_RSP].dword.erx = value;
								printf("ESP<-0x%x\t", value);
								break;
							case 5:
								cpu->gen_reg[REG_RBP].dword.erx = value;
								printf("EBP<-0x%x\t", value);
								break;
							case 6:
								cpu->gen_reg[REG_RSI].dword.erx = value;
								printf("ESI<-0x%x\t", value);
								break;
							case 7:
								cpu->gen_reg[REG_RDI].dword.erx = value;
								printf("EDI<-0x%x\t", value);
								break;
						}
					}


				}
				else if (1 == modrm.mod)
				{
					// mov r/m+disp8, reg
					//if (0 != np)
					if (xed_operand_values_has_rexw_prefix (ov))
					{
						// REX.W + 89 /r	MOV r/m64, r64
						xed_uint64_t value;
						value = get_r64(cpu, modrm);
						set_rm64(xedd, cpu, modrm, value, mc, mc_max_cnt);
					}
					else 
					{	// 89 /r		MOV r/m32, r32
						// mov [r64]+disp8, reg
						xed_uint32_t value;
						value = get_r32(cpu, modrm);
						set_rm32(xedd, cpu, modrm, value, mc, mc_max_cnt);

					}
				}
				else
				{
					// mov mem, reg
					printf("Unimplemented!!!!! mov mem, reg\t");

				}

			}
			break;
		case 0x8A:
			printf("8A MOV\t");
			break;
		case 0x8B:
			{
				// 8B/r			MOV r16, r/m16
				// 8B/r			MOV r32, r/m32
				// REX.W + 8B/r		MOV r64, r/m64
				//
				modrm_t modrm;

				modrm.byte = xed_decoded_inst_get_modrm(xedd);
				printf("8B MOV ModR/M %2x\t", modrm.byte);
				printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);

				switch (modrm.mod)
				{
					case 0:
					case 1:
					case 2:
						{
							if (xed_operand_values_has_rexw_prefix (ov))
							{
								// REX.W + 8B /r		MOV r/m64, r64
								xed_uint64_t value;
								value = get_rm64(xedd, cpu, modrm, mc, mc_max_cnt);
								set_r64(cpu, modrm, value);
							}
							else
							{
								// 8B /r		MOV r/m32, r32
								xed_uint32_t value;
								value = get_rm32(xedd, cpu, modrm, mc, mc_max_cnt);
								set_r32(cpu, modrm, value);
							}
						}
						break;
					case 3:
						printf("Unimplemented!!!! 8B mov mod 3\t");
						break;
				}
			}
			break;
		case 0xC7:
			{
				// C7 /0 id		MOV r/m32, imm32
				// REX.W + C7 /0 io	MOV r/m64, imm32
				//
				modrm_t modrm;

				modrm.byte = xed_decoded_inst_get_modrm(xedd);
				printf("C7 MOV ModR/M %2x\t", modrm.byte);
				printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);

				if (0 != np)
				{
					printf("Unimplemented!!!!! PREFIX C7 MOV\t");
					return 0;
				}

				switch (modrm.mod)
				{
					case 0:
					case 1:
					case 2:
						{
							xed_uint32_t value;
							value = xed_decoded_inst_get_signed_immediate(xedd);
							printf("imm:0x%x\t", value);
							set_rm32(xedd, cpu, modrm, value, mc, mc_max_cnt);
						}
						break;
					case 3:
						{
							printf("Unimplemented!!!!! PREFIX C7 MOV mod 3\t");
						}
						break;
				}

				return 0;
			}
			break;
		default:
			printf("Unimplemented MOV %x\t", op_byte);
			break;

	}

	return 0;
}
//-----------------------------------------------------------------------------//
int emulate_movzx (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	xed_uint8_t op_byte;
	xed_uint8_t op_byte2;
	xed_uint_t np;
	int i = 0;

	np = xed_decoded_inst_get_nprefixes(xedd);
	op_byte = xed_decoded_inst_get_byte(xedd, np);
	op_byte2 = xed_decoded_inst_get_byte(xedd, np + 1);

	if (0 != np) 
	{
		printf("PREFIX");
		for (i = 0; i < np; i++) {
			printf(" %2x", xed_decoded_inst_get_byte(xedd, i));
		}
		printf("\t");
		printf("Unimplemented\t");
		return 0;
	}

	switch (op_byte2)
	{
		case 0xB6:
			{
				// 0F B6 /r		MOVZX r32, r/m8
				// REX.W 0F B6 /r	MOVZX r64, r/m8
				//
				modrm_t modrm;
				xed_uint8_t value;
				modrm.byte = xed_decoded_inst_get_modrm(xedd);
				printf("0F B6 MOVZX, ModR/M %2x\t", modrm.byte);
				printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);

				value = get_rm8(xedd, cpu, modrm, mc, mc_max_cnt);
				set_r32(cpu, modrm, (xed_uint32_t)value);
			}
			break;
		case 0xB7:
			{
				// 0F B7 /r		MOVZX r32, r/m16
				// REX.W 0F B7 /r	MOVZX r64, r/m16
				//
				modrm_t modrm;
				xed_uint16_t value;
				modrm.byte = xed_decoded_inst_get_modrm(xedd);
				printf("0F B6 MOVZX, ModR/M %2x\t", modrm.byte);
				printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);

				value = get_rm16(xedd, cpu, modrm, mc, mc_max_cnt);
				set_r32(cpu, modrm, (xed_uint32_t)value);
			}
			break;
		default:
			printf("Unimplemented MOVZX %2x %2x\t", op_byte, op_byte2);
			break;
	}



	return 0;
}
//-----------------------------------------------------------------------------//
int emulate_movsxd (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	xed_uint8_t op_byte;
	xed_uint_t np;
	int i = 0;
	const xed_operand_values_t* ov;
	xed_uint32_t value32;
	xed_uint64_t value64;
	modrm_t modrm;

	np = xed_decoded_inst_get_nprefixes(xedd);
	op_byte = xed_decoded_inst_get_byte(xedd, np);
	ov = xed_decoded_inst_operands_const(xedd);

	if (0 != np) 
	{
		printf("PREFIX");
		for (i = 0; i < np; i++) {
			printf(" %2x", xed_decoded_inst_get_byte(xedd, i));
		}
		printf("\t");
	}

	// REX.W + 63 /r		MOVSXD r64, r/m32

	// MOVSXD only have one opcode 63, and it must come with REX.W
	if (!xed_operand_values_has_rexw_prefix (ov))
	{
		printf("Weired MOVXSD has no REX.W, Unimplemented!!!!!\t ");
		return -1;
	}
	if (0x63 != op_byte)
	{
		printf("Weired MOVXSD opcode is not 0x63, Unimplemented!!!!!\t ");
		return -1;
	}

	modrm.byte = xed_decoded_inst_get_modrm(xedd);
	printf("48 63 REX.W MOVSXD, ModR/M %2x\t", modrm.byte);
	printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);
	value32 = get_rm32(xedd, cpu, modrm, mc, mc_max_cnt);
	if ((xed_int32_t)value32 < 0)
	{
		// test sign
		value64 = 0xFFFFFFFF00000000 + value32;
	}
	else
	{
		value64 = (xed_uint64_t)value32;
	}

	set_r64(cpu, modrm, value64);	

	return 0;
}
//-----------------------------------------------------------------------------//
int emulate_lea (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	xed_uint_t np;
	int i = 0;
	const xed_operand_values_t* ov;
	modrm_t modrm;
	xed_uint64_t value;
	xed_uint32_t inst_len = 0;

	np = xed_decoded_inst_get_nprefixes(xedd);
	ov = xed_decoded_inst_operands_const(xedd);

	if (0 != np) 
	{
		printf("PREFIX");
		for (i = 0; i < np; i++) {
			printf(" %2x", xed_decoded_inst_get_byte(xedd, i));
		}
		printf("\t");
	}


	// 8D /r		LEA r32, m
	// REX.W 8D/r		LEA r64, m
	//

	// it only has opcode 8D, so no switch case needed
	//

	modrm.byte = xed_decoded_inst_get_modrm(xedd);
	printf("8D LEA, ModR/M %2x\t", modrm.byte);
	printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);

	value = get_m64(xedd, cpu, modrm);
	inst_len = xed_decoded_inst_get_length(xedd);

	printf("instruction length:%d\t", inst_len);
	// add instruction length to RIP, more RIP to next instruction, 
	// LEA instruction e.g. 48 8d 0d 9c 58 04 00


	value += inst_len;

	if (xed_operand_values_has_rexw_prefix (ov))
	{
		set_r64(cpu, modrm, value); 
	}
	else
	{
		set_r32(cpu, modrm, (xed_uint32_t)value);
	}

	return 0;	
}
//-----------------------------------------------------------------------------//
int emulate_add (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	xed_uint8_t op_byte;
	xed_uint_t np;
	const xed_operand_values_t* ov;
	int i = 0;

	np = xed_decoded_inst_get_nprefixes(xedd);
	op_byte = xed_decoded_inst_get_byte(xedd, np);
	ov = xed_decoded_inst_operands_const(xedd);

	if (0 != np) 
	{
		printf("PREFIX");
		for (i = 0; i < np; i++) {
			printf(" %2x", xed_decoded_inst_get_byte(xedd, i));
		}
		printf("\t");
	}

	switch (op_byte)
	{
		case 0x1:
			{
				// 01/r			ADD r/m16, r16
				// 01/r			ADD r/m32, r32
				// REX.W + 01/r		ADD r/m64, r64
				//
				modrm_t modrm;

				modrm.byte = xed_decoded_inst_get_modrm(xedd);
				printf("01 ADD ModR/M %2x\t", modrm.byte);
				printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);

				switch (modrm.mod)
				{
					case 0:
					case 1:
					case 2:
						printf("Unimplemented!!!!! 0x01 ADD mod 0,1,2\t");
						break;
					case 3:
						{
							if (xed_operand_values_has_rexw_prefix (ov))
							{
								// REX.W + 01 /r 	ADD r/m64, r64
								// todo: set OF CF
								xed_uint64_t value_src, value_dst;
								xed_uint64_t value_sum;

								value_src = get_r64(cpu, modrm);
								value_dst = get_rm64(xedd, cpu, modrm, mc, mc_max_cnt);
								value_sum = value_src + value_dst;
								set_rm64(xedd, cpu, modrm, value_sum, mc, mc_max_cnt);
							}
							else
							{
								// add r32, r32
								// todo: set OF CF
								xed_uint32_t value_src, value_dst;
								xed_uint32_t value_sum;

								value_src = get_r32(cpu, modrm);
								value_dst = get_rm32(xedd, cpu, modrm, mc, mc_max_cnt);
								value_sum = value_src + value_dst;
								set_rm32(xedd, cpu, modrm, value_sum, mc, mc_max_cnt);
							}
						}
						break;
				}
			}
			break;
		default:
			printf("Unimplemented %x ADD\t", op_byte);
			break;
	}

	return 0;
}
//-----------------------------------------------------------------------------//
int emulate_sub (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	xed_uint8_t op_byte;
	xed_uint_t np;
	const xed_operand_values_t* ov;
	int i = 0;

	np = xed_decoded_inst_get_nprefixes(xedd);
	op_byte = xed_decoded_inst_get_byte(xedd, np);
	ov = xed_decoded_inst_operands_const(xedd);

	if (0 != np)
	{
		printf("PREFIX");
		for (i = 0; i < np; i++) {
			printf(" %2x", xed_decoded_inst_get_byte(xedd, i));
		}
		printf("\t");
	}

	switch (op_byte)
	{
		case 0x83:
			{
				// 85 /5 ib		SUB r/m32, imm8
				// REX.W + 85 /5 ib	SUB r/m64, imm8
				//
				modrm_t modrm;

				modrm.byte = xed_decoded_inst_get_modrm(xedd);
				printf("85 SUB ModR/M %2x\t", modrm.byte);
				printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);

				if (xed_operand_values_has_rexw_prefix (ov))
				{
					// REX.W + 85 /5 ib	SUB r/m64, imm8
					xed_int64_t value;
					xed_int8_t imm;

					value = get_rm64(xedd, cpu, modrm, mc, mc_max_cnt);
					imm = xed_decoded_inst_get_signed_immediate(xedd);
					printf("imm:0x%x\t", imm);
					value -= imm;
					set_rm64(xedd, cpu, modrm, value, mc, mc_max_cnt);
				}
				else
				{
					// 85 /5 ib		SUB r/m32, imm8
					printf("Unimplemented SUB r/m32, imm8\t");
				}
			}
			break;
		default:
			printf("Unimplemented %x SUB\t", op_byte);
			break;
	}

	return 0;
}
//-----------------------------------------------------------------------------//
int emulate_xor (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	xed_uint8_t op_byte;
	xed_uint_t np;
	int i = 0;

	np = xed_decoded_inst_get_nprefixes(xedd);
	op_byte = xed_decoded_inst_get_byte(xedd, np);

	if (0 != np) 
	{
		printf("PREFIX");
		for (i = 0; i < np; i++) {
			printf(" %2x", xed_decoded_inst_get_byte(xedd, i));
		}
		printf("\t");
	}

	switch (op_byte)
	{
		case 0x31:
			{
				// 31 /r	XOR r/m32, r32
				//
				modrm_t modrm;
				xed_uint32_t value_src, value_dst;

				modrm.byte = xed_decoded_inst_get_modrm(xedd);
				printf("31 XOR ModR/M %2x\t", modrm.byte);
				printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);

				value_src = get_r32(cpu, modrm);
				value_dst = get_rm32(xedd, cpu, modrm, mc, mc_max_cnt);
				value_dst = value_src ^ value_dst;
				set_rm32(xedd, cpu, modrm, value_dst, mc, mc_max_cnt);
			}
			break;
		default:
			printf("Unimplemented %x XOR\t", op_byte);
			break;
	}


	return 0;
}
//-----------------------------------------------------------------------------//
int emulate_cmp (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	xed_uint8_t op_byte;
	xed_uint_t np;
	int i = 0;

	np = xed_decoded_inst_get_nprefixes(xedd);
	op_byte = xed_decoded_inst_get_byte(xedd, np);

	if (0 != np) 
	{
		printf("PREFIX");
		for (i = 0; i < np; i++) {
			printf(" %2x", xed_decoded_inst_get_byte(xedd, i));
		}
		printf("\t");
		printf("Unimplemented!!!!!\t");
		return 0;
	}

	switch (op_byte)
	{
		case 0x83:
			{
				// 83/7 ib		CMP r/m32, imm8
				// REX.W 83/7 ib	CMP r/m64, imm8
				//
				modrm_t modrm;
				xed_uint32_t value;
				xed_uint8_t imm;

				modrm.byte = xed_decoded_inst_get_modrm(xedd);
				printf("83 CMP ModR/M %2x\t", modrm.byte);
				printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);

				value = get_rm32(xedd, cpu, modrm, mc, mc_max_cnt);
				imm = xed_decoded_inst_get_signed_immediate(xedd);
				printf("r/m32 value:0x%x, imm:0x%x\t", value, imm);
				// CMP set SF PF  todo:

				if (0 == value - (xed_uint32_t)imm)
				{
					cpu->rflags.ZF = 1;
				} 
				else
				{
					cpu->rflags.ZF = 0;
				}

				if ((xed_int32_t)value < (xed_int32_t)imm)
				{
					cpu->rflags.CF = 1;
				}
				else
				{
					cpu->rflags.CF = 0;
				}

				//printf("ZF:%c\t", cpu->rflags.ZF? '1':'0');
				printf("ZF:%d\t", cpu->rflags.ZF);
				printf("CF:%d\t", cpu->rflags.CF);

			}
			break;
		default:
			printf("Unimplemented %x CMP\t", op_byte);
			break;
	}

	return 0;

}
//-----------------------------------------------------------------------------//
int emulate_test (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	xed_uint8_t op_byte;
	xed_uint_t np;
	int i = 0;

	np = xed_decoded_inst_get_nprefixes(xedd);
	op_byte = xed_decoded_inst_get_byte(xedd, np);

	if (0 != np) 
	{
		printf("PREFIX");
		for (i = 0; i < np; i++) {
			printf(" %2x", xed_decoded_inst_get_byte(xedd, i));
		}
		printf("\t");
		printf("Unimplemented!!!!!\t");
		return 0;
	}

	switch (op_byte)
	{
		case 0x85:
			{
				// 85 /r		TEST r/m32, r32
				// REX.W + 85 /r	TEST r/m64, r64
				//
				modrm_t modrm;
				xed_int32_t value0, value1;
				xed_int32_t value_result;

				modrm.byte = xed_decoded_inst_get_modrm(xedd);
				printf("85 TEST ModR/M %2x\t", modrm.byte);
				printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);

				value0 = get_rm32(xedd, cpu, modrm, mc, mc_max_cnt);
				value1 = get_r32(cpu, modrm);
				value_result = value0 & value1;
				if (0 == value_result)
				{
					cpu->rflags.ZF = 1;
				}
				else
				{
					cpu->rflags.ZF = 0;
				}
			}
			break;
		default:
			printf("Unimplemented %x TEST\t", op_byte);
			break;
	}



	return 0;
}
//-----------------------------------------------------------------------------//
int emulate_jz (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt, xed_uint64_t* new_rip)
{
	xed_uint8_t op_byte;

	op_byte = xed_decoded_inst_get_byte(xedd, 0);

	switch (op_byte)
	{
		case 0x74:
			{
				// 74 cb		JZ rel8
				xed_int8_t disp;
				disp = xed_decoded_inst_get_byte(xedd, 1);
				printf("branch displacement %2x\t", disp);
				if (1 == cpu->rflags.ZF)
				{
					*new_rip = (xed_int64_t)cpu->gen_reg[REG_RIP].rrx + disp + 2;
					return TE_JUMP;
				}
			}
			break;
		default:
			// any jcc belong to ICLASS_JZ
			printf("Unimplemented %x JZ\t", op_byte);
			return -1;
	}

	return 0;
}
//-----------------------------------------------------------------------------//
int emulate_jnz (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt, xed_uint64_t* new_rip)
{
	xed_uint8_t op_byte;

	op_byte = xed_decoded_inst_get_byte(xedd, 0);

	switch (op_byte)
	{
		case 0x75:
			{
				// 75 cb		JNZ rel8
				xed_int8_t disp;
				disp = xed_decoded_inst_get_byte(xedd, 1);
				printf("branch displacement %2x\t", disp);
				if (0 == cpu->rflags.ZF)
				{
					*new_rip = (xed_int64_t)cpu->gen_reg[REG_RIP].rrx + disp + 2;
					return TE_JUMP;
				}
			}
			break;
		default:
			// any jcc belong to ICLASS_JNZ
			printf("Unimplemented %x JNZ\t", op_byte);
			return -1;
	}
	return 0;
}
//-----------------------------------------------------------------------------//
int emualte_jnbe (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt, xed_uint64_t* new_rip)
{
	xed_uint8_t op_byte;
	xed_uint8_t op_byte2;

	op_byte = xed_decoded_inst_get_byte(xedd, 0);
	op_byte2 = xed_decoded_inst_get_byte(xedd, 1);

	switch (op_byte)
	{
		case 0x77:
			{
				// 77 cb		JNBE rel8
				xed_int8_t disp;
				disp = xed_decoded_inst_get_byte(xedd, 1);
				printf("branch displacement %2x\t", disp);
				if (0 == cpu->rflags.ZF && 0 == cpu->rflags.CF)
				{
					*new_rip = (xed_int64_t)cpu->gen_reg[REG_RIP].rrx + disp + 2;
					return TE_JUMP;
				}
			}
			break;
		case 0x0f:
			{
				switch (op_byte2)
				{
					case 0x87:
						{
							// 0f 87 cd		JNBE rel32
							//
							xed_uint32_t disp;
							disp = xed_decoded_inst_get_branch_displacement(xedd);
							printf("branch displacement %x\t", disp);
							if (0 == cpu->rflags.ZF && 0 == cpu->rflags.CF)
							{
								*new_rip = (xed_int64_t)cpu->gen_reg[REG_RIP].rrx + disp + 6;
								return TE_JUMP;
							}
						}
						break;
					default:
						printf("Unimplemented %2x %2x JNBE\t", op_byte, op_byte2);
						return -1;

				}
			}
			break;
		default:
			// any jcc belong to ICLASS_JNZ... yes
			printf("Unimplemented %2x JNBE\t", op_byte);
			return -1;
	}
	return 0;

}
//-----------------------------------------------------------------------------//
int emulate_jmp (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt, xed_uint64_t* new_rip)
{
	xed_uint8_t op_byte;
	modrm_t modrm;

	op_byte = xed_decoded_inst_get_byte(xedd, 0);
	modrm.byte = xed_decoded_inst_get_modrm(xedd);

	switch (op_byte)
	{
		case 0xeb:
			{
				// EB cb		JMP rel8
				xed_int8_t disp;
				// xed_decoded_inst_get_branch_displacement(xedd);
				disp = xed_decoded_inst_get_byte(xedd, 1);
				printf("branch displacement %2x\t", disp);
				*new_rip = (xed_int64_t)cpu->gen_reg[REG_RIP].rrx + disp + 2;
				return TE_JUMP;
			}
			break;
		case 0xe9:
			{
				// E9 cb		JMP rel32
				xed_int32_t disp;
				disp = xed_decoded_inst_get_branch_displacement(xedd);
				printf("branch displacement 0x%x\t", disp);
				*new_rip = (xed_int64_t)cpu->gen_reg[REG_RIP].rrx + disp + 5;
				return TE_JMP_REL32;

			}
		case 0xff:
			{
				// FF /4		JMP r/m64
				*new_rip = get_rm64(xedd, cpu, modrm, mc, mc_max_cnt);
				return TE_JMP_RM64;
			}
			break;
		default:
			printf("Unimplemented %x JMP\t", op_byte);
			break;
	}

	return 0;
}
//-----------------------------------------------------------------------------//
int emulate_call_near (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt, xed_uint64_t* new_rip)
{
	xed_uint8_t op_byte;

	op_byte = xed_decoded_inst_get_byte(xedd, 0);

	switch (op_byte)
	{
		case 0xe8:
			{
				// E8 cw	CALL rel32
				xed_int_t disp;
				disp = xed_decoded_inst_get_branch_displacement(xedd);
				printf("branch displacement 0x%x\t", disp);
				*new_rip = (xed_int64_t)cpu->gen_reg[REG_RIP].rrx + disp + 5;
				return TE_CALL_NEAR;
			}
			break;
		default:
			break;
	}

	return 0;
}
//-----------------------------------------------------------------------------//
int execute_one_instruction (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	int ret = 0;
	int instuction_len = 0;
	xed_uint64_t new_rip = 0;

	xed_state_t dstate;
	xed_chip_enum_t chip = XED_CHIP_INVALID;
	xed_error_enum_t xed_error;
	xed_iclass_enum_t iclass;

	xed_state_zero(&dstate);

	dstate.mmode=XED_MACHINE_MODE_LONG_64;
	//dstate.stack_addr_width=XED_ADDRESS_WIDTH_64b;
	xed_decoded_inst_zero_set_mode(xedd, &dstate);
	xed_decoded_inst_set_input_chip(xedd, chip);

	// fetch
	xed_error = xed_decode(xedd,
			XED_REINTERPRET_CAST(const xed_uint8_t*, cpu->gen_reg[REG_RIP].rrx),
			XED_MAX_INSTRUCTION_BYTES);
	switch(xed_error) 
	{
		case XED_ERROR_NONE:
			break;
		case XED_ERROR_BUFFER_TOO_SHORT:
			printf("Not enough bytes provided\n");
			exit(1);
		case XED_ERROR_INVALID_FOR_CHIP:
			printf("The instruction was not valid for the specified chip.\n");
			exit(1);
		case XED_ERROR_GENERAL_ERROR:
			printf("Could not decode given input.\n");
			exit(1);
		default:
			printf("Unhandled error code %s\n",
					xed_error_enum_t2str(xed_error));
			exit(1);
	}	
	instuction_len = xed_decoded_inst_get_length(xedd);


	// emulate instruction

	iclass = xed_decoded_inst_get_iclass(xedd);
	switch (iclass)
	{
		case XED_ICLASS_MOV:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			emulate_mov(xedd, cpu, mc, mc_max_cnt);
			break;
		case XED_ICLASS_MOVZX:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			emulate_movzx(xedd, cpu, mc, mc_max_cnt);
			break;
		case XED_ICLASS_MOVSXD:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			emulate_movsxd(xedd, cpu, mc, mc_max_cnt);
			break;
		case XED_ICLASS_LEA:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			emulate_lea(xedd, cpu, mc, mc_max_cnt);
			break;
		case XED_ICLASS_PUSH:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			emulate_push(xedd, cpu, mc, mc_max_cnt);
			break;
		case XED_ICLASS_POP:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			emulate_pop(xedd, cpu, mc, mc_max_cnt);
			break;
		case XED_ICLASS_ADD:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			emulate_add(xedd, cpu, mc, mc_max_cnt);
			break;
		case XED_ICLASS_SUB:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			emulate_sub(xedd, cpu, mc, mc_max_cnt);
			break;
		case XED_ICLASS_XOR:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			emulate_xor(xedd, cpu, mc, mc_max_cnt);
			break;
		case XED_ICLASS_CMP:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			emulate_cmp(xedd, cpu, mc, mc_max_cnt);
			break;
		case XED_ICLASS_TEST:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			emulate_test(xedd, cpu, mc, mc_max_cnt);
			break;
		case XED_ICLASS_JZ:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			ret = emulate_jz(xedd, cpu, mc, mc_max_cnt, &new_rip);
			if (TE_JUMP == ret)
			{
				cpu->gen_reg[REG_RIP].rrx = new_rip;
				printf("JZ to 0x%lx\t", new_rip);
				return 0;
			}
			else if (TE_SUCCESS == ret)
			{
				break;
			}
			else
			{
				printf("JZ error, stop!!!!!\n\n");
				return -1;
			}
			break;
		case XED_ICLASS_JNZ:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			ret = emulate_jnz(xedd, cpu, mc, mc_max_cnt, &new_rip);
			if (TE_JUMP == ret)
			{
				cpu->gen_reg[REG_RIP].rrx = new_rip;
				printf("JNZ to 0x%lx\t", new_rip);
				return 0;
			}
			else if (TE_SUCCESS == ret)
			{
				break;
			}
			else
			{
				printf("JNZ error, stop!!!!!\n\n");
				return -1;
			}
			break;
		case XED_ICLASS_JNBE:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			ret = emualte_jnbe(xedd, cpu, mc, mc_max_cnt, &new_rip);
			if (TE_JUMP == ret)
			{
				cpu->gen_reg[REG_RIP].rrx = new_rip;
				printf("JNBE to 0x%lx\t", new_rip);
				return 0;
			}
			else if (TE_SUCCESS == ret)
			{
				break;
			}
			else
			{
				printf("JNBE error, stop!!!!!\n\n");
				return -1;
			}
			break;
		case XED_ICLASS_JMP:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			ret = emulate_jmp(xedd, cpu, mc, mc_max_cnt, &new_rip);
			if (TE_JUMP == ret)
			{
				cpu->gen_reg[REG_RIP].rrx = new_rip;
				printf("JMP to 0x%lx\t", new_rip);
				return 0;
			}
			else if (TE_JMP_REL32 == ret)
			{
				printf("\nEMULATION END: jmp rel32 0x%lx\n\n", new_rip);
				return TE_EMULATION_END;
			}
			else if (TE_JMP_RM64 == ret)
			{
				printf("\nEMULATION END: jmp r/m64 0x%lx\n\n", new_rip);
				return TE_EMULATION_END;
			}
			else
			{
				printf("JMP error, stop!!!!!\n\n");
				return -1;
			}
			break;
		case XED_ICLASS_CALL_NEAR:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			ret = emulate_call_near(xedd, cpu, mc, mc_max_cnt, &new_rip);
			if (TE_CALL_NEAR == ret)
			{
				// need to setup call stack, but for now, ends here
				printf("call(rel32) 0x%lx\n\n", new_rip);
				return TE_EMULATION_END;
			}
			else
			{
				printf("CALL error, stop!!!!!\n\n");
				return -1;
			}
			break;
		case XED_ICLASS_RET_NEAR:
			printf("iclass %s\t", xed_iclass_enum_t2str(iclass));
			printf("function return 0x%llx\n", cpu->gen_reg[REG_RAX].rrx);
			return TE_EMULATION_END;
		default:
			printf("Unimplemented iclass %s\n", xed_iclass_enum_t2str(iclass));
			break;
	}

	// update RIP
	cpu->gen_reg[REG_RIP].rrx += instuction_len;

	return 0;
}
//-----------------------------------------------------------------------------//
int cpu_loop (cpu_t* cpu, int instruction_max_cnt, mc_t* mc, int mc_max_cnt /*, other quit conditions*/)
{
	xed_decoded_inst_t xedd;

	int ret = 0;
	int i = 0;

	xed_tables_init();

	for (i = 0; i < instruction_max_cnt; i++) {

		printf("RIP: 0x%llx\n", cpu->gen_reg[REG_RIP].rrx);
		ret = execute_one_instruction(&xedd, cpu, mc, mc_max_cnt);
		if (0 != ret) break;
		printf("\n\n");
	}

	return ret;
}
//-----------------------------------------------------------------------------//
int te_function_emulate (int inst_count, void* func, long long int  para0, long long int para1, long long int para2, long long int para3)
{
	void* stack = NULL;

#define MC_MAX		50
	mc_t mc[MC_MAX];
	int i = 0;

	printf("testxed\n");

	for (i = 0; i < MC_MAX; i++)
	{
		mc[i].address = -1;
	}

#define STACK_SIZE	4096
	// setup stack
	posix_memalign(&stack, 16, STACK_SIZE);
	if (NULL == stack)
	{
		printf("posix_memalign fail\n");
		return -1;
	}

	g_cpu.stack_buf = stack;
	g_cpu.stack_buf_len = STACK_SIZE;


	// set pseduo segment register
	arch_prctl(ARCH_GET_FS, &g_cpu.pseudo_fs);
	//asm ("lea %%fs:0x0, %0\n": "=r"(g_cpu.pseduo_fs));   // segment overrdie prefix doesn't affect lea
	printf("pseudo_fs:0x%llx\n", g_cpu.pseudo_fs);

	// setup parameters
	g_cpu.gen_reg[REG_RSP].rrx = (Bit64u)stack + STACK_SIZE;
	g_cpu.gen_reg[REG_RBP].rrx = (Bit64u)stack + STACK_SIZE; // 

	printf("stack RSP:0x%llx RBP:0x%llx\n", g_cpu.gen_reg[REG_RSP].rrx, g_cpu.gen_reg[REG_RBP].rrx);

	g_cpu.gen_reg[REG_RDI].rrx = para0;
	g_cpu.gen_reg[REG_RSI].rrx = para1;
	g_cpu.gen_reg[REG_RDX].rrx = para2;
	g_cpu.gen_reg[REG_RCX].rrx = para3;

	// setup eip
	g_cpu.gen_reg[REG_RIP].rrx = (Bit64u)func;



	//printf("%d\n", testfunc(2,3));

	cpu_loop(&g_cpu, inst_count, mc, MC_MAX);


	free(stack);
	return 0;
}
//-----------------------------------------------------------------------------//
