#include "xed/xed-interface.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
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
//-----------------------------------------------------------------------------//
cpu_t g_cpu = {0};
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
xed_uint32_t get_rm32 (xed_decoded_inst_t* xedd, cpu_t* cpu, modrm_t modrm, mc_t* mc, int mc_max_cnt)
{
	xed_int64_t address = 0;
	xed_int64_t disp = 0;
	xed_int32_t ret_value = 0;

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
			}
			break;
		case 3:
			return get_r32(cpu, modrm);
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

	if (3 == modrm.rm)
	{
		printf("ERROR in set_rm32!!!!!!!!!!!!!\n");
		exit(1);
	}

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
		printf("Write memory outside of current stack, (to mc), address 0x%lx, value 0x%x\t", address, value);
		pmc->address = address;
		pmc->value = value;
	}

	return 0;
}
//-----------------------------------------------------------------------------//
int set_r32 (cpu_t* cpu, modrm_t modrm, xed_uint32_t value)
{
	switch (modrm.reg)
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

	return 0;
}
//-----------------------------------------------------------------------------//
int set_r64 (cpu_t* cpu, modrm_t modrm, xed_uint64_t value)
{
	// r64 means mod must be 11

	//printf("test!!!!!!!! sizeof(long unsigned int)=%ld\t", sizeof(long unsigned int));

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

	return 0;
}
//-----------------------------------------------------------------------------//
int push64 (cpu_t* cpu, xed_uint64_t value)
{
	xed_uint64_t* p = NULL;

	cpu->gen_reg[REG_RSP].rrx -= 8;

	p = (xed_uint64_t*)cpu->gen_reg[REG_RSP].rrx;

	*p = value;

	return 0;
}
//-----------------------------------------------------------------------------//
int emulate_push (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	xed_uint8_t op_byte;
	xed_uint_t np;
	np = xed_decoded_inst_get_nprefixes(xedd);
	op_byte = xed_decoded_inst_get_byte(xedd, np);


	if (0x50 == (op_byte & 0xf0))
	{
		int reg = op_byte & 0x7;
		xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);
		xed_uint64_t value;

		printf("%2x PUSH %s\t", op_byte, xed_reg_enum_t2str(r0));
		if (0 != np)
		{
			printf("PREFIX PUSH unhandled!!!!!!!!!\t");
			return 0;
		}

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
	else
	{
		printf("%2x PUSH unhandled!!!!!!!!!\t", op_byte);
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
	int size = 1;


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
						set_r64(cpu, modrm, value);
					}
					else
					{
						// 32
						printf("Unimplemented!!!!! mov reg32, reg32\t");
						//xed_uint32_t value;
						//value = get_r32(cpu, modrm);
						//set_r64(cpu, modrm, value);
					}


				}
				else if (1 == modrm.mod)
				{
					// mov r/m+disp8, reg
					if (0 != np)
					{
						printf("Unimplemented!!!!! PREFIX mov r/m+disp8, reg\t");
					}
					else 
					{
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
				// REW.W + 8B/r		MOV r64, r/m64
				//
				modrm_t modrm;
				xed_reg_enum_t r0 = xed_decoded_inst_get_reg(xedd, XED_OPERAND_REG0);

				modrm.byte = xed_decoded_inst_get_modrm(xedd);
				printf("8B MOV ModR/M %2x\t", modrm.byte);
				printf("mod 0x%x, reg 0x%x, rm 0x%x\t", modrm.mod, modrm.reg, modrm.rm);

				switch (modrm.mod)
				{
					case 0:
						printf("Unimplemented!!!! 8B mov mod 0\t");
						break;
					case 1:
						{
							if (0 != np)
							{
								printf("Unimplemented!!!! PREFIX 8B mov mod 1\t");
							}
							else
							{
								// mov r32, [r64]+disp8
								xed_uint32_t value;
								value = get_rm32(xedd, cpu, modrm, mc, mc_max_cnt);
								set_r32(cpu, modrm, value);
							}
						}
						break;
					case 2:
						printf("Unimplemented!!!! 8B mov mod 2\t");
						break;
					case 3:
						printf("Unimplemented!!!! 8B mov mod 3\t");
						break;
				}
			}
			break;
		case 0xC7:
			printf("C7 MOV\t");
			break;
		default:
			printf("Unhandled MOV %x\t", op_byte);
			break;

	}

	return 0;
}
//-----------------------------------------------------------------------------//
int execute_one_instruction (xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	int ret = 0;
	int instuction_len = 0;

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
			emulate_mov(xedd, cpu, mc, mc_max_cnt);
			printf("iclass %s\n\n", xed_iclass_enum_t2str(iclass));
			break;
		case XED_ICLASS_PUSH:
			emulate_push(xedd, cpu, mc, mc_max_cnt);
			printf("iclass %s\n\n", xed_iclass_enum_t2str(iclass));
			break;
		case XED_ICLASS_POP:
			printf("iclass %s\n\n", xed_iclass_enum_t2str(iclass));
			break;
		case XED_ICLASS_ADD:
			printf("iclass %s\n\n", xed_iclass_enum_t2str(iclass));
			break;
		case XED_ICLASS_RET_NEAR:
			printf("iclass %s\n\n", xed_iclass_enum_t2str(iclass));
			break;

		default:
			printf("Unhandled iclass %s\n", xed_iclass_enum_t2str(iclass));
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
	}

	return ret;
}
//-----------------------------------------------------------------------------//
int testfunc(int a, int b)
{
	return a + b;
}
//-----------------------------------------------------------------------------//
int main(void)
{
	void* stack = NULL;

#define MC_MAX		10
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

	// setup parameters
	g_cpu.gen_reg[REG_RSP].rrx = (Bit64u)stack + STACK_SIZE;
	g_cpu.gen_reg[REG_RBP].rrx = (Bit64u)stack + STACK_SIZE; // 

	// setup eip
	g_cpu.gen_reg[REG_RIP].rrx = (Bit64u)testfunc;

	cpu_loop(&g_cpu, 10, mc, MC_MAX);


	free(stack);
	return 0;
}
//-----------------------------------------------------------------------------//
