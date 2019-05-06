#include "xed/xed-interface.h"

#include <stdio.h>
#include <stdlib.h>
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
} cpu_t;
//-----------------------------------------------------------------------------//
// memory content
typedef struct {
	Bit64u address;
	Bit64u value;
} mc_t;
//-----------------------------------------------------------------------------//
cpu_t g_cpu = {0};
//-----------------------------------------------------------------------------//
int execute_one_instruction(xed_decoded_inst_t* xedd, cpu_t* cpu, mc_t* mc, int mc_max_cnt)
{
	int ret = 0;
	int instuction_len = 0;

	xed_state_t dstate;
	xed_chip_enum_t chip = XED_CHIP_INVALID;
	xed_error_enum_t xed_error;
	
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


	printf("testxed\n");

	g_cpu.gen_reg[REG_RIP].rrx = (Bit64u)testfunc;
	cpu_loop(&g_cpu, 10, NULL, 0);

	return 0;
}
//-----------------------------------------------------------------------------//
