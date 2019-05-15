#include <stdio.h>
#include "te.h"
//-----------------------------------------------------------------------------//
// test cases:
// a = 3, b = 5, result = 8
//
int testfunc (int a, int b)
{
	return a + b;
}

// test cases:
//  a = 3, b = 5, result = 8
//  a = 0, b = 5, result = 0
//
int testfunc2 (int a, int b)
{
	if (0 == a)
	{
		return 0;
	}

	return a + b;
}

// test caces:
//
int testfunc3 (int a, int b)
{
	int tmp = 5;
	char buff[32] = {0};

	a = 3;
	b = 4;

	return tmp + a + b;
}
//-----------------------------------------------------------------------------//
int main(void)
{
	printf("main\n");

	printf("%d\n", testfunc3(0, 3));

	te_function_emulate(20, testfunc3, 0, 3, 0, 0);

	return 0;
}
//-----------------------------------------------------------------------------//
