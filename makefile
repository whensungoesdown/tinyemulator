all: test_te

test_te: main.o libte.a
	gcc -g -Wall -o test_te main.o -L. -lte -Lxed/lib -lxed

main.o: main.c
	gcc -g -Wall -c main.c te.h

testxed.o: testxed.c
	gcc -g -Wall -fPIC -c testxed.c -Ixed/include #xed/lib/libxed.a 

libte.a: testxed.o xed/lib/libxed.a
	ar rcs libte.a testxed.o xed/lib/libxed.a

libs: libte.a

clean:
	rm -f test_te *.o *.a *.gch

