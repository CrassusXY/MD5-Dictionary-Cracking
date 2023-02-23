TRGDIR=./
OBJ=./obj
CPPFLAGS= -lssl -lcrypto -pthread -c -g -Wall -pedantic -std=c++2a -iquote inc

__start__: passcrack.out
	./passcrack.out

passcrack.out: ${OBJ} ${OBJ}/main.o
	g++ -o passcrack.out ${OBJ}/main.o -lssl -lcrypto -pthread

${OBJ}:
	mkdir ${OBJ}

${OBJ}/main.o: src/main.cpp inc/hashmd5.hh
	g++ ${CPPFLAGS} -o ${OBJ}/main.o src/main.cpp


clear:
	rm -f passcrack.out ${OBJ}/*