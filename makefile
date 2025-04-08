# Makefile for cdes 
# Chris K Cockrum

cdes : cdes.c
	gcc -O6 cdes.c -o cdes -lm
	./test

debug : cdes.c
	gcc -O6 cdes.c -o cdes -lm -DDEBUG 
	./test 

clean :
	rm -f cdes outtest
