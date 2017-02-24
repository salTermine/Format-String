# Make File

#CFLAGS=-m32 -g -Wall -DLEN1=1024 -DLEN2=512 -DRANDOM=random\(\)
CFLAGS=-m32 -g -Wall -DLEN1=1024 -DLEN2=512 -DRANDOM=0

all: dirs vuln.o my_malloc.o vuln 

dirs:
	@mkdir -p bin
	@mkdir -p objects

vuln: vuln.o my_malloc.o
	gcc $(CFLAGS) -o bin/vuln objects/vuln.o objects/my_malloc.o
	execstack -s bin/vuln

vuln.o: vuln.c my_malloc.h
	gcc $(CFLAGS) -c vuln.c -o objects/vuln.o

my_malloc.o: my_malloc.h my_malloc.c
	gcc $(CFLAGS) -c my_malloc.c -o objects/my_malloc.o

.PHONY: clean

clean:
	rm -rf bin
	rm -rf objects