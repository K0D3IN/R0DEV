CC = gcc
CFLAGS = -Wall -O2 -fPIC -fmacro-prefix-map=$(PWD)=.
LDFLAGS = -ldl
STRIP = strip

.PHONY: all clean strip

all: rootkit.so fix_rootkit forcekill injector

rootkit.so: rootkit.c
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDFLAGS)

fix_rootkit: fix_rootkit.c
	$(CC) $(CFLAGS) -static -o $@ $<

forcekill: forcekill.c
	$(CC) $(CFLAGS) -static -o $@ $<

injector: injector.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

strip:
	$(STRIP) -s rootkit.so fix_rootkit forcekill injector 2>/dev/null; true

clean:
	rm -f rootkit.so fix_rootkit forcekill injector *.o
