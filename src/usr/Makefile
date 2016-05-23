CFLAGS = -O2 -Wall -I..
XTABLES_SO_DIR = $(shell pkg-config xtables --variable xtlibdir)

all:
	gcc ${CFLAGS} -D_INIT=libxt_marksrcrange_init -fPIC -c -o libxt_MARKSRCRANGE.o libxt_MARKSRCRANGE.c
	gcc -shared -fPIC -o libxt_MARKSRCRANGE.so libxt_MARKSRCRANGE.o
clean:
	rm -f *.o *.so
install:
	sudo cp libxt_MARKSRCRANGE.so ${XTABLES_SO_DIR}
uninstall:
	sudo rm ${XTABLES_SO_DIR}/libxt_MARKSRCRANGE.so

