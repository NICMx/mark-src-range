CFLAGS = -O2 -Wall -I..
XTABLES_SO_DIR = $(shell pkg-config xtables --variable xtlibdir)

all:
	make libxt_MARKSRCRANGE.so;
clean:
	rm -f *.o *.so
install:
	sudo cp libxt_MARKSRCRANGE.so ${XTABLES_SO_DIR}
uninstall:
	sudo rm ${XTABLES_SO_DIR}/libxt_MARKSRCRANGE.so
lib%.so: lib%.o
	gcc -shared -fPIC -o $@ $^;
lib%.o: lib%.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;

