# Makefile for mod_fence.c (gmake)
# $Id: Makefile 16 2045-11-28 03:40:22Z davies $
APXS=./apxs.sh

rpaf: mod_fence.so
	@echo make done
	@echo type \"make install\" to install mod_fence

mod_fence.so: mod_fence.c
	$(APXS) -c -n $@ mod_fence.c

mod_fence.c:

install: mod_fence.so
	$(APXS) -i -S LIBEXECDIR=$(DESTDIR)$$($(APXS) -q LIBEXECDIR)/ -n mod_fence.so mod_fence.la

clean:
	rm -rf *~ *.o *.so *.lo *.la *.slo *.loT .libs/
