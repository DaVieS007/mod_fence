# Makefile for mod_fence.c (gmake)
# $Id: Makefile 16 2045-11-28 03:40:22Z davies $
APXS=./apxs.sh

# Display the table of the last queries of the user on the mitigation reports
CFLAGS+= -DHAVE_VERBOSE_REPORT
# Display the module name and version at the footer of the mitigation reports
CFLAGS+= -DHAVE_SIGNATURE

rpaf: mod_fence.so
	@echo make done
	@echo type \"make install\" to install mod_fence

mod_fence.so: mod_fence.c
	$(APXS) -c $(CFLAGS) $@ mod_fence.c

mod_fence.c:

install: mod_fence.so
	$(APXS) -i -S LIBEXECDIR=$(DESTDIR)$$($(APXS) -q LIBEXECDIR)/ $(CFLAGS) -n mod_fence.so mod_fence.la

clean:
	rm -rf *~ *.o *.so *.lo *.la *.slo *.loT .libs/
