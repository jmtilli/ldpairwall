AIRWALL_SRC_LIB := airwall.c secret.c detect.c yyutils.c hosthash.c porter.c udpporter.c conf.c reasshl.c
AIRWALL_SRC := $(AIRWALL_SRC_LIB) ldpairwall.c detecttest.c detectperf.c genchartbl.c unittest.c sz.c portertest.c udpportertest.c pcpclient.c

AIRWALL_LEX_LIB := conf.l
AIRWALL_LEX := $(AIRWALL_LEX_LIB)

AIRWALL_YACC_LIB := conf.y
AIRWALL_YACC := $(AIRWALL_YACC_LIB)

AIRWALL_LEX_LIB := $(patsubst %,$(DIRAIRWALL)/%,$(AIRWALL_LEX_LIB))
AIRWALL_LEX := $(patsubst %,$(DIRAIRWALL)/%,$(AIRWALL_LEX))

AIRWALL_YACC_LIB := $(patsubst %,$(DIRAIRWALL)/%,$(AIRWALL_YACC_LIB))
AIRWALL_YACC := $(patsubst %,$(DIRAIRWALL)/%,$(AIRWALL_YACC))

AIRWALL_LEXGEN_LIB := $(patsubst %.l,%.lex.c,$(AIRWALL_LEX_LIB))
AIRWALL_LEXGEN := $(patsubst %.l,%.lex.c,$(AIRWALL_LEX))

AIRWALL_YACCGEN_LIB := $(patsubst %.y,%.tab.c,$(AIRWALL_YACC_LIB))
AIRWALL_YACCGEN := $(patsubst %.y,%.tab.c,$(AIRWALL_YACC))

AIRWALL_GEN_LIB := $(patsubst %.l,%.lex.c,$(AIRWALL_LEX_LIB)) $(patsubst %.y,%.tab.c,$(AIRWALL_YACC_LIB))
AIRWALL_GEN := $(patsubst %.l,%.lex.c,$(AIRWALL_LEX)) $(patsubst %.y,%.tab.c,$(AIRWALL_YACC))

AIRWALL_SRC_LIB := $(patsubst %,$(DIRAIRWALL)/%,$(AIRWALL_SRC_LIB))
AIRWALL_SRC := $(patsubst %,$(DIRAIRWALL)/%,$(AIRWALL_SRC))

AIRWALL_OBJ_LIB := $(patsubst %.c,%.o,$(AIRWALL_SRC_LIB))
AIRWALL_OBJ := $(patsubst %.c,%.o,$(AIRWALL_SRC))

AIRWALL_OBJGEN_LIB := $(patsubst %.c,%.o,$(AIRWALL_GEN_LIB))
AIRWALL_OBJGEN := $(patsubst %.c,%.o,$(AIRWALL_GEN))

AIRWALL_DEP_LIB := $(patsubst %.c,%.d,$(AIRWALL_SRC_LIB))
AIRWALL_DEP := $(patsubst %.c,%.d,$(AIRWALL_SRC))

AIRWALL_DEPGEN_LIB := $(patsubst %.c,%.d,$(AIRWALL_GEN_LIB))
AIRWALL_DEPGEN := $(patsubst %.c,%.d,$(AIRWALL_GEN))

CFLAGS_AIRWALL := -I$(DIRPACKET) -I$(DIRLINKEDLIST) -I$(DIRIPHDR) -I$(DIRMISC) -I$(DIRLOG) -I$(DIRHASHTABLE) -I$(DIRHASHLIST) -I$(DIRPORTS) -I$(DIRALLOC) -I$(DIRTIMERLINKHEAP) -I$(DIRMYPCAP) -I$(DIRDYNARR) -I$(DIRIPHASH) -I$(DIRTHREETUPLE2) -I$(DIRDATABUF) -I$(DIRNETMAP) -I$(DIRLDP) -I$(DIRARP) -I$(DIRAIRWALL) -I$(DIRIPFRAG) -I$(DIRRBTREE)

MAKEFILES_AIRWALL := $(DIRAIRWALL)/module.mk

#LIBS_AIRWALL := $(DIRSACKHASH)/libsackhash.a $(DIRIPHASH)/libiphash.a $(DIRDYNARR)/libdynarr.a $(DIRALLOC)/liballoc.a $(DIRIPHDR)/libiphdr.a $(DIRHASHTABLE)/libhashtable.a $(DIRHASHLIST)/libhashlist.a $(DIRTIMERLINKHEAP)/libtimerlinkheap.a $(DIRMISC)/libmisc.a $(DIRTHREETUPLE)/libthreetuple.a $(DIRDATABUF)/libdatabuf.a $(DIRNETMAP)/libnetmap.a $(DIRLOG)/liblog.a $(DIRLDP)/libldp.a $(DIRPORTS)/libports.a $(DIRMYPCAP)/libmypcap.a
#LIBS_AIRWALL := $(DIRSACKHASH)/libsackhash.a $(DIRTHREETUPLE)/libthreetuple.a $(DIRLIBPPTK)/libpptk.a
LIBS_AIRWALL := $(DIRTHREETUPLE2)/libthreetuple2.a $(DIRLIBPPTK)/libpptk.a

.PHONY: AIRWALL clean_AIRWALL distclean_AIRWALL unit_AIRWALL $(LCAIRWALL) clean_$(LCAIRWALL) distclean_$(LCAIRWALL) unit_$(LCAIRWALL)

$(LCAIRWALL): AIRWALL
clean_$(LCAIRWALL): clean_AIRWALL
distclean_$(LCAIRWALL): distclean_AIRWALL
unit_$(LCAIRWALL): unit_AIRWALL

AIRWALL: $(DIRAIRWALL)/libairwall.a

ifeq ($(WITH_NETMAP),yes)
CFLAGS_AIRWALL += -I$(NETMAP_INCDIR)
endif
ifeq ($(WITH_ODP),yes)
CFLAGS_AIRWALL += -I$(ODP_DIR)/include
LIBS_AIRWALL_ODP := $(ODP_DIR)/lib/libodp-linux.a $(LIBS_ODPDEP)
endif
AIRWALL: $(DIRAIRWALL)/ldpairwall $(DIRAIRWALL)/detecttest $(DIRAIRWALL)/detectperf $(DIRAIRWALL)/genchartbl $(DIRAIRWALL)/unittest $(DIRAIRWALL)/sz $(DIRAIRWALL)/portertest $(DIRAIRWALL)/udpportertest $(DIRAIRWALL)/pcpclient

unit_AIRWALL: $(DIRAIRWALL)/detecttest $(DIRAIRWALL)/detectperf $(DIRAIRWALL)/unittest
	$(DIRAIRWALL)/detecttest
	$(DIRAIRWALL)/detectperf
	$(DIRAIRWALL)/unittest

$(DIRAIRWALL)/libairwall.a: $(AIRWALL_OBJ_LIB) $(AIRWALL_OBJGEN_LIB) $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	rm -f $@
	ar rvs $@ $(filter %.o,$^)

$(DIRAIRWALL)/sz: $(DIRAIRWALL)/sz.o $(DIRAIRWALL)/libairwall.a $(LIBS_AIRWALL) $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_AIRWALL) $(LDFLAGS_LDP) -lpthread -ldl

$(DIRAIRWALL)/portertest: $(DIRAIRWALL)/portertest.o $(DIRAIRWALL)/libairwall.a $(LIBS_AIRWALL) $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_AIRWALL) $(LDFLAGS_LDP) -lpthread -ldl

$(DIRAIRWALL)/udpportertest: $(DIRAIRWALL)/udpportertest.o $(DIRAIRWALL)/libairwall.a $(LIBS_AIRWALL) $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_AIRWALL) $(LDFLAGS_LDP) -lpthread -ldl

$(DIRAIRWALL)/genchartbl: $(DIRAIRWALL)/genchartbl.o $(DIRAIRWALL)/libairwall.a $(LIBS_AIRWALL) $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_AIRWALL) $(LDFLAGS_LDP) -lpthread -ldl

$(DIRAIRWALL)/detecttest: $(DIRAIRWALL)/detecttest.o $(DIRAIRWALL)/libairwall.a $(LIBS_AIRWALL) $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_AIRWALL) $(LDFLAGS_LDP) -lpthread -ldl

$(DIRAIRWALL)/detectperf: $(DIRAIRWALL)/detectperf.o $(DIRAIRWALL)/libairwall.a $(LIBS_AIRWALL) $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_AIRWALL) $(LDFLAGS_LDP) -lpthread -ldl

$(DIRAIRWALL)/ldpairwall: $(DIRAIRWALL)/ldpairwall.o $(DIRAIRWALL)/libairwall.a $(LIBS_AIRWALL) $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_AIRWALL) $(LDFLAGS_LDP) -lpthread -ldl

$(DIRAIRWALL)/unittest: $(DIRAIRWALL)/unittest.o $(DIRAIRWALL)/libairwall.a $(LIBS_AIRWALL) $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_AIRWALL) $(LDFLAGS_LDP) -lpthread -ldl

$(DIRAIRWALL)/pcpclient: $(DIRAIRWALL)/pcpclient.o $(DIRAIRWALL)/libairwall.a $(LIBS_AIRWALL) $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(filter %.a,$^) $(CFLAGS_AIRWALL) $(LDFLAGS_LDP) -lpthread -ldl

$(AIRWALL_OBJ): %.o: %.c %.d $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -c -o $*.o $*.c $(CFLAGS_AIRWALL)
	$(CC) $(CFLAGS) -c -S -o $*.s $*.c $(CFLAGS_AIRWALL)
$(AIRWALL_OBJGEN): %.o: %.c %.h %.d $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -c -o $*.o $*.c $(CFLAGS_AIRWALL) -Wno-sign-compare -Wno-missing-prototypes
	$(CC) $(CFLAGS) -c -S -o $*.s $*.c $(CFLAGS_AIRWALL) -Wno-sign-compare -Wno-missing-prototypes

$(AIRWALL_DEP): %.d: %.c $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -MM -MP -MT "$*.d $*.o" -o $*.d $*.c $(CFLAGS_AIRWALL)
$(AIRWALL_DEPGEN): %.d: %.c %.h $(MAKEFILES_COMMON) $(MAKEFILES_AIRWALL)
	$(CC) $(CFLAGS) -MM -MP -MT "$*.d $*.o" -o $*.d $*.c $(CFLAGS_AIRWALL)

$(DIRAIRWALL)/conf.lex.d: $(DIRAIRWALL)/conf.tab.h $(DIRAIRWALL)/conf.lex.h
$(DIRAIRWALL)/conf.lex.o: $(DIRAIRWALL)/conf.tab.h $(DIRAIRWALL)/conf.lex.h
$(DIRAIRWALL)/conf.tab.d: $(DIRAIRWALL)/conf.lex.h $(DIRAIRWALL)/conf.tab.h
$(DIRAIRWALL)/conf.tab.o: $(DIRAIRWALL)/conf.lex.h $(DIRAIRWALL)/conf.tab.h

$(DIRAIRWALL)/CONF.LEX.INTERMEDIATE: $(DIRAIRWALL)/conf.l
	mkdir -p $(DIRAIRWALL)/intermediatestore
	flex --outfile=$(DIRAIRWALL)/intermediatestore/conf.lex.c --header-file=$(DIRAIRWALL)/intermediatestore/conf.lex.h $(DIRAIRWALL)/conf.l
	touch $(DIRAIRWALL)/CONF.LEX.INTERMEDIATE
$(DIRAIRWALL)/CONF.TAB.INTERMEDIATE: $(DIRAIRWALL)/conf.y
	mkdir -p $(DIRAIRWALL)/intermediatestore
	bison --defines=$(DIRAIRWALL)/intermediatestore/conf.tab.h --output=$(DIRAIRWALL)/intermediatestore/conf.tab.c $(DIRAIRWALL)/conf.y
	touch $(DIRAIRWALL)/CONF.TAB.INTERMEDIATE
$(DIRAIRWALL)/conf.lex.c: $(DIRAIRWALL)/CONF.LEX.INTERMEDIATE
	cp $(DIRAIRWALL)/intermediatestore/conf.lex.c $(DIRAIRWALL)
$(DIRAIRWALL)/conf.lex.h: $(DIRAIRWALL)/CONF.LEX.INTERMEDIATE
	cp $(DIRAIRWALL)/intermediatestore/conf.lex.h $(DIRAIRWALL)
$(DIRAIRWALL)/conf.tab.c: $(DIRAIRWALL)/CONF.TAB.INTERMEDIATE
	cp $(DIRAIRWALL)/intermediatestore/conf.tab.c $(DIRAIRWALL)
$(DIRAIRWALL)/conf.tab.h: $(DIRAIRWALL)/CONF.TAB.INTERMEDIATE
	cp $(DIRAIRWALL)/intermediatestore/conf.tab.h $(DIRAIRWALL)

clean_AIRWALL:
	rm -f $(AIRWALL_OBJ) $(AIRWALL_OBJGEN) $(AIRWALL_DEP) $(AIRWALL_DEPGEN)
	rm -rf $(DIRAIRWALL)/intermediatestore
	rm -f $(DIRAIRWALL)/CONF.TAB.INTERMEDIATE
	rm -f $(DIRAIRWALL)/CONF.LEX.INTERMEDIATE
	rm -f $(DIRAIRWALL)/conf.lex.c
	rm -f $(DIRAIRWALL)/conf.lex.h
	rm -f $(DIRAIRWALL)/conf.tab.c
	rm -f $(DIRAIRWALL)/conf.tab.h

distclean_AIRWALL: clean_AIRWALL
	rm -f $(DIRAIRWALL)/libairwall.a $(DIRAIRWALL)/ldpairwall

-include $(DIRAIRWALL)/*.d
