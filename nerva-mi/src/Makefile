DEBUG_CFLAGS = -DDEBUG -g
SRCS = $(wildcard $(MAIN_SRC)/*.c)
INCS = $(wildcard $(MAIN_INC)/*.h) 

release: libminv.a minerva

#Test-Debug
#PUBLIB_DIR:=../../../PUBLIC_LIB
#EXT_CFLAGS+=-I/usr/local/include_daq_206 -I$(PUBLIB_DIR)/include
#EXT_LDFLAGS+=-L/usr/local/lib_daq_206
#RTE_SDK=/home/lhzy01/git/surveyor/usi_midware/dpdk-stable-16.07.2
#RTE_TARGET=build
#Test-Debug End

EXT_CFLAGS+=-I$(RTE_SDK)/$(RTE_TARGET)/include -DBUILD_DPDK_MODULE -msse4 
EXT_LDFLAGS+=-L./ -L/usr/lib/x86_64-linux-gnu -L$(RTE_SDK)/$(RTE_TARGET)/lib -Wl,--whole-archive,-ldpdk,--no-whole-archive 

MI_DIR=./

#header
_MI_DEPS=mn_gen.h mn_daq.h statsifc.h mn_sf_cfl.h minerva.h mn_sf_sys_var.h mn_mem_schedule.h
#_MI_DEPS=statsifc.h minerva.h
MI_DEPS=$(patsubst %, $(MI_DIR)/%, $(_MI_DEPS))
#EXEC
_MI_OBJS=mn_daq.o statsifc.o mn_sf_cfl.o minerva.o
MI_OBJS=$(patsubst %, $(MI_DIR)/%, $(_MI_OBJS))
#LIBS
_MI_S_OBJS=mn_sf_sys_var.o
MI_S_OBJS=$(patsubst %, $(MI_DIR)/%, $(_MI_S_OBJS))

%.o: %.c $(MI_DEPS)
	gcc $(EXT_CFLAGS) -c -o $@ $< 

libminv.a: $(MI_S_OBJS) $(MI_DEPS)
	ar rcs $@ $^
	-cp -f $@ $(PUBLIB_DIR)/lib

minerva: $(MI_OBJS)
	@echo "#####building minerva...#####"
	gcc -o $@ $^ $(EXT_LDFLAGS) -lminv -lmysqlclient_r -lrt -lheartbeat -ldl -lpthread -lm -ldaq_static -ldaq_static_modules -lpcap -lsfbpf
	@echo "#####build minerva end...#####"
	-cp -f jhash.h branch_prediction.h mn_sf_cfl.h mn_sf_sys_var.h mn_mem_schedule.h $(PUBLIB_DIR)/include

debug:
	$(CC)	$(DEBUG_CFLAGS) $(SRCS) $(INCS) -o minerva -I $(LIBS)
clean:
	-rm -rf *.o *.a minerva
install:
