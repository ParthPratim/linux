include arch/lkl/auto.conf

KBUILD_CFLAGS += -fno-builtin

ifneq (,$(filter $(OUTPUT_FORMAT),elf64-x86-64 elf64-x86-64-freebsd elf32-littlearm elf64-littleaarch64))
KBUILD_CFLAGS += -fPIC 
else ifneq (,$(filter $(OUTPUT_FORMAT),pe-i386 pe-x86-64 ))
ifneq ($(OUTPUT_FORMAT),pe-x86-64)
prefix=_
endif
# workaround for #include_next<stdarg.h> errors
LINUXINCLUDE := -isystem arch/lkl/include/system $(LINUXINCLUDE)
# workaround for https://gcc.gnu.org/bugzilla/show_bug.cgi?id=52991
KBUILD_CFLAGS += -mno-ms-bitfields -g
else
$(error Unrecognized platform: $(OUTPUT_FORMAT))
endif

ifeq ($(shell test ".$(OUTPUT_FORMAT)" = .elf64-x86-64-freebsd -a \
                   ".$(CROSS_COMPILE)" = . &&  printf "true"), true)
NPROC=$(shell sysctl -n hw.ncpu)
else
NPROC=$(shell nproc)
endif

LDFLAGS_vmlinux += -r
LKL_ENTRY_POINTS := lkl_start_kernel lkl_sys_halt lkl_syscall lkl_trigger_irq \
	lkl_get_free_irq lkl_put_irq lkl_is_running lkl_bug lkl_printf

ifeq ($(OUTPUT_FORMAT),elf32-i386)
LKL_ENTRY_POINTS += \
	__x86.get_pc_thunk.bx __x86.get_pc_thunk.dx __x86.get_pc_thunk.ax \
	__x86.get_pc_thunk.cx __x86.get_pc_thunk.si __x86.get_pc_thunk.di
endif

LKL_ENTRY_POINTS += \
	dce_sock_socket dce_sock_close \
	dce_sock_recvmsg dce_sock_sendmsg dce_sock_getsockname dce_sock_getpeername \
	dce_sock_bind dce_sock_connect dce_sock_listen dce_sock_shutdown dce_sock_accept \
	dce_sock_ioctl dce_sock_setsockopt dce_sock_getsockopt dce_dev_create dce_dev_destroy \
	dce_dev_get_private dce_dev_set_address dce_dev_set_mtu dce_dev_rx dce_dev_create_packet \
	dce_sys_iterate_files dce_sys_file_read dce_sys_file_write __initcall_start __initcall_end setup_sim_init

core-y += arch/lkl/kernel/
core-y += arch/lkl/mm/
core-y += arch/lkl/drivers/
core-y += arch/lkl/dce/

all: lkl.o

lkl.o: vmlinux
	$(OBJCOPY) -R .eh_frame -R .syscall_defs $(foreach sym,$(LKL_ENTRY_POINTS),-G$(prefix)$(sym)) vmlinux lkl.o

arch/lkl/include/generated/uapi/asm/syscall_defs.h: vmlinux
	$(OBJCOPY) -j .syscall_defs -O binary --set-section-flags .syscall_defs=alloc $< $@
	$(Q) export tmpfile=$(shell mktemp); \
	sed 's/\x0//g' $@ > $$tmpfile; mv $$tmpfile $@ ; rm -f $$tmpfile

install: lkl.o headers arch/lkl/include/generated/uapi/asm/syscall_defs.h
	@echo "  INSTALL	$(INSTALL_PATH)/lib/lkl.o"
	@mkdir -p $(INSTALL_PATH)/lib/
	@cp lkl.o $(INSTALL_PATH)/lib/
	@$(srctree)/arch/lkl/scripts/headers_install.py \
		$(subst -j,-j$(NPROC),$(findstring -j,$(MAKEFLAGS))) \
		$(INSTALL_PATH)/include

archclean:
	$(Q)$(MAKE) $(clean)=$(boot)

define archhelp
  echo '  install	- Install library and headers to INSTALL_PATH/{lib,include}'
endef



