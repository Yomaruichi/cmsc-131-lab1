# CMSC 131 platform preamble. Shared by every laboratory activity.
#
# This file is not a Makefile on its own. make-lab-bundles.sh concatenates it
# ahead of each lab's own Makefile, the part that names that lab's objects
# and targets. A student's bundle then holds one Makefile that reads top to
# bottom: platform detection first, then the activity's rules. The platform
# logic is the only part that repeats across activities, so this split keeps
# it in one place instead of three.
#
# The platform check asks twice on purpose. Windows sets OS=Windows_NT in the
# environment and a native make imports it. That alone is not enough. A make
# built for MSYS2 or Cygwin reports OS as empty even on Windows, and such a
# make is easy to install by accident. Asking uname as well stops this file
# from quietly picking the Linux branch on a Windows machine and failing
# several steps later.

UNAME := $(shell uname -s 2>/dev/null)

ifeq ($(OS),Windows_NT)
  PLATFORM := windows
else ifneq (,$(findstring MINGW,$(UNAME)))
  PLATFORM := windows
else ifneq (,$(findstring MSYS,$(UNAME)))
  PLATFORM := windows
else ifneq (,$(findstring CYGWIN,$(UNAME)))
  PLATFORM := windows
else
  PLATFORM := $(UNAME)
endif

NASM := nasm
CC   := gcc

ifeq ($(PLATFORM),windows)
  # COFF objects. The linker also needs to know this is a console program
  # rather than a windowed one.
  ASFLAGS := -f win32
  LDFLAGS := -Wl,-subsystem,console
  EXE     := .exe
else
  # ELF objects. -d ELF_TYPE reaches every assembly file, where it respells
  # the decorated entry points. asm_io.inc uses the same trick for the
  # bootcamp blocks. You write the Windows spelling everywhere, and the flag
  # swaps it for the undecorated one C uses on Linux.
  #
  # -no-pie matters. gcc has defaulted to position-independent executables
  # since Ubuntu 17.10, and the absolute addressing this course's assembly
  # uses cannot be relocated that way. Without it the link fails with
  # "relocation R_386_32 ... can not be used when making a PIE object".
  ASFLAGS := -f elf32 -d ELF_TYPE
  LDFLAGS := -no-pie
  EXE     :=
endif

CFLAGS := -m32

# The laboratory activities bind assembly to a C driver under the cdecl
# convention. An object rule for each language and one link rule therefore
# cover every activity's build. Names are decorated with a leading
# underscore on Windows but not on Linux. The assembly sources handle that
# themselves (there is no asm_io.inc remap here), so nothing in this file
# does.
%.obj: %.asm
	$(NASM) $(ASFLAGS) $< -o $@

%.o: %.c cdecl.h
	$(CC) $(CFLAGS) -c $< -o $@
# renpkt build rules. Every laboratory activity shares the platform preamble
# above this file. It lives in lab-shared/Makefile.platform. It covers
# platform detection, NASM and CC, flags, and the object rules.
#
# This half names this activity's objects and targets:
#
#   make            build renpkt and the contract test
#   make check      build both, then run ./run_tests.sh
#   make test       alias for check
#   make clean      delete build output
#
# Driver-side file I/O and formatting are C. The three routines that do the
# bit work are assembly. Link them together and you have the tool.
#
# contract_test and contract_regs are the provided second pass. They call
# the three routines directly, so they catch an encode path that loses a
# field and a routine that clobbers a callee-saved register. Neither one is
# yours to edit.

BIN  := renpkt$(EXE)
OBJS := driver.o decode.obj encode.obj checksum.obj

TESTBIN  := contract_test$(EXE)
TESTOBJS := contract_test.o contract_regs.obj decode.obj encode.obj checksum.obj

# The default goal builds both programs, so a plain `make` leaves the
# directory ready for run_tests.sh.
all: $(BIN) $(TESTBIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TESTBIN): $(TESTOBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

driver.o: driver.c cdecl.h
contract_test.o: contract_test.c cdecl.h

decode.obj: decode.asm
encode.obj: encode.asm
checksum.obj: checksum.asm
contract_regs.obj: contract_regs.asm

check: $(BIN) $(TESTBIN)
	bash ./run_tests.sh

test: check

clean:
	rm -f $(BIN) $(TESTBIN) *.obj *.o

.PHONY: all check test clean
