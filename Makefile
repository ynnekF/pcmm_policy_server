SHELL=/bin/bash

# GNU make knows how to execute several recipes at once. Normally, make will execute only one
# recipe at a time, waiting for it to finish before executing the next. However, the ‘-j’ or
# ‘--jobs’ option tells make to execute many recipes simultaneously. Not defining the option
# SINGLE_CPU_EXEC will allow this makefile to use the maximum number of physical CPUs.
# See link for more info (https://www.gnu.org/software/make/manual/html_node/Parallel.html)
ifndef SINGLE_CPU_EXEC
    NCPU 		?= $(shell (nproc --all || sysctl -n hw.physicalcpu) 2>/dev/null || echo 1)
    MAKEFLAGS	+= --jobs=$(NCPU)
endif

# Path to executable `gcc` (/usr/bin/gcc). MUST be installed prior to using this makefile.
# (brew install gcc, apt-get install -y gcc, etc.)
CC=$(shell which gcc)

# Included a GCC version check and GNU make check for visibility but it may not be required.
ifneq ($(firstword $(shell $(firstword $(MAKE)) --version)),GNU)
$(error GNU make is not installed.)
endif

GCC_VERSION=$(shell $(CC) -dumpversion)

ifneq ($(GCC_VERSION),$(filter $(GCC_VERSION),15.0.0 14.1.0))
$(warning Untested GCC version)
endif

# Directory Structure Options
CWD=$(shell pwd)

# Directory with source files
SRC_DIR=src

# Directory with header files
INC_DIR=include

# Directory for compiled output. This directory's format should match that of the src 
# directory but where the *.c files are, this wll have object files and a top-level exe.
BIN_DIR=bin

# RPM target directory ./rpmbuild contains all RPMs and build specs.
# RPM target directory ./dist contains TGZs and source files.
BUILD_DIR := $(CWD)/build
DIST_DIR := $(BUILD_DIR)/dist

# C Source test file directory and options. Test code is only compiled if COMPILE_TEST=1 and
# is only required when the unittest option is given to the main arguments.
TP_DIR=tests

# Test source code subpath
TP_PATH=$(TP_DIR)\/policy_server\/unit

# Similar to `FOLDERS` below but this is used when creating the compilation targets
DIRS=$(sort $(SRC_DIR) $(TP_DIR))

# Source file suffix
CEXT=c

# Header file suffix
HEXT=h
#
# Compile Time Options
#
# Here we include any libraries we want to link, prefixed with "-l". The -l option (-l<library>)
# is passed directly to the linker by GCC to search standard libraries and any specified by "-L".
LIBS = -lulfius -ljansson
# Library paths specified by "-L/path/to/lib"
LDFLAGS= -g

# C Compiler flags
CFLAGS= -g

# Enfore executable is recompiled when header files are changed. When used with -M or -MM,
# specifies a file to write the dependencies to. If no -MF switch is given the preprocessor
# sends the rules to the same place it would send preprocessed output. When used with the
# driver options -MD or -MMD, -MF overrides the default dependency output file.
C_DEPS=-MMD -MF $(@:.o=.d)

# Preprocessor macro definitions. These values will be predefined on each
# source file before compilation. Currently there are two optional macros.
# ex. -DUNIT_TEST
C_DEFINES=

# Extra preprocessor macro definitions not computed by below logic. Can be
# populated here or during make (i.e., make C_EXTRA_DEFINES=-DNO_COLOR run)
C_EXTRA_DEFINES=

# List of directories and libraries to be searched for header files.
# The files under include will be searched before anything else.
# ex. -I/opt/homebrew/include/
C_INCLUDES=-I $(INC_DIR) $(LIBS)

# Compiler warning flags
#
# Wall: 			Enable all warnings
# Wextra: 			Enable extra warnings
# Wpedantic: 		Enable pedantic warnings
# Wformat=2:		Enable Wformat plus checks
# Wshawdow:			Warn on shadowed variables
# Wwrite-strings:   Copying the address of one into a non-const char * pointer produces a warning
#
C_WARNINGS= -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Wredundant-decls\
			-Wnested-externs -Wmissing-include-dirs -Wold-style-definition -Wno-unused-parameter

# With -O, the compiler tries to reduce code size and execution time, without performing any
# optimizations that take a great deal of compilation time. As compared to -O, this -02
# increases both compilation time and the performance of the generated code. -03 is the max.
# https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html
ifdef BUILD_OPTIMIZATIONS
    CFLAGS 	+= -O2
endif

# gcc Show commands to run and use verbose output
ifdef LD_VERBOSE
    LDFLAGS += -v
endif

ifdef ALL_WARNINGS
    C_WARNINGS 	+= 	-Wformat=2 -Wwrite-strings
endif

# System processor arch and hardware
UNAME_P=$(shell uname -p)
UNAME_M=$(shell uname -m)

# Directories to search for targets
FOLDERS=$(SRC_DIR) $(INC_DIR)
MAX_DEPTH=1

ifeq ($(OS),Windows_NT)
    OS = windows
else
    KERNEL=$(shell uname -s)
	ifeq ($(KERNEL),Darwin)
        OS = macos
	else ifeq ($(KERNEL),Linux)
        OS = linux
	else
$(error unsupported OS)
	endif
endif

ifneq ($(OS),linux)
    C_WARNINGS +=  -Wno-unused-command-line-argument
endif

# When COMPILE_TEST is set to one, increment the MAX_DEPTH value to include test 
# related header files, include the test directory in the FOLDERS variable and
# add the UNIT_TEST macro to our preprocessor options.
ifeq ($(COMPILE_TEST),1)
    MAX_DEPTH := 2
    FOLDERS	+= $(TP_PATH)
    C_DEFINES += -DUNIT_TEST

	ifeq ($(EXCLUDE_API_JSON),1)
        C_DEFINES += -DEXCLUDE_JSON_TEST
	endif

	LDFLAGS += -I$(TP_PATH)/include
endif

ifeq ($(OS),windows)
    SHELL := powershell.exe
    PATHS := $(SRC_DIR), $(INC_DIR)
    .SHELLFLAGS := -NoProfile -Command
    ifeq ($(PROCESSOR_ARCHITECTURE),x86)
        CC += -D IA32
    endif
    ifeq ($(COMPILE_TEST),1)
        PATHS +=, $(TP_PATH)
    endif
    HEADER_FILES := $(shell (Get-ChildItem \
							 -Path $(PATHS)\
							 -Filter "*.$(HEXT)"\
							 -recurse | Resolve-Path -Relative))

    SOURCE_FILES := $(shell (Get-ChildItem\
							 -Path $(PATHS)\
							 -Filter "*.$(CEXT)"\
							-recurse | Resolve-Path -Relative))

    FORMAT_FILES := $(HEADER_FILES) $(SOURCE_FILES)
$(error Windows not supported)

else ifeq ($(OS),$(filter $(OS), macos linux))
    # Assign linker options for shared/std libraries. These paths are passed directly
    # to the linker to search along with the standard system libraries.
    ifeq ($(UNAME_P),i386)
        C_INCLUDES += -I/usr/local/include/ -L/usr/local/lib
	
	else ifeq ($(UNAME_M),aarch64)
        C_INCLUDES += -I/usr/lib -I/usr/include

	else ifeq ($(UNAME_P),arm)
        C_INCLUDES += -I/opt/homebrew/include/ -L/opt/homebrew/lib
    endif

    # Source file query patterns
    t_pattern := $(TP_DIR)/%.$(CEXT)
    c_pattern := $(SRC_DIR)/%.$(CEXT)
    o_pattern := $(BIN_DIR)/obj/%.o
    
    # All Policy Server source files (*.c) within the computed folders
    SOURCE_FILES := $(patsubst \
					$(c_pattern),\
					$(o_pattern),\
					$(shell find $(FOLDERS) -iname *.$(CEXT)))

    SOURCE_FILES := $(patsubst $(t_pattern), $(o_pattern), $(SOURCE_FILES))

    # All Policy Server header files (*h) within the computed folders (should only match
    # header files in the include directory.)
    HEADER_FILES := $(shell find $(FOLDERS) -maxdepth $(MAX_DEPTH) -iname *.$(HEXT))

    # All Policy Server files (*.c and *.h) for clang-format
    FORMAT_FILES := $(shell find $(FOLDERS) -iname *.$(CEXT) -o -iname *.$(HEXT))
endif

# Finalize compile/link options
LDFLAGS+=$(C_WARNINGS)
LDFLAGS+=$(C_DEFINES)
LDFLAGS+=$(C_INCLUDES)
LDFLAGS+=$(EXTRA_C_DEFINES)

#
# Package / Dist Options
#
NAME=pserver

# Package version structure
MAJOR=0
MINOR=0
PATCH=0
EXTRA=rc

# RPM package version value. The other version, VERSION, just prefixes RAW_VERSION with
# the package name. To override version, specify RAW_VERSION in the MAKECMDARGS args.
# ex. make RAW_VERSION=2.2.2 rpm
RAW_VERSION := $(strip $(MAJOR).$(MINOR).$(PATCH))
FMT_VERSION := $(strip $(MAJOR)-$(MINOR)-$(PATCH))
VERSION 	:= $(strip $(NAME)-$(RAW_VERSION))

ifneq ($(EXTRA),)
    VERSION := $(strip $(VERSION)-$(EXTRA))
endif

# RPM Package release number
RELEASE=1

# RPM .tgz and .rpm file names (ex. 1.7.4-2.arm64.rpm)
# RPM_ARCH := $(shell uname -m)
RPM_ARCH := noarch
TGZ_FILE := $(VERSION)-$(RELEASE).$(RPM_ARCH).tar.gz
RPM_FILE := $(VERSION)-$(RELEASE).$(RPM_ARCH).rpm

# Docker image names
IMG_TAG=tmp
DOCKER_IMAGE=$(NAME):$(IMG_TAG)

define log
[ "$<" ] && \
	( printf "Makelog %-30s %-30s %s\n" "$@" "$<" "$(1)" )\
	|| ( printf "Makelog %-10s %s\n" "$@" "$(1)" )
endef

define _v
	$(1) --version 2>/dev/null || echo "$(1) not installed."
endef

args		:= `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`
fmt_file  	:= --style=file:.clang-format --verbose

$(VERBOSE).SILENT:

.PHONY: run version format format-check debug clean help config list \
		build-dist build-rpm pytest-connect pytest-dryrun pytest-qos

BID=$(CWD)/data/.bid

# Below is the "template" for defining our targets to compile object files. Since we 
# have two "sources", the src directory and the unit test directory we can evaluate the 
# result of the below foreach call to generate a target for each directory.
#
# During the secondary expansion of explicit rules, $$@ and $$% evaluate, respectively,
# to the file name of the target and, when the target is an archive member, the target
# member name. The $$< variable evaluates to the first prerequisite in the first rule
# for this target. $$^ and $$+ evaluate to the list of all prerequisites of rules that
# have already appeared for the same target ($$+ with repetitions and $$^ without).
define compiler_target_template
    $(BIN_DIR)/obj/%.o: $(1)/%.$(CEXT) $(HEADER_FILES) | $(BIN_DIR)
		$$(call log,compiling)
		$$(eval obj_dir := $$(shell dirname $$@))
		mkdir -p $$(obj_dir) 2> /dev/null
		$$(CC) $(CFLAGS) -c -o $$@ $$< $$(LDFLAGS) -DRELEASE_VER=\"$(RAW_VERSION)\"
endef

# Build compiler targets
$(eval $(foreach f,$(DIRS),$(eval $(call compiler_target_template,$(f)))))

# Link object files
$(BIN_DIR)/$(NAME): $(SOURCE_FILES)
    # Surface assembled machine code.
	$(eval BINS	:= $(shell find $(BIN_DIR) -name '*.o'))

    # Link files + shared libraries
	$(CC) -o $@ $(BINS) $(LDFLAGS)
	$(call log,built executable $@)

	@if ! test -f $(BID); then echo 0 > $(BID); fi
	@echo $$(($$(cat $(BID)) + 1)) > $(BID)

# Create the bin object directory.
$(BIN_DIR):
	mkdir -p $(BIN_DIR)/obj

# Run built executables with the given args.
run: $(BIN_DIR)/$(NAME)
	$(call log,)
	$(BIN_DIR)/$(NAME) $(args)

# Remove RPM, PyTest artifacts
clean:
	-@$(RM) -rf ${BIN_DIR} ${DIST_DIR} ${CWD}/dist $(CWD)/build *.egg-info
	-@find ./ -type d -name "__pycache__" | xargs rm -rf


########################################################################
##                          	  Dist		                          ##
########################################################################

dist-clean:
	rm -rf $(BUILD_DIR)

dist-build: clean-dist
	mkdir -p {$(BUILD_DIR),$(DIST_DIR),$(DIST_DIR)/files}
	
	cp -r ./{src,include} $(DIST_DIR)/files
	cp ./{Makefile,.clang-format} $(DIST_DIR)/files

	tar czf $(DIST_DIR)/$(TGZ_FILE) -P $(DIST_DIR)/files

dist-rpm: dist-build
	mkdir -p $(BUILD_DIR)/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}
	
	mv $(DIST_DIR)/$(TGZ_FILE) $(BUILD_DIR)/rpmbuild/SOURCES/
	cp -f $(CWD)/$(NAME).spec $(BUILD_DIR)/rpmbuild/specs

	@(LC_ALL=C rpmbuild -v \
		--define "_name $(NAME)"\
		--define "_version $(RAW_VERSION)"\
		--define "_release $(RELEASE)"\
		--define "_topdir $(BUILD_DIR)/rpmbuild"\
		--define "_tarball $(TGZ_FILE)"\
		-bb $(BUILD_DIR)/rpmbuild/SPECS/$(NAME).spec)

docker-image-build:
	docker build --pull --network=host --progress=plain -t $(DOCKER_IMAGE) --target dev .

docker-image-up: docker-image-build
	docker run --network=host $(DOCKER_IMAGE)

docker-image-push:
	$(warning not implemented)


########################################################################
##                          	  Tests		                          ##
########################################################################

# Activate the virtualenv created for the Pytest environment then execute the target
# given which matches an existing path `tests/policy_server/<path>`, then attempt an exit.
define pytest_exec
	(\
		source tests/venv/bin/activate;\
		py.test -v -x tests/policy_server/$(strip $(1));\
		exit;\
	)
endef
# Execute QoS integration tests by file, function or all
# ex. make pytest-qos TP=tp_fls.py TP_FUNC=tp_fls_leg_set
pytest-qos:
	@if [[ -z "$(TP)" ]]; then \
		$(call pytest_exec,integration/qos);\
	fi
	@if [[ -n "$(TP)" && -n "$(TP_FUNC)" ]]; then \
		$(call pytest_exec,integration/qos/$(TP)::TestCase::$(TP_FUNC));\
	fi
	@if [[ -n "$(TP)" ]]; then \
		$(call pytest_exec,integration/qos/$(TP));\
	fi

pytest-dryrun:
	$(call pytest_exec, integration/dryrun/tp_dryrun.py)

pytest-dryrun-opt:
	$(call pytest_exec, integration/dryrun/tp_dryrun.py)

pytest-dryrun-parallel: pytest-dryrun pytest-dryrun-opt

pytest-connect:
	$(call pytest_exec, integration/connect)

regression-creates:
	$(call pytest_exec, regression/reg_create_v4_v6_classifer.py)

regression-modify:
	$(call pytest_exec, regression/reg_modify_v4_v6_classifier.py)

# SINGLE_CPU_EXEC must be toggled if you want these to pass
smoke: pytest-dryrun pytest-connect regression-creates


########################################################################
##                          	  Help		                          ##
########################################################################

# Execute `clang-format` against all source files
format:
	clang-format $(fmt_file) -i $(FORMAT_FILES)

# Execute a `clang-format` check against all source files
format-check:
	clang-format $(fmt_file) --dry-run -Werror $(FORMAT_FILES)

# Make and start an LLDB session for debugging. If nothing happens, within the 
# debugger run "run server". Running 'make && lldb -o run -- pserver' will run the 
# executable immediately but doesn't accept SIGABRTs
debug:
	make && lldb bin/pserver -- "run server"

# Generate Clang's JSON compilation database to record which compile options are
# used to build each individual project file. MUST have compiledb installed.
compilation-database: clean
	@compiledb make

# Run the executable against valgrind for memory maangement analysis
# ex. $ make clean && make (COMPILE_TEST=1)
# 	  $ make valgrind VARG=server|unittest
valgrind:
	@if [[ -z "$(VARG)" ]]; then\
		echo "setting default" && $(eval VARG=unittest):;\
	fi

    ifeq ($(OS),linux)
		valgrind --suppressions=linux_sdl_gl.sup\
				--gen-suppressions=all\
				--leak-check=full\
				--show-leak-kinds=all\
				--track-origins=yes\
				--verbose bin/pserver $(VARG)
    else
		echo "not for osx"
    endif

define pconf
	printf "%-24s %s\n" "$(strip $(1))" "$(strip $(2))"
endef

# List all target names
list:
	@LC_ALL=C $(MAKE) -pRrq -f \
	$(firstword $(MAKEFILE_LIST)) : 2>/dev/null \
	| awk -v RS= -F: '/(^|\n)# Files(\n|$$)/,/(^|\n)# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' \
	| sort | grep -E -v -e '^[^[:alnum:]]' -e '^$@$$'

# Print system config and makevars
config:
	$(call pconf, Flags, 					$(MAKEFLAGS));
	$(call pconf, Version, 					$(VERSION))
	$(call pconf, Processor arch., 			$(UNAME_P))
	$(call pconf, Kernel name, 				$(KERNEL))
	$(call pconf, GCC Version, 				$(GCC_VERSION))
	$(call pconf, Physical CPUs, 			$(NCPU))
	$(call pconf, Computed OS, 				$(OS))
	$(call pconf, RPM build dir.,			$(BUILD_DIR))
	$(call pconf, RPM .tgz filename, 		$(TGZ_FILE))
	$(call pconf, RPM .rpm filename, 		$(RPM_FILE))
	$(call pconf, Working directory, 	  	$(CWD))
	$(call pconf, Source directory (.c),  	$(CWD)/$(SRC))
	$(call pconf, Include directory (.h), 	$(CWD)/$(INC))
	$(call pconf, Compiled binaries (.o), 	$(CWD)/$(BIN))
	$(call pconf)
	$(call pconf, C Flags)
	$(foreach d,$(CFLAGS),echo "  " $d;)
	$(call pconf,Linker Flags)
	@$(foreach d,$(sort $(LDFLAGS)),echo -e "  " $d;)
	$(call pconf)

	$(call pconf, Object files)
	$(foreach d,$(SOURCE_FILES), echo "  " $d;)

	$(call pconf, Header files)
	$(foreach d,$(HEADER_FILES), echo "  " $d;)