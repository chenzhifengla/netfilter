# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.6

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /cygdrive/c/Users/yingzi/.CLion2016.3/system/cygwin_cmake/bin/cmake.exe

# The command to remove a file.
RM = /cygdrive/c/Users/yingzi/.CLion2016.3/system/cygwin_cmake/bin/cmake.exe -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /cygdrive/d/Users/yingzi/ClionProjects/netfilter

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /cygdrive/d/Users/yingzi/ClionProjects/netfilter/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/netfilter.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/netfilter.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/netfilter.dir/flags.make

CMakeFiles/netfilter.dir/client/client.c.o: CMakeFiles/netfilter.dir/flags.make
CMakeFiles/netfilter.dir/client/client.c.o: ../client/client.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/cygdrive/d/Users/yingzi/ClionProjects/netfilter/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/netfilter.dir/client/client.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/netfilter.dir/client/client.c.o   -c /cygdrive/d/Users/yingzi/ClionProjects/netfilter/client/client.c

CMakeFiles/netfilter.dir/client/client.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/netfilter.dir/client/client.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /cygdrive/d/Users/yingzi/ClionProjects/netfilter/client/client.c > CMakeFiles/netfilter.dir/client/client.c.i

CMakeFiles/netfilter.dir/client/client.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/netfilter.dir/client/client.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /cygdrive/d/Users/yingzi/ClionProjects/netfilter/client/client.c -o CMakeFiles/netfilter.dir/client/client.c.s

CMakeFiles/netfilter.dir/client/client.c.o.requires:

.PHONY : CMakeFiles/netfilter.dir/client/client.c.o.requires

CMakeFiles/netfilter.dir/client/client.c.o.provides: CMakeFiles/netfilter.dir/client/client.c.o.requires
	$(MAKE) -f CMakeFiles/netfilter.dir/build.make CMakeFiles/netfilter.dir/client/client.c.o.provides.build
.PHONY : CMakeFiles/netfilter.dir/client/client.c.o.provides

CMakeFiles/netfilter.dir/client/client.c.o.provides.build: CMakeFiles/netfilter.dir/client/client.c.o


CMakeFiles/netfilter.dir/src/alarmDetection.c.o: CMakeFiles/netfilter.dir/flags.make
CMakeFiles/netfilter.dir/src/alarmDetection.c.o: ../src/alarmDetection.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/cygdrive/d/Users/yingzi/ClionProjects/netfilter/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/netfilter.dir/src/alarmDetection.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/netfilter.dir/src/alarmDetection.c.o   -c /cygdrive/d/Users/yingzi/ClionProjects/netfilter/src/alarmDetection.c

CMakeFiles/netfilter.dir/src/alarmDetection.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/netfilter.dir/src/alarmDetection.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /cygdrive/d/Users/yingzi/ClionProjects/netfilter/src/alarmDetection.c > CMakeFiles/netfilter.dir/src/alarmDetection.c.i

CMakeFiles/netfilter.dir/src/alarmDetection.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/netfilter.dir/src/alarmDetection.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /cygdrive/d/Users/yingzi/ClionProjects/netfilter/src/alarmDetection.c -o CMakeFiles/netfilter.dir/src/alarmDetection.c.s

CMakeFiles/netfilter.dir/src/alarmDetection.c.o.requires:

.PHONY : CMakeFiles/netfilter.dir/src/alarmDetection.c.o.requires

CMakeFiles/netfilter.dir/src/alarmDetection.c.o.provides: CMakeFiles/netfilter.dir/src/alarmDetection.c.o.requires
	$(MAKE) -f CMakeFiles/netfilter.dir/build.make CMakeFiles/netfilter.dir/src/alarmDetection.c.o.provides.build
.PHONY : CMakeFiles/netfilter.dir/src/alarmDetection.c.o.provides

CMakeFiles/netfilter.dir/src/alarmDetection.c.o.provides.build: CMakeFiles/netfilter.dir/src/alarmDetection.c.o


CMakeFiles/netfilter.dir/src/communication.c.o: CMakeFiles/netfilter.dir/flags.make
CMakeFiles/netfilter.dir/src/communication.c.o: ../src/communication.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/cygdrive/d/Users/yingzi/ClionProjects/netfilter/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/netfilter.dir/src/communication.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/netfilter.dir/src/communication.c.o   -c /cygdrive/d/Users/yingzi/ClionProjects/netfilter/src/communication.c

CMakeFiles/netfilter.dir/src/communication.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/netfilter.dir/src/communication.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /cygdrive/d/Users/yingzi/ClionProjects/netfilter/src/communication.c > CMakeFiles/netfilter.dir/src/communication.c.i

CMakeFiles/netfilter.dir/src/communication.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/netfilter.dir/src/communication.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /cygdrive/d/Users/yingzi/ClionProjects/netfilter/src/communication.c -o CMakeFiles/netfilter.dir/src/communication.c.s

CMakeFiles/netfilter.dir/src/communication.c.o.requires:

.PHONY : CMakeFiles/netfilter.dir/src/communication.c.o.requires

CMakeFiles/netfilter.dir/src/communication.c.o.provides: CMakeFiles/netfilter.dir/src/communication.c.o.requires
	$(MAKE) -f CMakeFiles/netfilter.dir/build.make CMakeFiles/netfilter.dir/src/communication.c.o.provides.build
.PHONY : CMakeFiles/netfilter.dir/src/communication.c.o.provides

CMakeFiles/netfilter.dir/src/communication.c.o.provides.build: CMakeFiles/netfilter.dir/src/communication.c.o


CMakeFiles/netfilter.dir/src/dealConf.c.o: CMakeFiles/netfilter.dir/flags.make
CMakeFiles/netfilter.dir/src/dealConf.c.o: ../src/dealConf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/cygdrive/d/Users/yingzi/ClionProjects/netfilter/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/netfilter.dir/src/dealConf.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/netfilter.dir/src/dealConf.c.o   -c /cygdrive/d/Users/yingzi/ClionProjects/netfilter/src/dealConf.c

CMakeFiles/netfilter.dir/src/dealConf.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/netfilter.dir/src/dealConf.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /cygdrive/d/Users/yingzi/ClionProjects/netfilter/src/dealConf.c > CMakeFiles/netfilter.dir/src/dealConf.c.i

CMakeFiles/netfilter.dir/src/dealConf.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/netfilter.dir/src/dealConf.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /cygdrive/d/Users/yingzi/ClionProjects/netfilter/src/dealConf.c -o CMakeFiles/netfilter.dir/src/dealConf.c.s

CMakeFiles/netfilter.dir/src/dealConf.c.o.requires:

.PHONY : CMakeFiles/netfilter.dir/src/dealConf.c.o.requires

CMakeFiles/netfilter.dir/src/dealConf.c.o.provides: CMakeFiles/netfilter.dir/src/dealConf.c.o.requires
	$(MAKE) -f CMakeFiles/netfilter.dir/build.make CMakeFiles/netfilter.dir/src/dealConf.c.o.provides.build
.PHONY : CMakeFiles/netfilter.dir/src/dealConf.c.o.provides

CMakeFiles/netfilter.dir/src/dealConf.c.o.provides.build: CMakeFiles/netfilter.dir/src/dealConf.c.o


CMakeFiles/netfilter.dir/src/netFilter.c.o: CMakeFiles/netfilter.dir/flags.make
CMakeFiles/netfilter.dir/src/netFilter.c.o: ../src/netFilter.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/cygdrive/d/Users/yingzi/ClionProjects/netfilter/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/netfilter.dir/src/netFilter.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/netfilter.dir/src/netFilter.c.o   -c /cygdrive/d/Users/yingzi/ClionProjects/netfilter/src/netFilter.c

CMakeFiles/netfilter.dir/src/netFilter.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/netfilter.dir/src/netFilter.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /cygdrive/d/Users/yingzi/ClionProjects/netfilter/src/netFilter.c > CMakeFiles/netfilter.dir/src/netFilter.c.i

CMakeFiles/netfilter.dir/src/netFilter.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/netfilter.dir/src/netFilter.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /cygdrive/d/Users/yingzi/ClionProjects/netfilter/src/netFilter.c -o CMakeFiles/netfilter.dir/src/netFilter.c.s

CMakeFiles/netfilter.dir/src/netFilter.c.o.requires:

.PHONY : CMakeFiles/netfilter.dir/src/netFilter.c.o.requires

CMakeFiles/netfilter.dir/src/netFilter.c.o.provides: CMakeFiles/netfilter.dir/src/netFilter.c.o.requires
	$(MAKE) -f CMakeFiles/netfilter.dir/build.make CMakeFiles/netfilter.dir/src/netFilter.c.o.provides.build
.PHONY : CMakeFiles/netfilter.dir/src/netFilter.c.o.provides

CMakeFiles/netfilter.dir/src/netFilter.c.o.provides.build: CMakeFiles/netfilter.dir/src/netFilter.c.o


CMakeFiles/netfilter.dir/threadTest/kthread.c.o: CMakeFiles/netfilter.dir/flags.make
CMakeFiles/netfilter.dir/threadTest/kthread.c.o: ../threadTest/kthread.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/cygdrive/d/Users/yingzi/ClionProjects/netfilter/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/netfilter.dir/threadTest/kthread.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/netfilter.dir/threadTest/kthread.c.o   -c /cygdrive/d/Users/yingzi/ClionProjects/netfilter/threadTest/kthread.c

CMakeFiles/netfilter.dir/threadTest/kthread.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/netfilter.dir/threadTest/kthread.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /cygdrive/d/Users/yingzi/ClionProjects/netfilter/threadTest/kthread.c > CMakeFiles/netfilter.dir/threadTest/kthread.c.i

CMakeFiles/netfilter.dir/threadTest/kthread.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/netfilter.dir/threadTest/kthread.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /cygdrive/d/Users/yingzi/ClionProjects/netfilter/threadTest/kthread.c -o CMakeFiles/netfilter.dir/threadTest/kthread.c.s

CMakeFiles/netfilter.dir/threadTest/kthread.c.o.requires:

.PHONY : CMakeFiles/netfilter.dir/threadTest/kthread.c.o.requires

CMakeFiles/netfilter.dir/threadTest/kthread.c.o.provides: CMakeFiles/netfilter.dir/threadTest/kthread.c.o.requires
	$(MAKE) -f CMakeFiles/netfilter.dir/build.make CMakeFiles/netfilter.dir/threadTest/kthread.c.o.provides.build
.PHONY : CMakeFiles/netfilter.dir/threadTest/kthread.c.o.provides

CMakeFiles/netfilter.dir/threadTest/kthread.c.o.provides.build: CMakeFiles/netfilter.dir/threadTest/kthread.c.o


# Object files for target netfilter
netfilter_OBJECTS = \
"CMakeFiles/netfilter.dir/client/client.c.o" \
"CMakeFiles/netfilter.dir/src/alarmDetection.c.o" \
"CMakeFiles/netfilter.dir/src/communication.c.o" \
"CMakeFiles/netfilter.dir/src/dealConf.c.o" \
"CMakeFiles/netfilter.dir/src/netFilter.c.o" \
"CMakeFiles/netfilter.dir/threadTest/kthread.c.o"

# External object files for target netfilter
netfilter_EXTERNAL_OBJECTS =

netfilter.exe: CMakeFiles/netfilter.dir/client/client.c.o
netfilter.exe: CMakeFiles/netfilter.dir/src/alarmDetection.c.o
netfilter.exe: CMakeFiles/netfilter.dir/src/communication.c.o
netfilter.exe: CMakeFiles/netfilter.dir/src/dealConf.c.o
netfilter.exe: CMakeFiles/netfilter.dir/src/netFilter.c.o
netfilter.exe: CMakeFiles/netfilter.dir/threadTest/kthread.c.o
netfilter.exe: CMakeFiles/netfilter.dir/build.make
netfilter.exe: CMakeFiles/netfilter.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/cygdrive/d/Users/yingzi/ClionProjects/netfilter/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Linking C executable netfilter.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/netfilter.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/netfilter.dir/build: netfilter.exe

.PHONY : CMakeFiles/netfilter.dir/build

CMakeFiles/netfilter.dir/requires: CMakeFiles/netfilter.dir/client/client.c.o.requires
CMakeFiles/netfilter.dir/requires: CMakeFiles/netfilter.dir/src/alarmDetection.c.o.requires
CMakeFiles/netfilter.dir/requires: CMakeFiles/netfilter.dir/src/communication.c.o.requires
CMakeFiles/netfilter.dir/requires: CMakeFiles/netfilter.dir/src/dealConf.c.o.requires
CMakeFiles/netfilter.dir/requires: CMakeFiles/netfilter.dir/src/netFilter.c.o.requires
CMakeFiles/netfilter.dir/requires: CMakeFiles/netfilter.dir/threadTest/kthread.c.o.requires

.PHONY : CMakeFiles/netfilter.dir/requires

CMakeFiles/netfilter.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/netfilter.dir/cmake_clean.cmake
.PHONY : CMakeFiles/netfilter.dir/clean

CMakeFiles/netfilter.dir/depend:
	cd /cygdrive/d/Users/yingzi/ClionProjects/netfilter/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /cygdrive/d/Users/yingzi/ClionProjects/netfilter /cygdrive/d/Users/yingzi/ClionProjects/netfilter /cygdrive/d/Users/yingzi/ClionProjects/netfilter/cmake-build-debug /cygdrive/d/Users/yingzi/ClionProjects/netfilter/cmake-build-debug /cygdrive/d/Users/yingzi/ClionProjects/netfilter/cmake-build-debug/CMakeFiles/netfilter.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/netfilter.dir/depend

