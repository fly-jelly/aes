# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.12

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

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = "D:\Program Files\JetBrains\CLion 2018.2.1\bin\cmake\win\bin\cmake.exe"

# The command to remove a file.
RM = "D:\Program Files\JetBrains\CLion 2018.2.1\bin\cmake\win\bin\cmake.exe" -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = E:\CLionProjects\TestAES

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = E:\CLionProjects\TestAES\cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/TestAES.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/TestAES.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/TestAES.dir/flags.make

CMakeFiles/TestAES.dir/main.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/main.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/main.c.obj: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/TestAES.dir/main.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\main.c.obj   -c E:\CLionProjects\TestAES\main.c

CMakeFiles/TestAES.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/main.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\main.c > CMakeFiles\TestAES.dir\main.c.i

CMakeFiles/TestAES.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/main.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\main.c -o CMakeFiles\TestAES.dir\main.c.s

CMakeFiles/TestAES.dir/aes/aes_core.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/aes_core.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/aes_core.c.obj: ../aes/aes_core.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/TestAES.dir/aes/aes_core.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\aes_core.c.obj   -c E:\CLionProjects\TestAES\aes\aes_core.c

CMakeFiles/TestAES.dir/aes/aes_core.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/aes_core.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\aes_core.c > CMakeFiles\TestAES.dir\aes\aes_core.c.i

CMakeFiles/TestAES.dir/aes/aes_core.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/aes_core.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\aes_core.c -o CMakeFiles\TestAES.dir\aes\aes_core.c.s

CMakeFiles/TestAES.dir/aes/aes_cbc.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/aes_cbc.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/aes_cbc.c.obj: ../aes/aes_cbc.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/TestAES.dir/aes/aes_cbc.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\aes_cbc.c.obj   -c E:\CLionProjects\TestAES\aes\aes_cbc.c

CMakeFiles/TestAES.dir/aes/aes_cbc.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/aes_cbc.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\aes_cbc.c > CMakeFiles\TestAES.dir\aes\aes_cbc.c.i

CMakeFiles/TestAES.dir/aes/aes_cbc.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/aes_cbc.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\aes_cbc.c -o CMakeFiles\TestAES.dir\aes\aes_cbc.c.s

CMakeFiles/TestAES.dir/aes/aes_cfb.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/aes_cfb.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/aes_cfb.c.obj: ../aes/aes_cfb.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/TestAES.dir/aes/aes_cfb.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\aes_cfb.c.obj   -c E:\CLionProjects\TestAES\aes\aes_cfb.c

CMakeFiles/TestAES.dir/aes/aes_cfb.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/aes_cfb.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\aes_cfb.c > CMakeFiles\TestAES.dir\aes\aes_cfb.c.i

CMakeFiles/TestAES.dir/aes/aes_cfb.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/aes_cfb.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\aes_cfb.c -o CMakeFiles\TestAES.dir\aes\aes_cfb.c.s

CMakeFiles/TestAES.dir/aes/aes_ecb.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/aes_ecb.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/aes_ecb.c.obj: ../aes/aes_ecb.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/TestAES.dir/aes/aes_ecb.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\aes_ecb.c.obj   -c E:\CLionProjects\TestAES\aes\aes_ecb.c

CMakeFiles/TestAES.dir/aes/aes_ecb.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/aes_ecb.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\aes_ecb.c > CMakeFiles\TestAES.dir\aes\aes_ecb.c.i

CMakeFiles/TestAES.dir/aes/aes_ecb.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/aes_ecb.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\aes_ecb.c -o CMakeFiles\TestAES.dir\aes\aes_ecb.c.s

CMakeFiles/TestAES.dir/aes/cbc128.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/cbc128.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/cbc128.c.obj: ../aes/cbc128.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/TestAES.dir/aes/cbc128.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\cbc128.c.obj   -c E:\CLionProjects\TestAES\aes\cbc128.c

CMakeFiles/TestAES.dir/aes/cbc128.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/cbc128.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\cbc128.c > CMakeFiles\TestAES.dir\aes\cbc128.c.i

CMakeFiles/TestAES.dir/aes/cbc128.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/cbc128.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\cbc128.c -o CMakeFiles\TestAES.dir\aes\cbc128.c.s

CMakeFiles/TestAES.dir/aes/cfb128.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/cfb128.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/cfb128.c.obj: ../aes/cfb128.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/TestAES.dir/aes/cfb128.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\cfb128.c.obj   -c E:\CLionProjects\TestAES\aes\cfb128.c

CMakeFiles/TestAES.dir/aes/cfb128.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/cfb128.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\cfb128.c > CMakeFiles\TestAES.dir\aes\cfb128.c.i

CMakeFiles/TestAES.dir/aes/cfb128.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/cfb128.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\cfb128.c -o CMakeFiles\TestAES.dir\aes\cfb128.c.s

CMakeFiles/TestAES.dir/aes/ctr128.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/ctr128.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/ctr128.c.obj: ../aes/ctr128.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object CMakeFiles/TestAES.dir/aes/ctr128.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\ctr128.c.obj   -c E:\CLionProjects\TestAES\aes\ctr128.c

CMakeFiles/TestAES.dir/aes/ctr128.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/ctr128.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\ctr128.c > CMakeFiles\TestAES.dir\aes\ctr128.c.i

CMakeFiles/TestAES.dir/aes/ctr128.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/ctr128.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\ctr128.c -o CMakeFiles\TestAES.dir\aes\ctr128.c.s

CMakeFiles/TestAES.dir/aes/ofb128.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/ofb128.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/ofb128.c.obj: ../aes/ofb128.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building C object CMakeFiles/TestAES.dir/aes/ofb128.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\ofb128.c.obj   -c E:\CLionProjects\TestAES\aes\ofb128.c

CMakeFiles/TestAES.dir/aes/ofb128.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/ofb128.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\ofb128.c > CMakeFiles\TestAES.dir\aes\ofb128.c.i

CMakeFiles/TestAES.dir/aes/ofb128.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/ofb128.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\ofb128.c -o CMakeFiles\TestAES.dir\aes\ofb128.c.s

CMakeFiles/TestAES.dir/aes/cts128.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/cts128.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/cts128.c.obj: ../aes/cts128.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building C object CMakeFiles/TestAES.dir/aes/cts128.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\cts128.c.obj   -c E:\CLionProjects\TestAES\aes\cts128.c

CMakeFiles/TestAES.dir/aes/cts128.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/cts128.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\cts128.c > CMakeFiles\TestAES.dir\aes\cts128.c.i

CMakeFiles/TestAES.dir/aes/cts128.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/cts128.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\cts128.c -o CMakeFiles\TestAES.dir\aes\cts128.c.s

CMakeFiles/TestAES.dir/aes/gcm128.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/gcm128.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/gcm128.c.obj: ../aes/gcm128.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Building C object CMakeFiles/TestAES.dir/aes/gcm128.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\gcm128.c.obj   -c E:\CLionProjects\TestAES\aes\gcm128.c

CMakeFiles/TestAES.dir/aes/gcm128.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/gcm128.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\gcm128.c > CMakeFiles\TestAES.dir\aes\gcm128.c.i

CMakeFiles/TestAES.dir/aes/gcm128.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/gcm128.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\gcm128.c -o CMakeFiles\TestAES.dir\aes\gcm128.c.s

CMakeFiles/TestAES.dir/aes/ccm128.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/ccm128.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/ccm128.c.obj: ../aes/ccm128.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_12) "Building C object CMakeFiles/TestAES.dir/aes/ccm128.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\ccm128.c.obj   -c E:\CLionProjects\TestAES\aes\ccm128.c

CMakeFiles/TestAES.dir/aes/ccm128.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/ccm128.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\ccm128.c > CMakeFiles\TestAES.dir\aes\ccm128.c.i

CMakeFiles/TestAES.dir/aes/ccm128.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/ccm128.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\ccm128.c -o CMakeFiles\TestAES.dir\aes\ccm128.c.s

CMakeFiles/TestAES.dir/aes/xts128.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/xts128.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/xts128.c.obj: ../aes/xts128.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_13) "Building C object CMakeFiles/TestAES.dir/aes/xts128.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\xts128.c.obj   -c E:\CLionProjects\TestAES\aes\xts128.c

CMakeFiles/TestAES.dir/aes/xts128.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/xts128.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\xts128.c > CMakeFiles\TestAES.dir\aes\xts128.c.i

CMakeFiles/TestAES.dir/aes/xts128.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/xts128.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\xts128.c -o CMakeFiles\TestAES.dir\aes\xts128.c.s

CMakeFiles/TestAES.dir/aes/aes_misc.c.obj: CMakeFiles/TestAES.dir/flags.make
CMakeFiles/TestAES.dir/aes/aes_misc.c.obj: CMakeFiles/TestAES.dir/includes_C.rsp
CMakeFiles/TestAES.dir/aes/aes_misc.c.obj: ../aes/aes_misc.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_14) "Building C object CMakeFiles/TestAES.dir/aes/aes_misc.c.obj"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\TestAES.dir\aes\aes_misc.c.obj   -c E:\CLionProjects\TestAES\aes\aes_misc.c

CMakeFiles/TestAES.dir/aes/aes_misc.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TestAES.dir/aes/aes_misc.c.i"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E E:\CLionProjects\TestAES\aes\aes_misc.c > CMakeFiles\TestAES.dir\aes\aes_misc.c.i

CMakeFiles/TestAES.dir/aes/aes_misc.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TestAES.dir/aes/aes_misc.c.s"
	D:\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\x86_64-w64-mingw32-gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S E:\CLionProjects\TestAES\aes\aes_misc.c -o CMakeFiles\TestAES.dir\aes\aes_misc.c.s

# Object files for target TestAES
TestAES_OBJECTS = \
"CMakeFiles/TestAES.dir/main.c.obj" \
"CMakeFiles/TestAES.dir/aes/aes_core.c.obj" \
"CMakeFiles/TestAES.dir/aes/aes_cbc.c.obj" \
"CMakeFiles/TestAES.dir/aes/aes_cfb.c.obj" \
"CMakeFiles/TestAES.dir/aes/aes_ecb.c.obj" \
"CMakeFiles/TestAES.dir/aes/cbc128.c.obj" \
"CMakeFiles/TestAES.dir/aes/cfb128.c.obj" \
"CMakeFiles/TestAES.dir/aes/ctr128.c.obj" \
"CMakeFiles/TestAES.dir/aes/ofb128.c.obj" \
"CMakeFiles/TestAES.dir/aes/cts128.c.obj" \
"CMakeFiles/TestAES.dir/aes/gcm128.c.obj" \
"CMakeFiles/TestAES.dir/aes/ccm128.c.obj" \
"CMakeFiles/TestAES.dir/aes/xts128.c.obj" \
"CMakeFiles/TestAES.dir/aes/aes_misc.c.obj"

# External object files for target TestAES
TestAES_EXTERNAL_OBJECTS =

TestAES.exe: CMakeFiles/TestAES.dir/main.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/aes_core.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/aes_cbc.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/aes_cfb.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/aes_ecb.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/cbc128.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/cfb128.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/ctr128.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/ofb128.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/cts128.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/gcm128.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/ccm128.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/xts128.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/aes/aes_misc.c.obj
TestAES.exe: CMakeFiles/TestAES.dir/build.make
TestAES.exe: CMakeFiles/TestAES.dir/linklibs.rsp
TestAES.exe: CMakeFiles/TestAES.dir/objects1.rsp
TestAES.exe: CMakeFiles/TestAES.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_15) "Linking C executable TestAES.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\TestAES.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/TestAES.dir/build: TestAES.exe

.PHONY : CMakeFiles/TestAES.dir/build

CMakeFiles/TestAES.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\TestAES.dir\cmake_clean.cmake
.PHONY : CMakeFiles/TestAES.dir/clean

CMakeFiles/TestAES.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" E:\CLionProjects\TestAES E:\CLionProjects\TestAES E:\CLionProjects\TestAES\cmake-build-debug E:\CLionProjects\TestAES\cmake-build-debug E:\CLionProjects\TestAES\cmake-build-debug\CMakeFiles\TestAES.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/TestAES.dir/depend

