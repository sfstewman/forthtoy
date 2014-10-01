# forthtoy #

## Introduction ##

`forthtoy` is a small FORTH interpreter, written in about a day, to
better understand FORTH interpreters and compilers. It is far from
complete and follows no known standard.


## Compiling ##

`forthtoy` expects a compiler that supports the C99 standard. The build system
is largely geared for clang, and has only been tested on Mac OS X, but the
source should be portable, and the build system is small enough that it can be
easily adapted.

The recommended way to build `forthtoy` is in a separate build directory:

    # In the forthtoy/ project root directory:
    mkdir Build
    cd Build
    cmake ..
    make

    # The intepreter will be in Build/Build/
    ./Build/forthtoy

The intepreter depends only on the C runtime.


## Quirks and limitations ##

There are many quirks.  The interpreter has no real string support, only
a small amount of memory management, minimal I/O support, and no real
support for floating point operations.  Also, at the moment, there are
no unit tests, or tests of any kind.

There are a few compile-time resource limitations.  The FORTH heap,
where all executable words and data are stored, is statically allocated
and currently set to 16MB.  The string pool, where word names and other
strings are stored, is currently limited to 64KB.  The dictionary is
limited to 64K entries.  The emit buffer is limited to 512 opcodes,
which is an upper bound (opcodes can take a variable amount of space).

The error handling is also currently a mess. Apologies.

