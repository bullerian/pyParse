#!/bin/sh
LIB_NAME='lext'



swig -python $LIB_NAME.i &&\
gcc -fPIC -c "$LIB_NAME.c" "$LIB_NAME"'_wrap.c' -I/usr/include/python2.7 &&\
ld -shared "$LIB_NAME.o" "$LIB_NAME"'_wrap.o' -o _"$LIB_NAME".so

