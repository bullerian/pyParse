#!/bin/sh
LIB_NAME='lext'

gcc -shared -o_$LIB_NAME.so -Wall -fPIC line_extractor.c &&\
swig -python -o "../$LIB_NAME.py" $LIB_NAME.i
