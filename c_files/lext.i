%module lext
%{
#include "lext.h"
%}
extern int openFile(char * path);
extern char* getNextLine();
extern void closeFile();
