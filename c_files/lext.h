#ifndef LEXT_H
#define LEXT_H

#include <stdio.h>

#define ERROR_RETVAL    (-1)
#define SUCCESS_RETVAL  (0)
#define FILE_MODE       ("r")
#define BUFFER_LEN      (1024)
#define FALSE           (0)
#define TRUE            (!FALSE)


int openFile(char * path);
char* getNextLine();
void closeFile();

#endif
