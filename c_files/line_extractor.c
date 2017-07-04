#include "line_extractor.h" 

FILE* Input;
char Buffer[BUFFER_LEN];
int IsFileOpened=FALSE;

int openFile(const char * path){
    if (!path && IsFileOpened && !(Input=fopen(path, FILE_MODE))){
        return ERROR_RETVAL;
    }

    IsFileOpened = TRUE;
    return SUCCESS_RETVAL;	
}

char * getNextLine(){
   return fgets(Buffer, BUFFER_LEN, Input);
}

void closeFile(){
    if (IsFileOpened) {
        IsFileOpened=FALSE;
        fclose(Input);
    }
}
