#include "lext.h" 

FILE* Input;
char Buffer[BUFFER_LEN];
int IsFileOpened=FALSE;

int openFile(char * path){
    if (!path || IsFileOpened){
        return -2;
    }
    else if (!(Input=fopen(path, FILE_MODE))){
        return -3;
    }

    IsFileOpened = TRUE;

    return SUCCESS_RETVAL;
}

char * getNextLine(){
    fgets(Buffer, BUFFER_LEN, Input);
}

void closeFile(){
    if (IsFileOpened) {
        IsFileOpened=FALSE;
        fclose(Input);
    }
}
