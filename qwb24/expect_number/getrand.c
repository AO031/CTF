#include<stdio.h>
#include<stdlib.h>

int main(){
    int rand_list[300];
    srand(0);
    printf("[");
    for (int i=0;i < 300;i++){
        rand_list[i] = rand()%4;
        printf("%d,",rand_list[i]);
    }
    printf("]\n");
    return 0;
}