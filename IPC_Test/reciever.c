#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/ipc.h>
#include<sys/msg.h>


struct  msg_buffer 
{
    long msg_type;
    char msg_txt [100];

}message;

int main ()
{

    key_t key;
    int msgid;


    //ftok to generate unique key 
    key = ftok("progfile",65);

    //msget creates a message queue and returns identifier 

    msgid = msgget(key,0666 | IPC_CREAT);  


    //msgrcv to receive messages 

    msgrcv(msgid,&message,sizeof(message),1,0);

    //Display the message
    printf("Data received is : %s \n",message.msg_txt);


    //to destroy the messsage queue 

    msgctl(msgid, IPC_RMID, NULL);



    return 0;
}