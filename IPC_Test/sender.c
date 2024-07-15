#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/ipc.h>
#include<sys/msg.h>



struct msg_buffer {
    long msg_type;
    char msg_text[100];

}message;



int main()
{

key_t key;
int msgid;

key = ftok("progfile",65); //ftok to generate unique key


//msgget creates a messages queue and returns identifier
msgid = msgget(key,0666  | IPC_CREAT);
message.msg_type = 1;

printf("Write Data : ");
fgets(message.msg_text,sizeof(message.msg_text),stdin);


//msgsnd to send message
msgsnd(msgid,&message,sizeof(message),0);

printf("Data send is : %s  \n", message.msg_text);

return 0;

}