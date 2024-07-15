import sys
import sysv_ipc

key = 1234  
message_queue = sysv_ipc.MessageQueue(key, sysv_ipc.IPC_CREAT)

# Input message from user
message_text = input("Write Data: ").strip()

# Send message to the message queue
message_queue.send(message_text.encode())

print("Data sent successfully.")
