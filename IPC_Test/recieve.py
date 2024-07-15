import sysv_ipc

key = 1234  # Replace with your desired key (same as C code)
message_queue = sysv_ipc.MessageQueue(key)

# Receive message from the message queue
message, _ = message_queue.receive()

print(f"Data received is: {message.decode()}")

# Optionally, remove the message queue
message_queue.remove()
