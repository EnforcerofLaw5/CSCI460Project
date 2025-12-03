# CSCI460Project - Concurrent Server with Diffie-Hellman & AES
## Group
- Brayden Miller
- Diego Moylan
- Samuel Rollins

## Overview
This is a secure multithreaded TCP server that handles concurrent client connections. Communication is secured with the Diffie-Hellman key exchange and AES.

## Dependencies
- Python 3.x
- cryptography library
```bash
pip install cryptography
```
## Files
- server.py: The multithreaded server. Listens on port 9999 and spawns a thread for each client. Logs messages from clients to a file.
- client.py: A script that launches 1000 concurrent threads connecting to the server
- server_output.txt: Txt file to store decrypted messages

# How to run
Open a terminal and start the server.
```bash
python server.py
```
Open a separate terminal and run the client file
```bash
python client.py
```
Open the newly created text file server_output.txt and see results. 
