 # Secure Multiprocess TCP Application Server

## Overview

The Secure Multiprocess TCP Application Server is a network programming project developed to demonstrate secure client-server communication using TCP sockets in C and Python. The project focuses on implementing a secure and scalable multiprocess server architecture with authentication, session handling, and audit logging features.

The server was designed and developed in a Linux environment using socket programming and multiprocessing concepts.

---

## Features

* Multiprocess TCP server implementation using `fork()`
* Secure client-server communication
* User authentication system
* Session token generation and validation
* Custom communication protocol design
* Audit logging and monitoring
* Python client application for testing
* Linux-based socket programming

---

## Technologies Used

* C Programming
* Python
* TCP Sockets
* Linux
* Socket Programming
* Multiprocessing
* Git & GitHub

---

## System Architecture

```text
Client (Python)
       │
       ▼
TCP Socket Connection
       │
       ▼
Multiprocess TCP Server (C)
       │
 ┌───────────────┐
 │ Authentication│
 │ Session Mgmt  │
 │ Audit Logging │
 └───────────────┘
```

---

## Key Concepts Implemented

* TCP/IP Networking
* Client-Server Architecture
* Concurrent Processing
* Process Management using `fork()`
* Secure Authentication
* Session Management
* Audit Logging

---

## Project Structure

```text
Secure-Multiprocess-TCP-Application-Server/
│
├── server/
├── client/
├── logs/
├── docs/
└── README.md
```

---

## Learning Outcomes

Through this project, I gained experience in:

* Developing TCP socket-based applications
* Implementing secure authentication mechanisms
* Working with Linux networking environments
* Managing concurrent client connections
* Designing secure communication protocols
* Building and testing client-server systems

---

## Future Improvements

* Add encryption using SSL/TLS
* Implement database integration
* Add GUI-based client application
* Improve scalability and performance
* Add advanced intrusion detection features

---

## Author

**Gayathri Silva**

Cyber Security Undergraduate

* GitHub: [https://github.com/gayathri-silva](https://github.com/gayathri-silva)
* LinkedIn: [https://www.linkedin.com/in/gayathri-silva-0a7b04372](https://www.linkedin.com/in/gayathri-silva-0a7b04372)

---

## Repository Link

[https://github.com/gayathri-silva/Secure-Multiprocessor-TCP-Application-Server](https://github.com/gayathri-silva/Secure-Multiprocessor-TCP-Application-Server)
