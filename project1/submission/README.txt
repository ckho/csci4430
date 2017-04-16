Group No.: 26
Member:
HO Chun Kit (1155048299)
CHEUNG Ka Lok (1155051301)
CHAN Tsz Wing (1155064367)

List of files:
- client (Client Side)
    - client.c (Sample Program of using the Library)
    - mtcp_client.c (uTCP Client Library Source Code)
    - mtcp_client.h (uTCP Client Library Header File)
    - mtcp_common.h (uTCP Library Common Header File)
    - Makefile (Makefile for Compilation)
- server (Server Side)
    - server.c (Sample Program of using the Library)
    - mtcp_server.c (uTCP Server Library Source Code)
    - mtcp_server.h (uTCP Server Library Header File)
    - mtcp_common.h (uTCP Library Common Header File)
    - Makefile (Makefile for Compilation)
- README.txt (This readme file)

Methods of Compilation
- just "make" (use make command) in client and server directory.

Method of Execution
- Execute the Server program first and then the Client program
- For Server program: Usage: ./server [server address] [output filename]
- For Client program: Usage: ./client [server address] [input filename]