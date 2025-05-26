UP25 Lab05
==========
Date: 2025-05-05

[TOC]

# Let's Race Together

This lab aims to investigate possible race or reentrant errors from multithreaded programs. Please read the codes and solve the challenges available on the three challenge servers.

## Challenge #1

The challenge server #1 can be accessed using the command:
```
nc up.zoolab.org 10931
```

Once you have connected to the challenge server, please dump the content of the `flag` file on the server.

We provide the source code of the challenge server for your reference [[view](https://up.zoolab.org/code.html?file=unixprog/lab05/unixfortune.c)].

## Challenge #2

The challenge server #2 can be accessed using the command:
```
nc up.zoolab.org 10932
```

Once you have connected to the challenge server, please ask the challenge server to retrieve the secret from localhost:10000.

We provide the source code of the challenge server for your reference [[view](https://up.zoolab.org/code.html?file=unixprog/lab05/flagsrv.cpp)].

## Challenge  #3

The challenge server #3 can be accessed using the command:
```
nc up.zoolab.org 10933
```

The challenge server is a simple web server. Please read the flag from http://up.zoolab.org:10933/secret/FLAG.txt

We provide the source code of the challenge server for your reference [[view](https://up.zoolab.org/code.html?file=unixprog/lab05/insecureweb.c)].

## Lab Grading

1. [10 pts] <font color="#1936C9">You can solve challenge #1.</font>

1. [15 pts] You can solve challenge #1 using a `pwntools` script (run it with a single command).

1. [10 pts] <font color="#1936C9">You can solve challenge #2.</font>

1. [15 pts] You can solve challenge #2 using a `pwntools` script (run it with a single command).

1. [20 pts] <font color="#1936C9">You can solve challenge #3.</font>

1. [30 pts] You can solve challenge #3 using a `pwntools` script (run it with a single command).


## Lab Submission
:::warning
You have to upload all your solution scripts and codes to e3. Specifically, grading item #2, #4, and #6.
:::

- Filename: `{studentID}_lab05.zip`
- Format:

```
+---{studentID}_lab05
|   solve_1.py
|   solve_2.py
|   solve_3.py
|   other files...
```
You need to put your files in a directory first, then compress the directory.
