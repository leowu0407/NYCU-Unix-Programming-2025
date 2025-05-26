UP25 Lab01
==========

[TOC]

# Build course environment

## Objective

This lab aims to build a runtime environment required by this course. You have to be familiar with `docker`, `python`, and `pwntools` in this lab. Please follow the instructions to complete this lab. Once you have completed any grading item, please demo it to the TAs.

:::danger
You ***MUST*** upload your scripts to E3 before you demo.
:::

:::danger
We do not discourage you to use LLM models, but if you use any LLM/AI approaches to solve the challenges, please also submit your full solving process to the E3 system.
:::

## Instructions

1. Prepare your own docker environment. You can install [Docker Desktop](https://www.docker.com/products/docker-desktop/) on your laptop or simply use the `docker.io` package in most Linux distributions.

1. Clone the course runtime repo from [github](https://github.com/chunying/up-runtime) and follow the instructions to set up your runtime environment. Ensure that you have correctly set up your username and created the home directory for the user.

   :::warning
   You need to run the scripts in a UNIX-like host runtime, e.g., WSL in Windows and macOS.
   :::

1. Once `pwntools` is installed successfully, please solve the ***simple HTTP challenge*** by implementing a `pwntools` script to retrieve an IP address from the URL: [http://ipinfo.io/ip](http://ipinfo.io/ip). You may try to play with the URL using the command:

   ```sh
   curl http://ipinfo.io/ip
   ```

   Your script output should be equivalent to the above command. To see the details about how `curl` interacts with the remote server, you may pass an optional parameter `-v` to `curl`.

1. Please also solve the challenge running on our challenge server. You can access it using the command:
   ```
   nc up.zoolab.org 10155
   ```
   Note that there is a `pow` challenge before you can actually solve it. Please read the [pow (proof-of-work)](https://md.zoolab.org/s/EHSmQ0szV) document first.
   
   The challenge asks you to play an interactive game. Read the source codes and find out how to solve the game. The mocked server implementation is available here (`guess.dist.py` [view](https://up.zoolab.org/code.html?file=unixprog/lab01/guess.dist.py)|[download](https://up.zoolab.org/unixprog/lab01/guess.dist.py)) for your reference. We also provide an empty sample solver script (`solver_simple.py` [view](https://up.zoolab.org/code.html?file=unixprog/lab01/solver_sample.py)|[download](https://up.zoolab.org/unixprog/lab01/solver_sample.py)) for you to get started more easily.

## Grading

1. [5pts] Prepare your own runtime environment (Linux OS running on dockers, VMs, or physical machines). Please ensure that you use your own username, and files can be placed into your runtime.

1. [5pts] Install pwntools and ensure that the following script works in the Python3 interpreter.

   ```python
   from pwn import *
   r = process('read Z; echo You got $Z', shell=True)
   r.sendline(b'AAA')
   r.interactive()
   ```

1. [20pts] Solve the ***simple HTTP challenge*** described above.
   <i style="color: red">You cannot call an external program, e.g., wget or curl, nor use a library call to solve this challenge.</i>

1. [20pts] Your solver can interact with our challenge server and decode/display the messages received from the server.

1. [50pts] Your solver can interact with our challenge server and solve the challenge without human intervention.

## Hints

1. The game solver `solver_simple.py` requires the PoW solver. You can simply place the PoW solver `solpow.py` file in the same directory as the game solver.

1. The mocked challenge server does exactly the same thing as the remote server. You can solve it locally and then play with the remote server to avoid the long waiting time of solving PoW.
