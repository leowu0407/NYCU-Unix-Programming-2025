UP25 Lab02
==========
Date: 2024-03-10

[TOC]

# Cryptomod: Encrypt and Decrypt Data Using a Kernel Module

In this lab, you will implement a kernel module that performs encryption and decryption operations using the Linux Kernel API. The kernel module should be configured using the `ioctl` interface and provide information through the `proc` file system.

## Preparation

Please read our [Lab02 Pre-Lab Announcement](https://md.zoolab.org/yHdtmVBwT02hDTuaUVwzZQ) for details.
You should have at least the `dist-6.6.17.tbz` and `hellomod-6.6.17.tbz` files.
You will also need the QEMU emulator to run the files.
See the [Lab Hints](#Lab-Hints) section for more information.

## AES Algorithm and Kernel Encryption API
- In Lab 02, you only need to use the AES algorithm with different key lengths. Since AES has a block size of ***16 bytes***, padding is ***required***.
- We provide a sample implementation of kernel `ECB` mode, rewritten from the kernel documentation: `sample_code.c`([view](https://up.zoolab.org/code.html?file=unixprog/lab02/sample_code.c) | [download](https://up.zoolab.org/unixprog/lab02/sample_code.c))

## Specification

The specification of the kernel module is summarized as follows.

1. The module must ***automatically*** create a device named `cryptodev` in the `/dev` filesystem. Each opened file descriptor should maintain its own state. For example, a process can open the device multiple times, with each file descriptor having its own configuration. The device's functionality is controlled through the `ioctl` interface.
    - The kernel module performs AES encryption and **only** supports the `ECB` mode, allowing each block to be processed **independently**.
    - The encryption and decryption operations can be configured using the `ioctl` interface:
        - **Encryption mode:** The user program writes plaintext to the device as input and reads the corresponding ciphertext as output.
        - **Decryption mode:** The user program writes ciphertext to the device as input and reads the corresponding plaintext as output.

1. The `write` Interface
    - The `write` interface allows the device to receive user input and process it based on [`CM_IOC_SETUP`](#CM_IOC_SETUP) (encryption or decryption).
    - Users may write data repeatedly, and each write operation may not necessarily be a multiple of the block size.
    - The return value should indicate the number of bytes processed:
      - If only part of the data can be handled by your kernel module, process that portion and return the number of bytes processed.
          - e.g., if a user program writes 16 bytes but your kernel module can only process 10 bytes, you should return 10.
      - If none of the bytes can be processed by your kernel module at the moment, return `-EAGAIN`.
    - After a [`CM_IOC_FINALIZE`](#CM_IOC_FINALIZE) call, the user program must not write to the device.
    - The operation may return the following error codes:
      - `-EINVAL`: The device is not properly set up, or [`CM_IOC_FINALIZE`](#CM_IOC_FINALIZE) has already been called.
      - `-EAGAIN`: The module cannot process data immediately.
      - `-EBUSY`: Copying data between user space and kernel space has failed.

1. The `read` Interface
    - The `read` operation allows users to retrieve data processed by the module.
    - Similar to the `write` interface, the `read` interface returns the number of bytes provided by the device:
      - If no data is available and [`CM_IOC_FINALIZE`](#CM_IOC_FINALIZE) has not been called, return `-EAGAIN`.
      - If no data is available and [`CM_IOC_FINALIZE`](#CM_IOC_FINALIZE) has been called, return `0`.

    - The operation may return the following error codes:
      - `-EINVAL`: The device is not properly set up.
      - `-EAGAIN`: The module cannot process data immediately.
      - `-EBUSY`: Copying data between user space and kernel space has failed.


1. The I/O behavior depends on the `ioctl` configuration, with two available modes:
    - **I/O Mode `BASIC`**:
        - All output data is buffered within the kernel module and cannot be accessed through `read` until [`CM_IOC_FINALIZE`](#CM_IOC_FINALIZE) is called.
        - Encryption or decryption is performed only after [`CM_IOC_FINALIZE`](#CM_IOC_FINALIZE) is called.
        - The maximum amount of data processed at a time is `1024` bytes.
    - **I/O Mode `ADV`**:
        - Data is encrypted or decrypted ***incrementally***. A full block of processed data becomes available for `read` only after enough input has been received to complete a block.
        - In **encryption mode**, **padding** is applied only when [`CM_IOC_FINALIZE`](#CM_IOC_FINALIZE) is called, which may result in an extra output block.
        - In **decryption mode**, one block is always withheld until [`CM_IOC_FINALIZE`](#CM_IOC_FINALIZE) is called, as it may contain padding that needs to be processed correctly.
        - See the [`CM_IOC_FINALIZE`](#CM_IOC_FINALIZE) section for more details on padding.

    :::warning
    It is ***recommended*** to implement mode `BASIC` first before implementing mode `ADV`.
    :::
    :::info
    **2025/03/15 Update**
    All read/write operations are treated as the entire file, so padding is only processed at the finalization stage. 
    This is also the reason why decryption requires keeping one block in I/O mode `ADV`.
    :::

1. The `ioctl` interface. The `ioctl` command supports the following operations. Command definitions can be found in the `cryptomod.h` ([view](https://up.zoolab.org/code.html?file=unixprog/lab02/cryptomod.h) | [download](https://up.zoolab.org/unixprog/lab02/cryptomod.h)) header file.
    <a id="CM_IOC_SETUP"></a>
    - `CM_IOC_SETUP`: Configures the encryption/decryption settings. The configuration is provided as a pointer to a `CryptoSetup` structure.
        - Note that the AES standard supports only specific key lengths.
            | AES Variant        | AES-128 | AES-192 | AES-256 |
            | ------------------ | ------- | ------- | ------- |
            | Key Length (bytes) | 16      | 24      | 32      |
        - If the device is reconfigured, all buffers must be cleared, and the new configuration must be applied.
        
        Possible error codes:
        - `-EINVAL`: Returned if any argument is invalid or a null pointer is passed.
        - `-EBUSY`: Returned if copying data between user space and kernel space fails.
    <a id="CM_IOC_FINALIZE"></a>
    - `CM_IOC_FINALIZE`: Applies padding using the `PKCS#7` padding method. In `ENC` mode, the kernel module should add padding to the plaintext before encryption. In `DEC` mode, the kernel module should validate and remove the padding during decryption.
        
        Padding method described below:
        - Each padding byte has a value equal to the total number of padding bytes added. For example, if 4 padding bytes are needed, each byte will have the value `0x04`:
            ```
            Plaintext:     | DD DD DD DD DD DD DD DD DD DD DD DD xx xx xx xx |
            After padding: | DD DD DD DD DD DD DD DD DD DD DD DD 04 04 04 04 |
            ```
        - If the data size is already a multiple of the block size, an entire block of bytes with the value `0x10` is appended.
        
        Possible error codes:
        - `-EINVAL`: Returned if the device is not set up, the input data size is not a multiple of the block size during decryption, or the padding is invalid during decryption.

    - `CM_IOC_CLEANUP`: Clears all buffers and resets the `CM_IOC_FINALIZE` state associated with the opened file descriptor.

        Possible error codes:
        - `-EINVAL`: Returned if the device is not set up.

    - `CM_IOC_CNT_RST`: Resets all counters, including byte frequency and bytes read/written.


1. `/proc/cryptomod` Interface
    The `/proc/cryptomod` interface provides the following two pieces of information:

    - First Row:
        ```
        <total bytes read by user programs> <total bytes written by user programs>
        ```

    - Byte Frequency Matrix:
      - Represents the ***global*** frequency ($f_b$) of each byte ($b$) in the data ***encrypted and read by user programs***.
      - Format:
        - Each row ($i$) and column ($j$) corresponds to:
          $a_{ij} = f_{16i+j}$
        - Each element is separated by a single space.

    - Example Output:
        ```
        2160 2121
         9 13  7 13  4 10 10  7  7  7 11  6 11  7  6  9 
         9  9  5 13  6 10  8  8 11  3 14 12 14  7  5 12 
         7  5 11  9  7  5  9 12 11  5  9  8 13  4  7  8 
         8 10  6 10 12 12 10  8 11 11 10 10  7  6 11 10 
         6  8  8  9  7 15  9  6  9 16  6 11 11  5  5 14 
         6  6 11  5  5  4 13 10 13 10 10 10  9  6  2  9 
        15 11 11 11 10 14 15  6  8  8  7 11  9 12  7  9 
         2 13  8 10 11  9  7  2  5  9 12  9 11 11  8  3 
         8  9  7  6 13  6  8 13  9 10 10 12  8 13  5  9 
         7  7 11 17  5 18  8  8 10  6 11  6  6 14  7  7 
        12  9  7  9  6  5 10 11  8  6 13  6  6  9  7  6 
         7  7 12  8  9 10  7  6  7 10  8  8  9  7 10  9 
         3  5 10  3 11  9 14  9  3  8  5  5  9  7  5 10 
         9  9  8  6  7  7 12  9  4  6 12  5  4  7  6  8 
         3  3 10 11  7 14  3  6  7  7  7  2 13  8  9  5 
         5  6  7  4 12 10  7  5  9  9 11  5  7  7  6  9 
        ```

    - Thread Safety:
      - You must ensure that the counters are **thread-safe** to prevent race conditions.


## Lab Hints

Here are some hints for you.

1. Please install the qemu system emulator in your development platform. For Ubuntu-based dockers, you can install it using the command `apt install qemu-system-x86`. It would work on both Intel and Apple chips. You can even install the native one on Mac by using `brew install qemu`.

1. Once you have the qemu system emulator, you can simply type `sh ./qemu.sh` to boot the Linux kernel in a virtual machine. The username is `root`. The current design uses the archive `rootfs.cpio.bz2` as the `initramfs` image. You can add more files in the filesystem by extracting files from the archive, adding files your want, and re-packing the archive.
    :::warning
    You can use `poweroff` command or simply press `Ctrl-A X` to exit QEMU.
    :::

1. If you plan to have your files in the `initramfs` image, you can extract the files using [bzip2(1)](https://linux.die.net/man/1/bzip2) and [cpio(1)](https://linux.die.net/man/1/cpio) utilities, and re-pack the image using the same tools.

   :::warning
   You may need to set the cpio format to `newc` format. Also please ensure that you pack all the required files in the image.
   :::

1. A sample `hello, world!` module is available [here (hellomod.tbz)](https://up.zoolab.org/unixprog/lab02/hellomod-6.6.17.tbz). You may implement your module based on the `hello, world!` example. It has sample file operations and `/proc` file system implementations.

   :::info
   In the `qemu` virtual machine runtime, you can use the commands `insmod` and `rmmod` to install and remove modules, respectively. Use `lsmod` to inspect what modules have been loaded.
   :::

1. To copy memory content from the user-space process to the kernel, please use the [`copy_from_user`](https://elixir.bootlin.com/linux/v6.6.17/source/include/linux/uaccess.h#L180) function. To copy memory content from the kernel to the user-space process, please use the [`copy_to_user`](https://elixir.bootlin.com/linux/v6.6.17/source/include/linux/uaccess.h#L188) function.

1. To lock shared resources between processors, you may use the [`mutex_lock`](https://elixir.bootlin.com/linux/v6.6.17/source/include/linux/mutex.h#L200) and the [`mutex_unlock`](https://elixir.bootlin.com/linux/v6.6.17/source/include/linux/mutex.h#L219) functions. The lock can be declared as a static global variable using the macro `DEFINE_MUTEX(name_of_the_lock_variable)`.

1. You may want to have ***private data*** associated with an opened file. To do this, you will need to ...

   - Define a customized data structure for your private data.
   - When opening a file, allocate a memory space using [kzalloc](https://elixir.bootlin.com/linux/v6.6.17/source/include/linux/slab.h#L718) for the customized data structure.
   - Assign the pointer of the allocated space to `file->private_data`.
   - Remember to release the spaces of the `file->private_data` using the [kfree](https://elixir.bootlin.com/linux/v6.6.17/source/include/linux/slab.h#L227) function.

1. Use `printk` to log kernel operations. To temporarily suppress log output on the console, adjust the console log level by writing a lower value to `/proc/sys/kernel/printk`. For example, running:

      ```bash
      echo 1 > /proc/sys/kernel/printk
      ```

      sets the console log level to `KERN_ALERT`, meaning only messages with severity `KERN_EMERG` (0) and `KERN_ALERT` (1) will be displayed. For more information, please refer to the [Message Logging with `printk`](https://www.kernel.org/doc/html/v6.6/core-api/printk-basics.html) documentation.

1. We have provided a test program, `test_crypto`, to validate your module. This program includes seven test cases, identified by numbers ranging from 0 to 6.
    - The usage of `test_crypto` is as follows:
        ```
        Usage: test_crypto test <num>
          or:  test_crypto enc -i INPUT -o OUTPUT -k KEY (hex, 32/48/64 chars) -s SIZE -m BASIC|ADV
          or:  test_crypto dec -i INPUT -o OUTPUT -k KEY (hex, 32/48/64 chars) -s SIZE -m BASIC|ADV
        ```
        - The key must be provided in hexadecimal format and must have a valid length.
     - Examples:
         - Run testcase
             ```
             ./test_crypto test 0
             ```
         - Decrypting a file with an I/O size of 128 in `ADV` mode:
             ```
             ./test_crypto dec -i fun.jpg.enc -o fun.jpg -k "e381aae38293e381a7e698a5e697a5e5bdb1e38284e381a3e3819fe381ae213f" -s 128 -m ADV
             ```
        The program can be downloaded from [here (test_crypto)](https://up.zoolab.org/unixprog/lab02/test_crypto).
        If your kernel module failed to pass the test in latest version of `test_crypto`, we also provide old version for you to demo.
        - [test_crypto_v1](https://up.zoolab.org/unixprog/lab02/test_crypto_v1)
            md5 checksum: `6a98b2ed0c47f631e3b8995db9dffb29`
        - [test_crypto_v2](https://up.zoolab.org/unixprog/lab02/test_crypto_v2)
            md5 checksum: `4d8af083e4c73a721a13957232ddb056`
    - You can generate test data yourself using `openssl`:
        ```bash
        openssl enc -aes-256-ecb -in <input file> -out <out file> -K <hex key string> -nosalt
        ```
    - You can launch `httpd` in the directory containing the files and download them from `http://localhost:8000/<file-name>` using `wget` or your browser.


## Grading

We have many test cases here. You don't have to complete them in order. Just demonstrate what you have completed. Before you run the `test_crypto` testcase program, please ensure its md5 checksum is `a77e4e644ecf204f062106bab6938c38`.
:::danger
The last demo time is 3/31 15:10.
:::

1. [10 pts] You can boot the Linux VM in a supported environment.

1. [10 pts] You can put your `cryptomod.ko` module and the `test_crypto` binary into the emulator. Load the module and it should automatically create the required `/dev/cryptodev` and `/proc/cryptomod` files.

1. [10 pts] Your kernel module can pass test 0 for `/proc/cryptomod` initial state check:
    Example output
    ```
    0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
    
    ```

1. [10 pts] Your kernel module can pass test 1 (encryption with I/O mode `BASIC`)

1. [10 pts] Your kernel module can pass test 2 (decryption with I/O mode `BASIC`)

1. [10 pts] Your kernel module can pass test 3 (encryption with I/O mode `ADV`)

1. [10 pts] Your kernel module can pass test 4 (decryption with I/O mode `ADV`)

1. [10 pts] You kernel module can pass test 5 (error handling test)

1. [10 pts] Your kernel module can pass test 6 (encryption and decryption with I/O mode `ADV`)

1. [10 pts] Your Kernel module can decrypt the data provided by TA (You can use large buffer in I/O mode `BASIC` or just use mode `ADV`)
    - [fun.jpg.enc](https://up.zoolab.org/unixprog/lab02/fun.jpg.enc) Key:`e381aae38293e381a7e698a5e697a5e5bdb1e38284e381a3e3819fe381ae213f` (AES-256)
