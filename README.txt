Assignment 1 Cryptography Algorithms & Key Store

The assignment has been done successfully.

There are 4 source files:
    src/crypto/cs457_crypto_test.c : This is the main file which contains the main function and the test cases for the algorithms.
    src/crypto/cs457_crypto.c : This file contains the implementation of the algorithms.
    src/crypto/cs457_crypto.h : This file contains the function prototypes and the necessary header files.
    src/kv/kv.c : This file contains the implementation of the Part B.

There is a Makefile that creates 2 executables:
    1. crypto_test : This is the executable for the Part A.
    2. kv : This is the executable for the Part B.

Observations:
    In crypto_test, all the plaintexts can be changed by defining the macros in the main function.

    Exercise 3:
        I have given partial output of my program in ex3.txt file.
        The plaintext is:
            THIS IS A TEXT THAT HAS BEEN ENCRYPTED
            USING THE AFFINE ALGORITHM AND GIVEN AS AN ASSIGMENT IN THE COMPUTER
            SCIENCE DEPARTMENT OF THE UNIVERSITY OF CRETE.

    Exercise 4:
        This Exercise is working well with and without ommiting spaces and special characters.

    Exercise 5,6:
        I ommit spaces and punctuation. I put them back using 'ommit' and  'add_ommited' functions.
