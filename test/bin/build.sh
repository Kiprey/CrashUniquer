#! /bin/bash
gcc test.c -o noasan_test
gcc test.c -o asan_test -fsanitize=address
