#!/bin/sh
gcc -fPIC -shared -o libmysql-argon2.so main.c -largon2
