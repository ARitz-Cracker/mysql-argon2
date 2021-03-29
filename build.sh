#!/bin/sh
gcc -fPIC -shared -o libmysql-argon2.so mysql-argon2.c -largon2
