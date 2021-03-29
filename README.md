# mysql-argon2
Exposes Argon2id's hash and verify functions as MySQL functions

To build + install on Ubuntu:

1. install `libmysqlclient-dev`, and `libargon2-dev`
2. run `build.sh`
3. copy the resulting `libmysql-argon2.so` to `/usr/lib/mysql/plugin`
4. Add the functions to your db
	* `CREATE FUNCTION ARGON2ID_HASH RETURNS STRING SONAME 'libmysql-argon2.so'`
	* `CREATE FUNCTION ARGON2ID_VERIFY RETURNS INTEGER SONAME 'libmysql-argon2.so'`
