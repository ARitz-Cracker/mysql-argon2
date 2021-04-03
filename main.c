#include <string.h>
#include <mysql/mysql.h>
#include <argon2.h>
// ARGON2ID_HASH(int timeCost, int memCost, int parallelism, string password, string salt, int hashLength)
bool ARGON2ID_HASH_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
	initid->max_length = 255;
	if (args->arg_count != 6)
	{
		strcpy(message, "ARGON2ID_HASH() requires six arguments");
		return 1;
	}
	if (args->arg_type[0] != INT_RESULT)
	{
		strcpy(message, "ARGON2ID_HASH(): Bad argument #1, int expected.");
		return 1;
	}
	if (args->arg_type[1] != INT_RESULT)
	{
		strcpy(message, "ARGON2ID_HASH(): Bad argument #2, int expected.");
		return 1;
	}
	if (args->arg_type[2] != INT_RESULT)
	{
		strcpy(message, "ARGON2ID_HASH(): Bad argument #3, int expected.");
		return 1;
	}
	if (args->arg_type[3] != STRING_RESULT)
	{
		strcpy(message, "ARGON2ID_HASH(): Bad argument #4, string expected.");
		return 1;
	}
	if (args->arg_type[4] != STRING_RESULT)
	{
		strcpy(message, "ARGON2ID_HASH(): Bad argument #5, string expected.");
		return 1;
	}
	if (args->arg_type[5] != INT_RESULT)
	{
		strcpy(message, "ARGON2ID_HASH(): Bad argument #6, int expected.");
		return 1;
	}
	return 0;
}

void ARGON2ID_HASH_deinit(UDF_INIT *initid)
{
}

void ARGON2ID_HASH_reset(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
}

void ARGON2ID_HASH_clear(UDF_INIT *initid, char *is_null, char *error)
{
}

void ARGON2ID_HASH_add(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
}
char *ARGON2ID_HASH(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error)
{
	// Is this needed for strlen to work properly?
	memset(result, 0, 255);
	int hashStatus = argon2id_hash_encoded(
		*(uint32_t*) args->args[0],
		*(uint32_t*) args->args[1],
		*(uint32_t*) args->args[2],
		(unsigned char *)(args->args[3]),
		args->lengths[3],
		(unsigned char *)(args->args[4]),
		args->lengths[4],
		*(uint32_t*) args->args[5],
		result,
		254
	);
	if(hashStatus == ARGON2_OK){
		*length = strlen(result);
	}else{
		*is_null = 1;
	}
	return result;
}


// ARGON2ID_VERIFY(string encodedHash, string password)
bool ARGON2ID_VERIFY_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
	if (args->arg_type[0] != STRING_RESULT)
	{
		strcpy(message, "ARGON2ID_VERIFY(): Bad argument #1, string expected.");
		return 1;
	}
	if (args->arg_type[1] != STRING_RESULT)
	{
		strcpy(message, "ARGON2ID_VERIFY(): Bad argument #2, string expected.");
		return 1;
	}
	return 0;
}

void ARGON2ID_VERIFY_deinit(UDF_INIT *initid)
{
}

void ARGON2ID_VERIFY_reset(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
}

void ARGON2ID_VERIFY_clear(UDF_INIT *initid, char *is_null, char *error)
{
}

void ARGON2ID_VERIFY_add(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
}
long long ARGON2ID_VERIFY(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
	// argon2id_verify expects a null terminated string for the encoded hash
	unsigned char* encodedHash;
	unsigned long encodedHashLength = args->lengths[0];
	encodedHash = malloc(encodedHashLength + 1);
	if(!encodedHash){
		*error = 1;
		*is_null = 1;
		return 0;
	}
	memcpy(encodedHash, (unsigned char *)(args->args[0]), encodedHashLength);
	encodedHash[encodedHashLength] = 0;
	// Well, that was painful. Now we can actually do the verification
	int verifyStatus = argon2id_verify(
		encodedHash,
		(unsigned char *)(args->args[1]),
		args->lengths[1]
	);
	free(encodedHash);
	// TODO: We should probably do something if the hash fails for any reason other than a non-match
	if(verifyStatus == ARGON2_OK){
		return 1;
	}
	return 0;
}
