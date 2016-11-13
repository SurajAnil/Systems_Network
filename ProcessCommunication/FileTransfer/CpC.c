/* Function to copy files
 * 
 * Author:
 *  Suraj Bennur <sbennur@outlook.com>
 */

#include <stdio.h>
#include <errno.h>
#define BUF_SIZE 256

int main(int argc, char *argv[])
{
	FILE *inFile, *outFile;
	char rec[BUF_SIZE];
	size_t bytesIn, bytesOut;

	if(argc!=3)
	{
		printf("Usage: cp file1 file2\n");
		return 1;
	}

	inFile = fopen(argv[1], "rb");
	if(inFile == NULL)
	{
		perror(argv[1]);
		return 1;
	}

	outFile = fopen(argv[2], "wb");
	if(outFile == NULL)
	{
		perror(argv[2]);
		return 1;
	}

	//transfer the file one record at a time
	while((bytesIn = fread(rec, 1, BUF_SIZE, inFile))>0)
	{
		bytesOut = fwrite(rec, 1, bytesIn, outFile);
		if(bytesOut == NULL)
		{
			perror("Fatal write error\n");
			return 4;
		}
	}


	fclose(inFile);
	fclose(outFile);

	return 0;
}
