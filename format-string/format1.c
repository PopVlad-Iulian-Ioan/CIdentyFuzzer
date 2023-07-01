#include  <stdio.h> 
void main(int argc, char **argv)
{
	// This line is vulnerable
	printf(argv[1]);
}