#include <stdint.h>
#include <stdlib.h>

#define RED "\033[0;31m"
#define YELLOW "\033[0;33m"
#define RESET "\033[0;0m"

#define BYTE_S 1L
#define KBYTE_S 1024L
#define MBYTE_S ((uint64_t) (KBYTE_S * KBYTE_S))

# define NT_LEN 1

int main(const int argc, char **const argv) {
	printf("%d\n", argc);
	printf("%s\n", argv[0]);
	return EXIT_SUCCESS;
}
