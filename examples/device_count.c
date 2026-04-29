#include "ctap2.h"

#include <stdio.h>

int main(void) {
    int count = ctap2_device_count();
    printf("Found %d FIDO2 device(s)\n", count);
    return count < 0 ? 1 : 0;
}
