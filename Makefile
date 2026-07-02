CC = gcc
CFLAGS = -g -Wall -Wextra -std=c11
LDLIBS = -lcrypto

TARGETS = asymmetric_encrypt_evp \
          envelope_evp \
          rsa_sign_verify_evp \
          symmetric_encrypt_evp

.PHONY: all clean

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

clean:
	-rm -f $(TARGETS) ciphertext decrypted_plaintext
