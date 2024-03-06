
#ifdef OPENSSL_NO_TTY

#include <openssl/e_os2.h>
#include <evp.h>
#include "ui_locl.h"
#include "cryptlib.h"

int dummy_read_write_string(UI *ui, UI_STRING *uis);
int dummy_open_close(UI *ui);

UI_METHOD ui_dummy =
	{
	"Dummy user interface",
	dummy_open_close,
	dummy_read_write_string,
	NULL,
	dummy_read_write_string,
	dummy_open_close,
	NULL
	};

UI_METHOD *UI_OpenSSL(void)
	{
	return &ui_dummy;
	}

int dummy_open_close(UI *ui)
	{
	/* Pretend that opening and closing the dummy UI succeeds. */
	return 1;
	}

int dummy_read_write_string(UI *ui, UI_STRING *uis)
	{
	/* Writing to and reading from the dummy UI is not possible. */
	return 0;
	}

int UI_add_input_string(UI *ui, const char *prompt, int flags,
    char *result_buf, int minsize, int maxsize) {
  return 1;
}

int UI_add_verify_string(UI *ui, const char *prompt, int flags, 
    char *result_buf, int minsize, int maxsize, 
    const char *test_buf) {
  return 1;
}

int UI_process(UI *ui) { return 1; }

void UI_free(UI *ui) { return; }

UI * UI_new(void) { return (UI *) NULL; }


/*
evp_key.c:(.text+0x99): undefined reference to `UI_new'
/usr/bin/ld: evp_key.c:(.text+0xc4): undefined reference to `UI_add_input_string'
/usr/bin/ld: evp_key.c:(.text+0xe9): undefined reference to `UI_add_verify_string'
/usr/bin/ld: evp_key.c:(.text+0xf3): undefined reference to `UI_process'
/usr/bin/ld: evp_key.c:(.text+0xff): undefined reference to `UI_free'
*/

#endif
