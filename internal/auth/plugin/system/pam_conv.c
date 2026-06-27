//go:build linux && cgo && pam

// bifrost_conv is the PAM conversation callback used by pam_linux.go.
//
// PAM calls it during pam_authenticate to obtain responses to messages (most
// importantly the password prompt, PAM_PROMPT_ECHO_OFF). We answer prompts with
// the password passed via appdata_ptr and ignore informational/error messages.
//
// This is implemented in C (rather than as an exported Go function) so that it
// is a plain C function pointer with the exact signature libpam expects, and so
// the password handling stays on the C side without crossing the cgo boundary on
// every prompt.

#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

int bifrost_conv(int num_msg, const struct pam_message **msg,
                 struct pam_response **resp, void *appdata_ptr) {
    if (num_msg <= 0 || msg == NULL || resp == NULL) {
        return PAM_CONV_ERR;
    }

    struct pam_response *replies =
        (struct pam_response *)calloc((size_t)num_msg, sizeof(struct pam_response));
    if (replies == NULL) {
        return PAM_BUF_ERR;
    }

    const char *password = (const char *)appdata_ptr;

    for (int i = 0; i < num_msg; i++) {
        replies[i].resp = NULL;
        replies[i].resp_retcode = 0;

        switch (msg[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
        case PAM_PROMPT_ECHO_ON:
            if (password != NULL) {
                replies[i].resp = strdup(password);
                if (replies[i].resp == NULL) {
                    // Roll back any allocations and signal failure.
                    for (int j = 0; j < i; j++) {
                        if (replies[j].resp != NULL) {
                            free(replies[j].resp);
                        }
                    }
                    free(replies);
                    return PAM_BUF_ERR;
                }
            }
            break;
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
        default:
            // Nothing to answer; leave resp NULL.
            break;
        }
    }

    *resp = replies;
    return PAM_SUCCESS;
}
