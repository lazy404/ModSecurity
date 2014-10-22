/*
* ModSecurity for Apache 2.x, http://www.modsecurity.org/
* Copyright (c) 2004-2013 Trustwave Holdings, Inc. (http://www.trustwave.com/)
*
* You may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* If any of the files related to licensing are missing or if you have any
* other questions related to licensing please contact Trustwave Holdings, Inc.
* directly using the email address security@modsecurity.org.
*/

#ifndef MSC_REMOTE_RULES_H
#define MSC_REMOTE_RULES_H

#include <apr_general.h>
#include <apr_optional.h>
#include <apr_thread_pool.h>
#include <curl/curl.h>

#include <apr_sha1.h>
#include <apr_crypto.h>
#include "http_core.h"

typedef struct msc_remote_rules_server msc_remote_rules_server;
struct msc_curl_memory_buffer_t;

#include "modsecurity.h"

struct msc_remote_rules_server {
        directory_config *context;
        const char *context_label;
        const char *uri;
        const char *key;
	    // Ping back which is not ready yet.
        // time_t timeout;
        int amount_of_rules;
};

char *msc_remote_invoke_cmd(const command_rec *cmd, cmd_parms *parms,
                              void *mconfig, const char *args);

int msc_remote_grab_content(apr_pool_t *mp, const char *uri, const char *key,
    struct msc_curl_memory_buffer_t *chunk, char **error_msg);

int msc_remote_enc_key_setup(apr_pool_t *pool,
        const char *key,
        apr_crypto_key_t **apr_key,
        apr_crypto_t *f,
        unsigned char *salt,
        char **error_msg);

int msc_remote_decrypt(apr_pool_t *pool,
        const char *key,
        struct msc_curl_memory_buffer_t *chunk,
        struct msc_curl_memory_buffer_t *chunk_plain,
        char **error_msg);

int msc_remote_add_rules_from_uri(cmd_parms *orig_parms,
        msc_remote_rules_server *remote_rules_server,
        char **error_msg);

#if 0
Ping back is not enabled yet.
void msc_remote_rules_after_logging(modsec_rec *msr);
#endif

#endif

