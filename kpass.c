/*
 * kpass.c
 * A function to do Kerberos password verification.
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <krb5.h>
#include <com_err.h>

#define CALL_FROM_PERL
#define HAVE_VSNPRINTF
#define TKT_LIFETIME     30           /* 30 seconds */
#define USE_MEMORY_CC                 /* use in-memory ccache */

/*
 * com_err hook for logging errors to syslog.
 *
 * Portability note: We don't currently happen to use the va_list args in any
 * of our calls to com_err, so it's currently fine to skip the buffer
 * formatting on systems that don't have that vsnprintf(3).
 */

static
void syslog_err(const char *tag, long code, const char *format, va_list args)
{
#ifdef HAVE_VSNPRINTF
    char buffer[128];
    (void)vsnprintf(buffer, sizeof(buffer), format, args);
    syslog(LOG_ERR, "%s: %s %s", tag, error_message(code), buffer);
#else
    syslog(LOG_ERR, "%s: %s %s", tag, error_message(code), format);
#endif
    return;
}

/*
 * Check a Kerberos function's return value; if any error occurred, log an
 * explanatory message and bail out.
 */
#define FAIL(err, tag) \
	if (err) { \
	    void (*proc)(const char *, long, const char *, va_list); \
	    proc = set_com_err_hook(syslog_err); \
	    com_err("kpass", (err), (tag)); \
	    (void)set_com_err_hook(proc); \
	    goto cleanup; \
	}

/*
 * Kerberos password verification. Attempt to obtain short term 
 * credentials for a given username and password from Kerberos AS, 
 * then obtain credentials for a local service from Kerberos TGS 
 * to verify the authenticity of the AS response.
 *
 * Arguments:
 *	username, password	The username and password to verify.
 *	service, host		A local service whose key will be used to
 *                              verify the authenticity of the Kerberos 
 *                              credentials. Specifying service as NULL
 *                              says use "host" and specifying host as NULL
 *                              says use my primary hostname.
 *	kt_pathname		Path of keytab file, or NULL to use default.
 *                              (Typical form "FILE:/abs/path/name".)
 *
 * Return -1 if an error occurs, 0 if the username or password is incorrect,
 * or 1 if password verification is successful.
 */

int kpass(username, password, service, host, kt_pathname)
     char *username;
     char *password;
     char *service;
     char *host;
     char *kt_pathname;
{
    krb5_error_code               err;
    krb5_context                  context;
    krb5_auth_context             auth_context = NULL;
    krb5_creds                    credentials;
    krb5_principal                user_principal,
	                          service_principal;
    krb5_keytab                   keytab = NULL;
    krb5_ccache                   ccache;
    char                          ccache_name[L_tmpnam + 8];
    krb5_get_init_creds_opt       gic_options;
    krb5_data                     apreq_pkt;

    int                           have_user_principal = 0,
	                          have_service_principal = 0,
	                          have_keytab = 0,
                                  have_credentials = 0,
                                  success = -1;

    apreq_pkt.data = NULL;

    err = krb5_init_context(&context);
    FAIL(err, "from krb5_init_context");

#ifdef NEED_INIT_ETS
    krb5_init_ets(context);
#endif

#ifdef USE_MEMORY_CC
    (void) memset(ccache_name, 0, sizeof(ccache_name));
    (void) strcpy(ccache_name, "MEMORY:");
    (void) tmpnam(&ccache_name[7]);
    err = krb5_cc_resolve(context, ccache_name, &ccache);
    FAIL(err, "from krb5_cc_resolve");
#else
    err = krb5_cc_default(context, &ccache);
    FAIL(err, "from cc_default");
#endif

    err = krb5_parse_name(context, username, &user_principal);
    FAIL(err, "from krb_parse_name");
    have_user_principal = 1;

    err = krb5_cc_initialize(context, ccache, user_principal);
    FAIL(err, "from krb_cc_initialize");

    krb5_get_init_creds_opt_init(&gic_options);
    krb5_get_init_creds_opt_set_tkt_life(&gic_options, TKT_LIFETIME);

    (void) memset( (char *)&credentials, 0, sizeof(credentials) );
    err = krb5_get_init_creds_password(context, &credentials,
                                       user_principal, password,
                                       0, 0, 0, 0, &gic_options);


    switch (err) {
    case 0:
	/* Success. */
	have_credentials = 1;
	break;
    case KRB5KDC_ERR_PREAUTH_FAILED:
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
    case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
	/* Bad username or password, unknown user etc */
	success = 0;
	/* fall through */
    default:
	/* Some other sort of failure. */
	FAIL(err, "from krb5_get_init_creds_password");
	break;
    }

    err = krb5_cc_store_cred(context, ccache, &credentials);
    FAIL(err, "from krb5_cc_store_cred");

#ifdef CALL_FROM_PERL
    /*
     * for perl module interface -- i don't know how to pass a C
     * NULL from perl (is there a way?), so translate the empty string.
     */
    if ( host && (!strcmp(host, "")) )
        host = NULL;

    if ( service && (!strcmp(service, "")) )
        service = NULL;
#endif /* CALL_FROM_PERL */

    err = krb5_sname_to_principal(
               context,
	       host, 
	       service,
	       KRB5_NT_SRV_HST,
	       &service_principal
	       );
    FAIL(err, "from krb5_sname_to_principal");
    have_service_principal = 1;

    if (kt_pathname && *kt_pathname) {
	err = krb5_kt_resolve(context, kt_pathname, &keytab);
	FAIL(err, "from krb5_kt_resolve");
	have_keytab = 1;
    }

    /*
     * Construct an AP_REQ message in "apreq_pkt". This will automatically
     * obtain a service ticket from the TGS.
     */

    err = krb5_mk_req(
               context,
	       &auth_context,
	       0,
	       service,
	       host,
	       NULL,
	       ccache,
	       &apreq_pkt
	       );
    FAIL(err, "from krb5_mk_req");

    if (auth_context) {
     	krb5_auth_con_free(context, auth_context);
	auth_context = NULL;
    }

#ifdef NO_REPLAYCACHE
    err = krb5_auth_con_init(context, &auth_context);
    FAIL(err, "from krb5_auth_con_init");

    err = krb5_auth_con_setflags(context, auth_context, 
                                 ~KRB5_AUTH_CONTEXT_DO_TIME);
    FAIL(err, "from krb5_auth_con_setflags");
#endif /* NO_REPLAYCACHE */

    /*
     * Now attempt to decrypt the acquired credentials.
     */

    err = krb5_rd_req(
               context,
	       &auth_context,
	       &apreq_pkt,
#ifdef NO_REPLAYCACHE
               NULL,
#else
	       service_principal,
#endif
	       keytab,
	       NULL,
	       NULL
	       );
    FAIL(err, "from krb5_rd_req");

    if (auth_context) {
        krb5_auth_con_free(context, auth_context);
        auth_context = NULL;
    }

    err = krb5_cc_destroy(context, ccache);
    FAIL(err, "from krb5_cc_destroy");

    success = 1;

cleanup:

    if (apreq_pkt.data)
        krb5_free_data_contents(context, &apreq_pkt);

    if (have_keytab)
	if (err = krb5_kt_close(context, keytab))
	    com_err("kpass", err, "from krb5_kt_close");

    if (have_user_principal)
        krb5_free_principal(context, user_principal);

    if (have_service_principal)
	krb5_free_principal(context, service_principal);

    if (have_credentials)
	krb5_free_cred_contents(context, &credentials);

    if (context)
        krb5_free_context(context);

    return success;
}

