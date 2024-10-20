#pragma once

#if __LINUX__ || __MAC__
// these are just copy/paste from openssl so we don't have to link against it
struct X509_STORE;
struct X509;
struct BIO_METHOD;
struct BIO;
struct pem_password_cb;
struct SSL_CTX;

typedef const BIO_METHOD* (*BIO_s_mem_fptr)(void);
typedef BIO* (*BIO_new_fptr)(const BIO_METHOD* type);
typedef int (*BIO_puts_fptr)(BIO* bp, const char* buf);
typedef X509* (*PEM_read_bio_X509_fptr)(BIO* out, X509** x, pem_password_cb* cb, void* u);
typedef int (*BIO_free_fptr)(BIO* a);
typedef int (*X509_STORE_add_cert_fptr)(X509_STORE* ctx, X509* x);
typedef void (*X509_free_fptr)(X509* a);
typedef int (*SSL_CTX_load_verify_locations_fptr)(SSL_CTX* ctx, const char* CAfile, const char* CApath);

struct openssl_ctx
{
    BIO_s_mem_fptr BIO_s_mem;
    BIO_new_fptr BIO_new;
    BIO_puts_fptr BIO_puts;
    PEM_read_bio_X509_fptr PEM_read_bio_X509;
    BIO_free_fptr BIO_free;
    X509_STORE_add_cert_fptr X509_STORE_add_cert;
    X509_free_fptr X509_free;
    SSL_CTX_load_verify_locations_fptr SSL_CTX_load_verify_locations;
};

#endif

#if __EA64__ && IDA_SDK_VERSION < 900
#define IDA_LIB_SUFF "64"
#else
#define IDA_LIB_SUFF
#endif

#if __NT__
constexpr auto IDA_LIB_NAME = "ida" IDA_LIB_SUFF ".dll";
#endif

#if __LINUX__
constexpr auto IDA_LIB_NAME = "libida" IDA_LIB_SUFF ".so";
#endif

#if __MAC__
constexpr auto IDA_LIB_NAME = "libida" IDA_LIB_SUFF ".dylib";
#endif
