#pragma once

#if __LINUX__ || __MAC__
// these are just copy/paste from openssl so we don't have to link against it
struct X509_STORE;
struct X509;
struct BIO_METHOD;
struct BIO;
struct pem_password_cb;

typedef const BIO_METHOD* (*BIO_s_mem_fptr)(void);
typedef BIO* (*BIO_new_fptr)(const BIO_METHOD* type);
typedef int (*BIO_puts_fptr)(BIO* bp, const char* buf);
typedef X509* (*PEM_read_bio_X509_fptr)(BIO* out, X509** x, pem_password_cb* cb, void* u);
typedef int (*BIO_free_fptr)(BIO* a);
typedef int (*X509_STORE_add_cert_fptr)(X509_STORE* ctx, X509* x);
typedef void (*X509_free_fptr)(X509* a);

struct openssl_ctx
{
    BIO_s_mem_fptr BIO_s_mem;
    BIO_new_fptr BIO_new;
    BIO_puts_fptr BIO_puts;
    PEM_read_bio_X509_fptr PEM_read_bio_X509;
    BIO_free_fptr BIO_free;
    X509_STORE_add_cert_fptr X509_STORE_add_cert;
    X509_free_fptr X509_free;
};

#endif
