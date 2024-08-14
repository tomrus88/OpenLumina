#include "pch.h"

#define PLUGIN_NAME		"OpenLumina"
#define PLUGIN_DESC		"Allows IDA to connect to third party Lumina servers"
#define PLUGIN_PREFIX	"OpenLumina: "
#define PLUGIN_VER		__DATE__ " " __TIME__

static plugin_ctx_t* s_plugin_ctx = nullptr;

bool load_certificate(qstring& buffer, const char* certFilePath)
{
    auto certFile = fopenRT(certFilePath);

    if (certFile != nullptr)
    {
        uint64 certSize = qfsize(certFile);

        buffer.resize(certSize, '\0');

        qfread(certFile, &buffer[0], certSize);

        qfclose(certFile);

        if ((debug & IDA_DEBUG_LUMINA) != 0)
            msg(PLUGIN_PREFIX "load_certificate:\n%s\nlength %lu\nsize %lu\n", buffer.c_str(), buffer.length(), buffer.size());

        bool hasHeader = strstr(buffer.c_str(), "-----BEGIN CERTIFICATE-----") != nullptr;
        bool hasFooter = strstr(buffer.c_str(), "-----END CERTIFICATE-----") != nullptr;

        return hasHeader && hasFooter;
    }
    return false;
}

#if __NT__
static BOOL(WINAPI* CertAddEncodedCertificateToStore_orig)(HCERTSTORE hCertStore, DWORD dwCertEncodingType, const BYTE* pbCertEncoded, DWORD cbCertEncoded, DWORD dwAddDisposition, PCCERT_CONTEXT* ppCertContext) = CertAddEncodedCertificateToStore;

static BOOL WINAPI CertAddEncodedCertificateToStore_hook(HCERTSTORE hCertStore, DWORD dwCertEncodingType, const BYTE* pbCertEncoded, DWORD cbCertEncoded, DWORD dwAddDisposition, PCCERT_CONTEXT* ppCertContext)
{
    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "CertAddEncodedCertificateToStore_hook called\n");

    if (s_plugin_ctx != nullptr && s_plugin_ctx->certificates.size() != 0)
    {
        for (auto cert : s_plugin_ctx->certificates)
        {
            DWORD pubKeySize = 2048;
            uint8_t pubKey[2048];

            if (CryptStringToBinaryA(cert.c_str(), cert.size(), CRYPT_STRING_BASE64HEADER, pubKey, &pubKeySize, NULL, NULL))
            {
                // inject our root certificate to certificate store
                if (CertAddEncodedCertificateToStore_orig(hCertStore, X509_ASN_ENCODING, pubKey, pubKeySize, CERT_STORE_ADD_USE_EXISTING, nullptr))
                {
                    if ((debug & IDA_DEBUG_LUMINA) != 0)
                        msg(PLUGIN_PREFIX "added our root certificate to certificate store\n");
                }
                else
                {
                    msg(PLUGIN_PREFIX "failed to add our root certificate to certificate store!\n");
                }
            }
            else
            {
                msg(PLUGIN_PREFIX "failed to decode our root certificate from string to binary!\n");
            }
        }
    }

    // continue adding official root certificate to certificate store 
    return CertAddEncodedCertificateToStore_orig(hCertStore, dwCertEncodingType, pbCertEncoded, cbCertEncoded, dwAddDisposition, ppCertContext);
}
#endif

#if __LINUX__ || __MAC__
static openssl_ctx crypto;

int X509_STORE_add_cert_hook(X509_STORE* ctx, X509* x)
{
    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "X509_STORE_add_cert_hook: %p %p\n", ctx, x);

    if (s_plugin_ctx != nullptr && s_plugin_ctx->certificates.size() != 0)
    {
        for (auto certStr : s_plugin_ctx->certificates)
        {
            BIO* mem = crypto.BIO_new(crypto.BIO_s_mem());;
            crypto.BIO_puts(mem, certStr.c_str());
            // may be use X509 *PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u); instead?
            X509* cert = crypto.PEM_read_bio_X509(mem, NULL, 0, NULL);
            crypto.BIO_free(mem);

            // inject our root certificate to certificate store
            if (crypto.X509_STORE_add_cert(ctx, cert))
            {
                if ((debug & IDA_DEBUG_LUMINA) != 0)
                    msg(PLUGIN_PREFIX "added our root certificate to certificate store\n");
            }
            else
            {
                msg(PLUGIN_PREFIX "failed to add our root certificate to certificate store!\n");
            }

            crypto.X509_free(cert);
        }
    }

    // continue adding official root certificate to certificate store
    return crypto.X509_STORE_add_cert(ctx, x);
}

void* dlopen_hook(const char* filename, int flags)
{
    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "dlopen_hook: %s %u\n", filename, flags);
    return dlopen(filename, flags);
}

void* dlsym_hook(void* handle, const char* symbol)
{
    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "dlsym_hook: %p %s\n", handle, symbol);

    void* addr = dlsym(handle, symbol);

    if (addr != nullptr && symbol != nullptr && strcmp(symbol, "X509_STORE_add_cert") == 0)
    {
        crypto.BIO_s_mem = (BIO_s_mem_fptr)dlsym(handle, "BIO_s_mem");
        crypto.BIO_new = (BIO_new_fptr)dlsym(handle, "BIO_new");
        crypto.BIO_puts = (BIO_puts_fptr)dlsym(handle, "BIO_puts");
        crypto.PEM_read_bio_X509 = (PEM_read_bio_X509_fptr)dlsym(handle, "PEM_read_bio_X509");
        crypto.BIO_free = (BIO_free_fptr)dlsym(handle, "BIO_free");
        crypto.X509_STORE_add_cert = (X509_STORE_add_cert_fptr)addr;
        crypto.X509_free = (X509_free_fptr)dlsym(handle, "X509_free");

        if ((debug & IDA_DEBUG_LUMINA) != 0)
            msg("openssl: BIO_s_mem %p BIO_new %p BIO_puts %p PEM_read_bio_X509 %p BIO_free %p X509_STORE_add_cert %p X509_free %p",
                crypto.BIO_s_mem, crypto.BIO_new, crypto.BIO_puts, crypto.PEM_read_bio_X509, crypto.BIO_free, crypto.X509_STORE_add_cert, crypto.X509_free);

        if ((debug & IDA_DEBUG_LUMINA) != 0)
            msg(PLUGIN_PREFIX "returned %p for X509_STORE_add_cert\n", (void*)X509_STORE_add_cert_hook);

        return (void*)X509_STORE_add_cert_hook;
    }

    return addr;
}
#endif

bool idaapi plugin_ctx_t::run(size_t arg)
{
    msg(PLUGIN_PREFIX "plugin run called\n");
    return true;
}

struct file_enumerator_impl : file_enumerator_t
{
    file_enumerator_impl(plugin_ctx_t* ctx) : pc(ctx) {}

    int visit_file(const char* file)
    {
        if ((debug & IDA_DEBUG_LUMINA) != 0)
            msg(PLUGIN_PREFIX "loading certificate: %s\n", file);

        qstring cert;

        if (load_certificate(cert, file))
            pc->certificates.add(cert);
        else
            msg(PLUGIN_PREFIX "failed to load certificate file!\n");

        if ((debug & IDA_DEBUG_LUMINA) != 0)
            msg(PLUGIN_PREFIX "loaded certificate: %s\n", file);

        return 0;
    }
private:
    plugin_ctx_t* pc = nullptr;
};

bool plugin_ctx_t::init_hook()
{
    const char* ida_dir = idadir(nullptr);

    char answer[QMAXPATH];
    file_enumerator_impl fe(this);

    enumerate_files(answer, sizeof(answer), ida_dir, "hexrays*.crt", fe);

    if (certificates.size() == 0)
    {
        msg(PLUGIN_PREFIX "can't find any hexrays*.crt files in your IDA folder!\n");
        return false;
    }
    else
    {
        if ((debug & IDA_DEBUG_LUMINA) != 0)
            msg(PLUGIN_PREFIX "loaded %lu certificates\n", certificates.size());
    }

    plthook_t* plthook;

#if __NT__
#if __EA64__
    if (plthook_open(&plthook, "ida64.dll") != 0) {
        msg("plthook_open error: %s\n", plthook_error());
        return false;
    }
#else
    if (plthook_open(&plthook, "ida.dll") != 0) {
        msg("plthook_open error: %s\n", plthook_error());
        return false;
    }
#endif
    if (plthook_replace(plthook, "CertAddEncodedCertificateToStore", (void*)CertAddEncodedCertificateToStore_hook, NULL) != 0) {
        msg("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return false;
    }
#endif

#if __LINUX__
#if __EA64__
    if (plthook_open(&plthook, "libida64.so") != 0) {
        msg("plthook_open error: %s\n", plthook_error());
        return false;
}
#else
    if (plthook_open(&plthook, "libida.so") != 0) {
        msg("plthook_open error: %s\n", plthook_error());
        return false;
    }
#endif
    if (plthook_replace(plthook, "dlopen", (void*)dlopen_hook, NULL) != 0) {
        msg("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return false;
    }
    if (plthook_replace(plthook, "dlsym", (void*)dlsym_hook, NULL) != 0) {
        msg("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return false;
    }
#endif

#if __MAC__
#if __EA64__
    if (plthook_open(&plthook, "libida64.dylib") != 0) {
        msg("plthook_open error: %s\n", plthook_error());
        return false;
    }
#else
    if (plthook_open(&plthook, "libida.dylib") != 0) {
        msg("plthook_open error: %s\n", plthook_error());
        return false;
    }
#endif
    if (plthook_replace(plthook, "dlopen", (void*)dlopen_hook, NULL) != 0) {
        msg("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return false;
    }
    if (plthook_replace(plthook, "dlsym", (void*)dlsym_hook, NULL) != 0) {
        msg("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return false;
    }
#endif
    plthook_close(plthook);

    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "certificate hook applied\n");

    return true;
}

plugin_ctx_t::~plugin_ctx_t()
{
    // TODO: remove hooks?

    s_plugin_ctx = nullptr;
}

static plugmod_t* idaapi init()
{
    msg(PLUGIN_PREFIX "init\n");

    auto ctx = new plugin_ctx_t;

    if (ctx == nullptr)
    {
        msg(PLUGIN_PREFIX "plugin ctx create failed!\n");
        return nullptr;
    }

    if (!ctx->init_hook())
    {
        msg(PLUGIN_PREFIX "plugin init_hook failed!\n");
        delete ctx;
        return nullptr;
    }

    s_plugin_ctx = ctx;

    msg(PLUGIN_PREFIX "initialized (Version: " PLUGIN_VER " by TOM_RUS)\n");

    return ctx;
}

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    // PLUGIN_HIDE - Plugin should not appear in the Edit, Plugins menu.
    // PLUGIN_FIX - Load plugin when IDA starts and keep it in the memory until IDA stops
    // PLUGIN_MULTI - The plugin can work with multiple idbs in parallel
    PLUGIN_HIDE | PLUGIN_FIX | PLUGIN_MULTI,	// Plugin flags
    init,										// Initialize plugin
    nullptr,									// Terminate plugin
    nullptr,									// Invoke plugin
    PLUGIN_DESC,								// Long comment about the plugin
    nullptr,									// Multiline help about the plugin
    PLUGIN_NAME,								// Preferred short name of the plugin
    nullptr,									// Preferred hotkey to run the plugin
};
