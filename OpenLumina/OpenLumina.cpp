#include "pch.h"

#define PLUGIN_NAME		"OpenLumina"
#define PLUGIN_DESC		"Allows IDA to connect to third party Lumina servers"
#define PLUGIN_PREFIX	"OpenLumina: "

static plugin_ctx_t* s_plugin_ctx = nullptr;

//#undef __NT__
//#define __LINUX__ 1

#if __NT__
bool load_and_decode_certificate(bytevec_t& buffer, const char* certFilePath)
{
    auto certFile = fopenRT(certFilePath);

    if (certFile != nullptr)
    {
        qstring cert;
        qstring line;

        if (qgetline(&line, certFile) >= 0)
        {
            do
            {
                if (strcmp(line.c_str(), "-----BEGIN CERTIFICATE-----"))
                {
                    if (!strcmp(line.c_str(), "-----END CERTIFICATE-----"))
                        break;

                    if (line.length())
                        cert += line;
                }
            } while (qgetline(&line, certFile) >= 0);
        }

        qfclose(certFile);

        if ((debug & IDA_DEBUG_LUMINA) != 0)
            msg(PLUGIN_PREFIX "load_and_decode_certificate: %s\n", cert.c_str());

        return base64_decode(&buffer, cert.c_str(), cert.length());
    }
    return false;
}

static BOOL(WINAPI* CertAddEncodedCertificateToStore_orig)(HCERTSTORE hCertStore, DWORD dwCertEncodingType, const BYTE* pbCertEncoded, DWORD cbCertEncoded, DWORD dwAddDisposition, PCCERT_CONTEXT* ppCertContext) = CertAddEncodedCertificateToStore;

static BOOL WINAPI CertAddEncodedCertificateToStore_hook(HCERTSTORE hCertStore, DWORD dwCertEncodingType, const BYTE* pbCertEncoded, DWORD cbCertEncoded, DWORD dwAddDisposition, PCCERT_CONTEXT* ppCertContext)
{
    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "CertAddEncodedCertificateToStore_hook called\n");

    if (s_plugin_ctx != nullptr && s_plugin_ctx->decodedCert.size() != 0)
    {
        // inject our root certificate to certificate store
        if (!CertAddEncodedCertificateToStore_orig(hCertStore, X509_ASN_ENCODING, &s_plugin_ctx->decodedCert[0], s_plugin_ctx->decodedCert.size(), CERT_STORE_ADD_USE_EXISTING, nullptr))
        {
            msg(PLUGIN_PREFIX "failed to add our root certificate to certificate store!\n");
        }
        else
        {
            if ((debug & IDA_DEBUG_LUMINA) != 0)
                msg(PLUGIN_PREFIX "added our root certificate to certificate store\n");
        }
    }

    // continue adding official root certificate to certificate store 
    return CertAddEncodedCertificateToStore_orig(hCertStore, dwCertEncodingType, pbCertEncoded, cbCertEncoded, dwAddDisposition, ppCertContext);
}

static BOOL WINAPI CertAddEncodedCertificateToStore_hook2(HCERTSTORE hCertStore, DWORD dwCertEncodingType, const BYTE* pbCertEncoded, DWORD cbCertEncoded, DWORD dwAddDisposition, PCCERT_CONTEXT* ppCertContext)
{
    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "CertAddEncodedCertificateToStore_hook2 called\n");

    if (s_plugin_ctx != nullptr && s_plugin_ctx->decodedCert.size() != 0)
    {
        // inject our root certificate to certificate store
        if (!CertAddEncodedCertificateToStore(hCertStore, X509_ASN_ENCODING, &s_plugin_ctx->decodedCert[0], s_plugin_ctx->decodedCert.size(), CERT_STORE_ADD_USE_EXISTING, nullptr))
        {
            msg(PLUGIN_PREFIX "failed to add our root certificate to certificate store!\n");
        }
        else
        {
            if ((debug & IDA_DEBUG_LUMINA) != 0)
                msg(PLUGIN_PREFIX "added our root certificate to certificate store\n");
        }
    }

    // continue adding official root certificate to certificate store
    return CertAddEncodedCertificateToStore(hCertStore, dwCertEncodingType, pbCertEncoded, cbCertEncoded, dwAddDisposition, ppCertContext);
}
#endif

#if __LINUX__ || __MAC__
bool load_certificate(qstring& buffer, const char* certFilePath)
{
    auto certFile = fopenRT(certFilePath);

    if (certFile != nullptr)
    {
        qstring line;
        bool hasHeader = false, hasFooter = false;

        if (qgetline(&line, certFile) >= 0)
        {
            do
            {
                if (strcmp(line.c_str(), "-----BEGIN CERTIFICATE-----") == 0)
                    hasHeader = true;

                if (strcmp(line.c_str(), "-----END CERTIFICATE-----") == 0)
                    hasFooter = true;

                if (line.length())
                {
                    buffer += line;
                    buffer += "\n";
                }
            } while (qgetline(&line, certFile) >= 0);
        }

        qfclose(certFile);

        if ((debug & IDA_DEBUG_LUMINA) != 0)
            msg(PLUGIN_PREFIX "load_certificate: %s\n", buffer.c_str());

        return hasHeader && hasFooter;
    }
    return false;
}

typedef int (*X509_STORE_add_cert_fptr)(X509_STORE* ctx, X509* x);

static X509_STORE_add_cert_fptr X509_STORE_add_cert_orig = nullptr;

int X509_STORE_add_cert_hook(X509_STORE* ctx, X509* x)
{
    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "X509_STORE_add_cert_hook: %p %p\n", ctx, x);

    if (s_plugin_ctx->pemCert.length() != 0)
    {
        const char* certText = s_plugin_ctx->pemCert.c_str();
        BIO* mem = BIO_new(BIO_s_mem());;
        BIO_puts(mem, certText);
        X509* cert = PEM_read_bio_X509(mem, NULL, 0, NULL);
        BIO_free(mem);

        // inject our root certificate to certificate store
        if (!X509_STORE_add_cert_orig(ctx, cert))
        {
            msg(PLUGIN_PREFIX "failed to add our root certificate to certificate store!\n");
        }
        else
        {
            if ((debug & IDA_DEBUG_LUMINA) != 0)
                msg(PLUGIN_PREFIX "added our root certificate to certificate store\n");
        }

        X509_free(cert);
    }

    // continue adding official root certificate to certificate store
    return X509_STORE_add_cert_orig(ctx, x);
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

    void *addr = dlsym(handle, symbol);

    if (addr != nullptr && strcmp(symbol, "X509_STORE_add_cert") == 0)
    {
        X509_STORE_add_cert_orig = (X509_STORE_add_cert_fptr)addr;
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

bool plugin_ctx_t::init_hook()
{
    char fileNameBuffer[QMAXPATH];

    auto certFileName = getsysfile(fileNameBuffer, sizeof(fileNameBuffer), "hexrays.crt", nullptr);

    if (certFileName == nullptr)
    {
        msg(PLUGIN_PREFIX "can't find hexrays.crt file in your IDA folder!\n");
        return false;
    }

    if ((debug & IDA_DEBUG_LUMINA) != 0)
        msg(PLUGIN_PREFIX "using certificate file \"%s\"\n", certFileName);

#if __NT__
    if (!load_and_decode_certificate(decodedCert, certFileName))
    {
        msg(PLUGIN_PREFIX "failed to load and decode certificate file!\n");
        return false;
    }
#elif __LINUX__ || __MAC__
    if (!load_certificate(pemCert, certFileName))
    {
        msg(PLUGIN_PREFIX "failed to load certificate file!\n");
        return false;
    }
#endif
    //DetourTransactionBegin();
    //DetourUpdateThread(GetCurrentThread());
    //DetourAttach(&(PVOID&)CertAddEncodedCertificateToStore_orig, CertAddEncodedCertificateToStore_hook);
    //DetourTransactionCommit();
    plthook_t* plthook;

#if __NT__
#if __EA64__
    if (plthook_open(&plthook, "ida64.dll") != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return false;
    }
#else
    if (plthook_open(&plthook, "ida.dll") != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return false;
    }
#endif
    if (plthook_replace(plthook, "CertAddEncodedCertificateToStore", (void*)CertAddEncodedCertificateToStore_hook2, NULL) != 0) {
        printf("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return false;
    }
#endif

#if __LINUX__
#if __EA64__
    if (plthook_open(&plthook, "libida64.so") != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return false;
    }
#else
    if (plthook_open(&plthook, "libida.so") != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return false;
    }
#endif
    if (plthook_replace(plthook, "dlopen", (void*)dlopen_hook, NULL) != 0) {
        printf("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return false;
    }
    if (plthook_replace(plthook, "dlsym", (void*)dlsym_hook, NULL) != 0) {
        printf("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return false;
    }
#endif

#if __MAC__
#if __EA64__
    if (plthook_open(&plthook, "libida64.dylib") != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return false;
    }
#else
    if (plthook_open(&plthook, "libida.dylib") != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return false;
    }
#endif
    if (plthook_replace(plthook, "dlopen", (void*)dlopen_hook, NULL) != 0) {
        printf("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return false;
    }
    if (plthook_replace(plthook, "dlsym", (void*)dlsym_hook, NULL) != 0) {
        printf("plthook_replace error: %s\n", plthook_error());
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
    //DetourTransactionBegin();
    //DetourUpdateThread(GetCurrentThread());
    //DetourDetach(&(PVOID&)CertAddEncodedCertificateToStore_orig, CertAddEncodedCertificateToStore_hook);
    //DetourTransactionCommit();

    s_plugin_ctx = nullptr;
}

static plugmod_t* idaapi init()
{
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
