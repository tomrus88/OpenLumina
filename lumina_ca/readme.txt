Install OpenSSL 3.x+ and make sure it's on the PATH environment variable before running those scripts

Run commands.cmd (on Windows) or commands.sh (on Linux) to generate TLS certificates for your Lumina server

Generated certificates will be copied to "out" directory

Use "lumina.crt" and "lumina.key" on your official private Lumina server

Use "lumen.p12" on your Lumen server (https://github.com/naim94a/lumen)
If you are hosting Lumen server on Windows OS, also install "intermediate.crt" to "Current User" certificate store under "Intermediate Certificate Authorities" -> "Certificates" category (it is automatically selected if you don't choose manually)
Installing intermediate certificate is required to workaround Windows bug where server is not sending full certificate chain from "lumen.p12" certificate file to client

Use "hexrays.crt" root certificate on your IDA clients
