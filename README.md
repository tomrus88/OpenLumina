OpenLumina

IDA plugin that allows connecting to third party Lumina servers.

## Getting started

1. Build or download precompiled version of the plugin and put it into your IDA\plugins directory
2. Copy your hexrays*.crt certificate file(s) provided by Lumina server owner to your IDA install directory

## Building plugin

1. CMake is required for building plugin. You can use CMake version bundled with Visual Studio 2022 (CMake 3.29.5 as of 02.09.2024)
2. Configure path to your extracted IDA SDK directory in build_win.cmd/build_linux.sh/build_mac.sh file
3. Run build_win.cmd/build_linux.sh/build_mac.sh (on Windows it must be run from VS Developer Command Prompt for VS2022)
3. Copy compiled plugin binaries to your <IDA_INSTALL>\plugins directory

## Generating TLS certificates for your own Lumina server

See scripts in lumina_ca folder. Generating certificates requires OpenSSL 3.x to be installed and be on the PATH environment variable.

## Troubleshooting

Run IDA with "-z 00800000" command line switch (it must be in quotes) to see additional debug messages printed into "Output" window
