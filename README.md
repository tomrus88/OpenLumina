OpenLumina

IDA plugin that allows connecting to third party Lumina servers.

## Getting started

1. Build or download precompiled version of the plugin and put it into your IDA\plugins directory
2. Copy your hexrays*.crt certificate file(s) provided by Lumina server owner to your IDA install directory

## Building plugin

1. Visual Studio 2022 is required for building plugin
2. vcpkg package manager required if you don't want to configure dependencies yourself manually
3. Install Microsoft Detours package through vcpkg `vcpkg install detours`
4. Configure paths to your extracted IDA SDK directory and optionally your IDA install directory in PropertySheet.props file
5. Open OpenLumina.sln in Visual Studio 2022 and build the plugin
6. Copy compiled plugin binaries to your IDA\plugins directory if you haven't configured your IDA install directory in step 4 above

## Generating TLS certificates for your own Lumina server

See scripts in lumina_ca folder. Generating certificates requires OpenSSL 3.x to be installed and be on the PATH environment variable.

## Troubleshooting

Run IDA with "-z 00800000" command line switch (it must be in quotes) to see additional debug messages printed into "Output" window
