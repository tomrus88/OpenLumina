chcp 65001
mkdir rootCA\certs
mkdir rootCA\crl
mkdir rootCA\newcerts
mkdir rootCA\private
mkdir rootCA\csr
mkdir intermediateCA\certs
mkdir intermediateCA\crl
mkdir intermediateCA\newcerts
mkdir intermediateCA\private
mkdir intermediateCA\csr
echo 01 > ./rootCA/serial
echo 01 > ./intermediateCA/serial
echo 01 > ./rootCA/crlnumber
echo 01 > ./intermediateCA/crlnumber
type NUL > ./rootCA/index.txt
type NUL > ./intermediateCA/index.txt
openssl genrsa -out ./rootCA/private/ca.key.pem 4096
rem chmod 400 ./rootCA/private/ca.key.pem
rem openssl rsa -noout -text -in ./rootCA/private/ca.key.pem
openssl req -config openssl_root.cnf -key ./rootCA/private/ca.key.pem -utf8 -new -x509 -days 7300 -sha512 -extensions v3_ca -out ./rootCA/certs/ca.cert.pem -batch
rem chmod 444 ./rootCA/certs/ca.cert.pem
rem openssl x509 -noout -text -in ./rootCA/certs/ca.cert.pem
openssl genrsa -out ./intermediateCA/private/intermediate.key.pem 4096
rem chmod 400 ./intermediateCA/private/intermediate.key.pem
openssl req -config openssl_intermediate.cnf -key ./intermediateCA/private/intermediate.key.pem -utf8 -new -sha512 -out ./intermediateCA/certs/intermediate.csr.pem -batch
openssl ca -config openssl_root.cnf -extensions v3_intermediate_ca -days 3650 -utf8 -notext -md sha512 -in ./intermediateCA/certs/intermediate.csr.pem -out ./intermediateCA/certs/intermediate.cert.pem -batch
rem chmod 444 ./intermediateCA/certs/intermediate.cert.pem
rem openssl x509 -noout -text -in ./intermediateCA/certs/intermediate.cert.pem
openssl verify -CAfile ./rootCA/certs/ca.cert.pem ./intermediateCA/certs/intermediate.cert.pem
copy /b intermediateCA\certs\intermediate.cert.pem + rootCA\certs\ca.cert.pem intermediateCA\certs\ca-chain.cert.pem
openssl verify -CAfile ./intermediateCA/certs/ca-chain.cert.pem ./intermediateCA/certs/intermediate.cert.pem
openssl ecparam -name prime256v1 -genkey -out ./intermediateCA/private/vault.hex-rays.com.key.pem
openssl req -config openssl_lumina.cnf -key ./intermediateCA/private/vault.hex-rays.com.key.pem -utf8 -new -sha256 -out ./intermediateCA/csr/vault.hex-rays.com.csr.pem -batch
openssl ca -config openssl_intermediate.cnf -extensions server_cert -days 1825 -utf8 -notext -md sha256 -in ./intermediateCA/csr/vault.hex-rays.com.csr.pem -out ./intermediateCA/certs/vault.hex-rays.com.cert.pem -batch
rem openssl x509 -noout -text -in ./intermediateCA/certs/vault.hex-rays.com.cert.pem
openssl verify -CAfile ./intermediateCA/certs/ca-chain.cert.pem ./intermediateCA/certs/vault.hex-rays.com.cert.pem
copy /b intermediateCA\certs\vault.hex-rays.com.cert.pem + intermediateCA\certs\intermediate.cert.pem intermediateCA\certs\vault.hex-rays.com.chain.cert.pem
openssl verify -CAfile ./intermediateCA/certs/ca-chain.cert.pem ./intermediateCA/certs/vault.hex-rays.com.chain.cert.pem
mkdir out
copy rootCA\certs\ca.cert.pem out\hexrays.crt
copy intermediateCA\certs\intermediate.cert.pem out\intermediate.crt
copy intermediateCA\certs\vault.hex-rays.com.chain.cert.pem out\lumina.crt
copy intermediateCA\private\vault.hex-rays.com.key.pem out\lumina.key
openssl pkcs12 -export -inkey ./intermediateCA/private/vault.hex-rays.com.key.pem -in ./intermediateCA/certs/vault.hex-rays.com.chain.cert.pem -out out/lumen.p12
