#!/bin/bash
#brski-cert.sh
export dir=./brski/intermediate
export cadir=./brski
export cnfdir=./conf
export format=pem
export default_crl_days=30
sn=8

DevID=pledge.1.2.3.4
serialNumber="serialNumber=$DevID"
export localhost="localhost:4433"
export hwType=1.3.6.1.4.1.6715.10.1
export hwSerialNum=01020304 # Some hex
export subjectAltName="otherName:1.3.6.1.5.5.7.8.4;SEQ:hmodname"
echo  $hwType - $hwSerialNum
echo $serialNumber

OPENSSL_BIN="openssl"

# remove all files
rm -r ./brski/*
#
# initialize file structure
# root level
cd $cadir
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
touch serial
echo 11223344556600 >serial
echo 1000 > crlnumber
# intermediate level
mkdir intermediate
cd intermediate
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 11223344556600 >serial
echo 1000 > crlnumber
cd ../..



# file structure is cleaned start filling

echo "#############################"
echo "create registrar keys and certificates "
echo "#############################"


echo "create root registrar certificate using ecdsa with sha 256 key"
$OPENSSL_BIN ecparam -name secp256r1 -genkey -noout -out $cadir/private/ca-regis.key

$OPENSSL_BIN req -new -x509 \
 -config $cnfdir/openssl-regis.cnf \
 -key $cadir/private/ca-regis.key \
 -out $cadir/certs/ca-regis.crt \
 -extensions v3_ca\
 -days 365 \
 -subj "/C=NL/ST=NB/L=Helmond/O=vanderstok/OU=consultancy/CN=registrar.stok.nl"

# Combine authority certificate and key
echo "Combine authority certificate and key"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
 -inkey $cadir/private/ca-regis.key \
 -in $cadir/certs/ca-regis.crt -export  \
-out $cadir/certs/ca-regis-comb.pfx

# converteer authority pkcs12 file to pem
echo "converteer authority pkcs12 file to pem"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
   -in $cadir/certs/ca-regis-comb.pfx -out $cadir/certs/ca-regis-comb.crt -nodes

#show certificate in registrar combined certificate
$OPENSSL_BIN  x509 -in $cadir/certs/ca-regis-comb.crt -text

echo "#############################"
echo "create regis_server keys and certificates for ecdsa with sha256 "
echo "#############################"

echo "create regis_server derived certificate using ecdsa with sha 256 key"
$OPENSSL_BIN ecparam -name secp256r1 -genkey -noout -out $dir/private/regis_server.key

echo "create regis_server certificate request"
$OPENSSL_BIN req -nodes -new -sha256 \
 -key $dir/private/regis_server.key \
 -out $dir/csr/regis_server.csr \
 -subj "/C=NL/ST=NB/L=Helmond/O=vanderstok/OU=operation/CN=REGIS server"

# Sign regis_server derived Certificate
echo "sign regis_server derived certificate "
$OPENSSL_BIN ca -config $cnfdir/openssl-regis.cnf \
 -extensions v3_intermediate_ca \
 -days 365 -in $dir/csr/regis_server.csr \
 -out $dir/certs/regis_server.crt 

# Add regis_server key and regis_server certificate to pkcs12 file
echo "Add regis_server key and regis_server certificate to pkcs12 file"
$OPENSSL_BIN pkcs12  -passin pass:watnietweet -passout pass:watnietweet\
 -inkey $dir/private/regis_server.key \
 -in $dir/certs/regis_server.crt \
 -export -out $dir/certs/regis_server-comb.pfx

# converteer regis_server pkcs12 file to pem
echo "converteer regis_server pkcs12 file to pem"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
 -in $dir/certs/regis_server-comb.pfx \
 -out $dir/certs/regis_server-comb.crt -nodes

#show certificate in regis_server-comb.crt
$OPENSSL_BIN  x509 -in $dir/certs/regis_server-comb.crt -text

#show private key in regis_server-comb.crt
$OPENSSL_BIN ecparam -name secp256r1 \
 -in $dir/certs/regis_server-comb.crt -text


echo "#############################"
echo "create regis_server keys and certificates for ed 25519 "
echo "#############################"

echo "create regis_server derived certificate using ed25519"
$OPENSSL_BIN genpkey -algorithm ed25519 \
 -out $dir/private/regis_server_ed25519.key

echo "create regis_server_ed25519 certificate request"
$OPENSSL_BIN req -nodes -new -sha256 \
 -key $dir/private/regis_server_ed25519.key \
 -out $dir/csr/regis_server_ed25519.csr \
 -subj "/C=NL/ST=NB/L=Helmond/O=vanderstok/OU=operation/CN=REGIS ED25519_server"

# Sign regis_server_ed25519 derived Certificate
echo "sign regis_server_ed25519 derived certificate "
$OPENSSL_BIN ca -config $cnfdir/openssl-regis.cnf \
 -days 365 -in $dir/csr/regis_server_ed25519.csr \
 -extensions v3_intermediate_ca\
 -out $dir/certs/regis_server_ed25519.crt 

# Add regis_server key and regis_server certificate to pkcs12 file
echo "Add regis_server_ed25519 key and regis_server_ed25519 certificate to pkcs12 file"
$OPENSSL_BIN pkcs12  -passin pass:watnietweet -passout pass:watnietweet\
 -inkey $dir/private/regis_server_ed25519.key \
 -in $dir/certs/regis_server_ed25519.crt \
 -export -out $dir/certs/regis_server_ed25519-comb.pfx

# converteer regis_server_ed25519 pkcs12 file to pem
echo "converteer regis_server_ed25519 pkcs12 file to pem"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
 -in $dir/certs/regis_server_ed25519-comb.pfx \
 -out $dir/certs/regis_server_ed25519-comb.crt -nodes

#show certificate in regis_server_ed25519-comb.crt
$OPENSSL_BIN  x509 \
 -in $dir/certs/regis_server_ed25519-comb.crt -text

#show private key in regis_server-comb.crt
$OPENSSL_BIN ecparam -name secp256r1 \
 -in $dir/certs/regis_server_ed25519-comb.crt -text


#
# Certificate Authority for MASA
#
echo "#############################"
echo "create MASA keys and certificates "
echo "#############################"

echo "create root MASA certificate using ecdsa with sha 256 key"
$OPENSSL_BIN ecparam -name secp256r1 -genkey -noout -out $cadir/private/ca-masa.key

$OPENSSL_BIN req -new -x509 \
 -config $cnfdir/openssl-masa.cnf \
 -days 1000 -key $cadir/private/ca-masa.key -out $cadir/certs/ca-masa.crt \
 -extensions v3_ca\
 -subj "/C=NL/ST=NB/L=Helmond/O=vanderstok/OU=manufacturer/CN=masa.stok.nl"

# Combine authority masa certificate and key
echo "Combine authority certificate and key for masa"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
   -inkey $cadir/private/ca-masa.key -in $cadir/certs/ca-masa.crt -export -out $cadir/certs/ca-masa-comb.pfx

# converteer masa authority pkcs12 file to pem for masa
echo "converteer authority pkcs12 file to pem for masa"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
   -in $cadir/certs/ca-masa-comb.pfx -out $cadir/certs/ca-masa-comb.crt -nodes

#show certificate in masa authority combined certificate
$OPENSSL_BIN  x509 -in $cadir/certs/ca-masa-comb.crt -text

echo "#############################"
echo "create masa_server keys and certificates for ecdsa with sha256 "
echo "#############################"

echo "create masa_server derived certificate using ecdsa with sha 256 key"
$OPENSSL_BIN ecparam -name secp256r1 -genkey -noout -out $dir/private/masa_server.key

echo "create masa_server certificate request"
$OPENSSL_BIN req -nodes -new -sha256 \
 -key $dir/private/masa_server.key \
 -out $dir/csr/masa_server.csr \
 -subj "/C=NL/ST=NB/L=Helmond/O=vanderstok/OU=operation/CN=MASA server"

# Sign masa_server derived Certificate
echo "sign masa_server derived certificate "
$OPENSSL_BIN ca -config $cnfdir/openssl-masa.cnf \
 -extensions v3_intermediate_ca \
 -days 365 -in $dir/csr/masa_server.csr \
 -out $dir/certs/masa_server.crt 

# Add masa_server key and masa_server certificate to pkcs12 file
echo "Add masa_server key and masa_server certificate to pkcs12 file"
$OPENSSL_BIN pkcs12  -passin pass:watnietweet -passout pass:watnietweet\
 -inkey $dir/private/masa_server.key \
 -in $dir/certs/masa_server.crt \
 -export -out $dir/certs/masa_server-comb.pfx

# converteer masa_server pkcs12 file to pem
echo "converteer masa_server pkcs12 file to pem"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
 -in $dir/certs/masa_server-comb.pfx \
 -out $dir/certs/masa_server-comb.crt -nodes

#show certificate in masa_server-comb.crt
$OPENSSL_BIN  x509 -in $dir/certs/masa_server-comb.crt -text

#show private key in masa_server-comb.crt
$OPENSSL_BIN ecparam -name secp256r1 \
 -in $dir/certs/masa_server-comb.crt -text

echo "#############################"
echo "create masa_server keys and certificates for ed 25519 "
echo "#############################"

echo "create masa_server derived certificate using ed25519"
$OPENSSL_BIN genpkey -algorithm ed25519 \
 -out $dir/private/masa_server_ed25519.key

echo "create masa_server_ed25519 certificate request"
$OPENSSL_BIN req -nodes -new -sha256 \
 -key $dir/private/masa_server_ed25519.key \
 -out $dir/csr/masa_server_ed25519.csr \
 -subj "/C=NL/ST=NB/L=Helmond/O=vanderstok/OU=operation/CN=MASA ED25519_server"

# Sign masa_server_ed25519 derived Certificate
echo "sign masa_server_ed25519 derived certificate "
$OPENSSL_BIN ca -config $cnfdir/openssl-masa.cnf \
 -days 365 -in $dir/csr/masa_server_ed25519.csr \
 -extensions v3_intermediate_ca\
 -out $dir/certs/masa_server_ed25519.crt 

# Add masa_server key and masa_server certificate to pkcs12 file
echo "Add masa_server_ed25519 key and masa_server_ed25519 certificate to pkcs12 file"
$OPENSSL_BIN pkcs12  -passin pass:watnietweet -passout pass:watnietweet\
 -inkey $dir/private/masa_server_ed25519.key \
 -in $dir/certs/masa_server_ed25519.crt \
 -export -out $dir/certs/masa_server_ed25519-comb.pfx

# converteer masa_server_ed25519 pkcs12 file to pem
echo "converteer masa_server_ed25519 pkcs12 file to pem"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
 -in $dir/certs/masa_server_ed25519-comb.pfx \
 -out $dir/certs/masa_server_ed25519-comb.crt -nodes

#show certificate in masa_server_ed25519-comb.crt
$OPENSSL_BIN  x509 \
 -in $dir/certs/masa_server_ed25519-comb.crt -text

#show private key in masa_server-comb.crt
$OPENSSL_BIN ecparam -name secp256r1 \
 -in $dir/certs/masa_server_ed25519-comb.crt -text


#
# Certificate for Pledge derived from MASA certificate
#
echo "#############################"
echo "create pledge keys and certificates for ecdsa with sha256 "
echo "#############################"


# Pledge derived ecda sha 256 Certificate

echo "create pledge derived certificate using ecdsa with sha 256 key"
$OPENSSL_BIN ecparam -name secp256r1 -genkey -noout \
 -out $dir/private/pledge_ES256.key

echo "create pledge certificate request"
$OPENSSL_BIN req -nodes -new \
 -key $dir/private/pledge_ES256.key \
 -out $dir/csr/pledge_ES256.csr \
  -subj "/C=NL/ST=NB/L=Helmond/O=vanderstok/OU=manufacturing/CN=uuid:$DevID/$serialNumber"

# Sign pledge derived Certificate
echo "sign pledge derived certificate "
$OPENSSL_BIN ca -config $cnfdir/openssl-pledge.cnf \
 -extensions 8021ar_idevid \
 -days 365 -in $dir/csr/pledge_ES256.csr \
 -out $dir/certs/pledge_ES256.crt 

# Add pledge key and pledge certificate to pkcs12 file
echo "Add derived pledge key and derived pledge certificate to pkcs12 file"
$OPENSSL_BIN pkcs12  -passin pass:watnietweet -passout pass:watnietweet\
 -inkey $dir/private/pledge_ES256.key \
 -in $dir/certs/pledge_ES256.crt -export \
 -out $dir/certs/pledge_ES256-comb.pfx

# converteer pledge pkcs12 file to pem
echo "converteer pledge pkcs12 file to pem"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
   -in $dir/certs/pledge_ES256-comb.pfx -out $dir/certs/pledge_ES256-comb.crt -nodes

#show certificate in pledge-comb.crt
$OPENSSL_BIN  x509 -in $dir/certs/pledge_ES256-comb.crt -text

#show private key in pledge_ES256-comb.crt
$OPENSSL_BIN ecparam -name sep256r1 -in $dir/certs/pledge_ES256-comb.crt -text

echo "#############################"
echo "create pledge keys and certificates for ed 25591 "
echo "#############################"


# Pledge derived ed25519 Certificate

DevID=pledge.5.6.7.8
serialNumber="serialNumber=$DevID"

echo "create pledge derived certificate using ed25519 key"
$OPENSSL_BIN genpkey -algorithm ed25519 \
 -out $dir/private/pledge_ed25519.key

echo "create pledge certificate request"
$OPENSSL_BIN req -nodes -new \
 -key $dir/private/pledge_ed25519.key \
 -out $dir/csr/pledge_ed25519.csr \
  -subj "/C=NL/ST=NB/L=Helmond/O=vanderstok/OU=manufacturing/CN=uuid:$DevID/$serialNumber"

# Sign pledge derived Certificate
echo "sign pledge derived certificate "
$OPENSSL_BIN ca -config $cnfdir/openssl-pledge.cnf \
 -extensions 8021ar_idevid \
 -days 365 -in $dir/csr/pledge_ed25519.csr \
 -out $dir/certs/pledge_ed25519.crt 

# Add pledge key and pledge certificate to pkcs12 file
echo "Add derived pledge key and derived pledge certificate to pkcs12 file"
$OPENSSL_BIN pkcs12  -passin pass:watnietweet \
 -passout pass:watnietweet\
 -inkey $dir/private/pledge_ed25519.key \
 -in $dir/certs/pledge_ed25519.crt -export\
 -out $dir/certs/pledge_ed25519-comb.pfx

# converteer pledge pkcs12 file to pem
echo "converteer pledge pkcs12 file to pem"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet \
 -passout pass:watnietweet\
   -in $dir/certs/pledge_ed25519-comb.pfx \
 -out $dir/certs/pledge_ed25519-comb.crt -nodes

#show certificate in pledge-comb.crt
$OPENSSL_BIN  x509 -in $dir/certs/pledge_ed25519-comb.crt -text

#show private key in pledge-comb.crt
$OPENSSL_BIN ecparam -name secp256r1 \
 -in $dir/certs/pledge_ed25519-comb.crt -text

#convert to PEM format
echo "convert key to der "
$OPENSSL_BIN pkey -in $dir/private/pledge_ed25519.key \
 -outform DER \
 -out $dir/private/pledge_ed25519_key.der

echo "convert certificate to der "
$OPENSSL_BIN x509 -in $dir/certs/pledge_ed25519.crt  \
 -outform DER \
 -out $dir/certs/pledge_ed25519_crt.der




