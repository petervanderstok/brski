#!/bin/bash
#wrong-cert.sh
# don't forget flip -u wrong-cert.sh
export dir=./wrong_certificates
ecport intdir=./brski/intermediate
export cadir=./brski
export cnfdir=./conf
export format=pem
export default_crl_days=30
sn=8

# remove all files
rm -r ./wrong_certificates/*
#
# initialize file structure
# root level
cd $dir
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
touch serial
echo 11223344556600 >serial
echo 1000 > crlnumber

cd ..

DevID=pledge.1.2.3.4
export issuer_key=./brski/private/ca-regis.key
export issuer_certificate=./brski/certs/ca-regis.crt
echo $issuer_certificate
echo $issuer_key

serialNumber="serialNumber=$DevID"
export urlOID="1.3.6.1.5.5.7.1.32"
export enddate="99991231235959Z"  
export MASAurl="localhost:4433"
export hwType=1.3.6.1.4.1.6715.10.1
export hwSerialNum=01020304 # Some hex
export subjectAltName="otherName:1.3.6.1.5.5.7.8.4;SEQ:hmodname"
echo  $hwType - $hwSerialNum
echo $serialNumber

OPENSSL_BIN="openssl"

#
# Certificates for Pledge with faults
#
echo "#############################"
echo "create pledge keys and certificates with faults "
echo "#############################"


# Pledge derived ecda sha 256 Certificate

echo "create pledge derived certificate using ecdsa with sha 256 key"
$OPENSSL_BIN ecparam -name secp256r1 -genkey -noout \
 -out $dir/private/pledge_wr_issuer.key

echo "create pledge certificate request"
$OPENSSL_BIN req -nodes -new \
 -key $dir/private/pledge_wr_issuer.key \
 -out $dir/csr/pledge_wr_issuer.csr \
  -subj "/C=NL/ST=NB/L=Helmond/O=vanderstok/OU=manufacturing/CN=uuid:$DevID/$serialNumber"

# Sign pledge derived Certificate
echo "sign pledge derived certificate "
$OPENSSL_BIN ca -config $cnfdir/openssl-wrong.cnf \
 -extensions 8021ar_idevid \
 -days 365 -in $dir/csr/pledge_wr_issuer.csr \
 -out $dir/certs/pledge_wr_issuer.crt 

# Add pledge key and pledge certificate to pkcs12 file
echo "Add derived pledge key and derived pledge certificate to pkcs12 file"
$OPENSSL_BIN pkcs12  -passin pass:watnietweet -passout pass:watnietweet\
 -inkey $dir/private/pledge_wr_issuer.key \
 -in $dir/certs/pledge_wr_issuer.crt -export \
 -out $dir/certs/pledge_wr_issuer-comb.pfx

# converteer pledge pkcs12 file to pem
echo "converteer pledge pkcs12 file to pem"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
   -in $dir/certs/pledge_wr_issuer-comb.pfx \
 -out $dir/certs/pledge_wr_issuer-comb.crt -nodes

#show certificate in wr_issuer-comb.crt
$OPENSSL_BIN  x509 -in $dir/certs/pledge_wr_issuer-comb.crt -text

#show private key in pledge_wr_issuer-comb.crt
$OPENSSL_BIN ecparam -name sep256r1 \
 -in $dir/certs/pledge_wr_issuer-comb.crt -text


export issuer_key=./brski/private/ca-masa.key
export issuer_certificate=./brski/certs/ca-masa.crt

# Pledge derived ecda sha 256 Certificate
# use wrong MASAurl

echo "#############################"
echo "create pledge derived certificate using ecdsa with sha 256 key"
echo "WRONG MASAurl"

export issuer_key=./brski/private/ca-masa.key
export issuer_certificate=./brski/certs/ca-masa.crt
export MASAurl="unknownhost:4433"
DevID=pledge.5.6.7.8
serialNumber="serialNumber=$DevID"

$OPENSSL_BIN ecparam -name secp256r1 -genkey -noout \
 -out $dir/private/pledge_wr_url.key

echo "create pledge certificate request"
$OPENSSL_BIN req -nodes -new \
 -key $dir/private/pledge_wr_url.key \
 -out $dir/csr/pledge_wr_url.csr \
  -subj "/C=NL/ST=NB/L=Helmond/O=vanderstok/OU=manufacturing/CN=uuid:$DevID/$serialNumber"

# Sign pledge derived Certificate
echo "sign pledge derived certificate "
$OPENSSL_BIN ca -config $cnfdir/openssl-wrong.cnf \
 -extensions 8021ar_idevid \
 -days 365 -in $dir/csr/pledge_wr_url.csr \
 -out $dir/certs/pledge_wr_url.crt 

# Add pledge key and pledge certificate to pkcs12 file
echo "Add derived pledge key and derived pledge certificate to pkcs12 file"
$OPENSSL_BIN pkcs12  -passin pass:watnietweet -passout pass:watnietweet\
 -inkey $dir/private/pledge_wr_url.key \
 -in $dir/certs/pledge_wr_url.crt -export \
 -out $dir/certs/pledge_wr_url-comb.pfx

# converteer pledge pkcs12 file to pem
echo "converteer pledge pkcs12 file to pem"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
   -in $dir/certs/pledge_wr_url-comb.pfx \
 -out $dir/certs/pledge_wr_url-comb.crt -nodes

#show certificate in wr_issuer-comb.crt
$OPENSSL_BIN  x509 -in $dir/certs/pledge_wr_url-comb.crt -text

#show private key in pledge_wr_url-comb.crt
$OPENSSL_BIN ecparam -name sep256r1 \
 -in $dir/certs/pledge_wr_url-comb.crt -text

# Pledge derived ecda sha 256 Certificate
# wrong  MASAurl OID

echo "#############################"
echo "create pledge derived certificate using ecdsa with sha 256 key"
echo "WRONG MASAurl OID"

export issuer_key=./brski/private/ca-masa.key
export issuer_certificate=./brski/certs/ca-masa.crt
export MASAurl="localhost:4433"
export urlOID="1.3.6.1.5.5.7.1.78"
DevID=pledge.9.10.11.12
serialNumber="serialNumber=$DevID"

$OPENSSL_BIN ecparam -name secp256r1 -genkey -noout \
 -out $dir/private/pledge_no_url.key

echo "create pledge certificate request"
$OPENSSL_BIN req -nodes -new \
 -key $dir/private/pledge_no_url.key \
 -out $dir/csr/pledge_no_url.csr \
  -subj "/C=NL/ST=NB/L=Helmond/O=vanderstok/OU=manufacturing/CN=uuid:$DevID/$serialNumber"

# Sign pledge derived Certificate
echo "sign pledge derived certificate "
$OPENSSL_BIN ca -config $cnfdir/openssl-wrong.cnf \
 -extensions 8021ar_idevid \
 -days 365 -in $dir/csr/pledge_no_url.csr \
 -out $dir/certs/pledge_no_url.crt 

# Add pledge key and pledge certificate to pkcs12 file
echo "Add derived pledge key and derived pledge certificate to pkcs12 file"
$OPENSSL_BIN pkcs12  -passin pass:watnietweet -passout pass:watnietweet\
 -inkey $dir/private/pledge_no_url.key \
 -in $dir/certs/pledge_no_url.crt -export \
 -out $dir/certs/pledge_no_url-comb.pfx

# converteer pledge pkcs12 file to pem
echo "converteer pledge pkcs12 file to pem"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
   -in $dir/certs/pledge_no_url-comb.pfx \
 -out $dir/certs/pledge_no_url-comb.crt -nodes

#show certificate in no_url-comb.crt
$OPENSSL_BIN  x509 -in $dir/certs/pledge_no_url-comb.crt -text

#show private key in pledge_no_url-comb.crt
$OPENSSL_BIN ecparam -name sep256r1 \
 -in $dir/certs/pledge_no_url-comb.crt -text

# Pledge derived ecda sha 256 Certificate
# wrong  validation date

echo "#############################"
echo "create pledge derived certificate using ecdsa with sha 256 key"
echo "WRONG validation date"

export issuer_key=./brski/private/ca-masa.key
export issuer_certificate=./brski/certs/ca-masa.crt
export MASAurl="localhost:4433"
export urlOID="1.3.6.1.5.5.7.1.32"
export enddate="20211025140000Z" 
DevID=pledge.13.14.15.16
serialNumber="serialNumber=$DevID"

$OPENSSL_BIN ecparam -name secp256r1 -genkey -noout \
 -out $dir/private/pledge_wr_valid.key

echo "create pledge certificate request"
$OPENSSL_BIN req -nodes -new \
 -key $dir/private/pledge_wr_valid.key \
 -out $dir/csr/pledge_wr_valid.csr \
  -subj "/C=NL/ST=NB/L=Helmond/O=vanderstok/OU=manufacturing/CN=uuid:$DevID/$serialNumber"

# Sign pledge derived Certificate
echo "sign pledge derived certificate "
$OPENSSL_BIN ca -config $cnfdir/openssl-wrong.cnf \
 -extensions 8021ar_idevid \
 -days 1 -in $dir/csr/pledge_wr_valid.csr \
 -out $dir/certs/pledge_wr_valid.crt 

# Add pledge key and pledge certificate to pkcs12 file
echo "Add derived pledge key and derived pledge certificate to pkcs12 file"
$OPENSSL_BIN pkcs12  -passin pass:watnietweet -passout pass:watnietweet\
 -inkey $dir/private/pledge_wr_valid.key \
 -in $dir/certs/pledge_wr_valid.crt -export \
 -out $dir/certs/pledge_wr_valid-comb.pfx

# converteer pledge pkcs12 file to pem
echo "converteer pledge pkcs12 file to pem"
$OPENSSL_BIN pkcs12 -passin pass:watnietweet -passout pass:watnietweet\
   -in $dir/certs/pledge_wr_valid-comb.pfx \
 -out $dir/certs/pledge_wr_valid-comb.crt -nodes

#show certificate in wr_valid-comb.crt
$OPENSSL_BIN  x509 -in $dir/certs/pledge_wr_valid-comb.crt -text

#show private key in pledge_wr_valid-comb.crt
$OPENSSL_BIN ecparam -name sep256r1 \
 -in $dir/certs/pledge_wr_valid-comb.crt -text




