#!/bin/bash
#vendor-cert.sh
export dir=./brski/intermediate
export cadir=./brski
export cnfdir=./conf
export vnddir=./vendors

OPENSSL_BIN="openssl"


# file structure is cleaned start filling

echo "#############################"
echo "combine sandelman key and certificate "
echo "#############################"

cp $vnddir/sandelman_masa.crt $cadir/certs/sandelman_masa.crt
cp $vnddir/sandelman_pledge.crt $dir/certs/sandelman_pledge.crt
cp $vnddir/sandelman_pledge.key $dir/private/sandelman_pledge.key
cp $vnddir/sandelman_masa_srv.crt $dir/certs/sandelman_masa_srv.crt

$OPENSSL_BIN pkcs12 \
 -inkey $dir/private/sandelman_pledge.key \
 -in $dir/certs/sandelman_pledge.crt -export  \
-out $dir/certs/sandelman_pledge-comb.pfx

# converteer sandelman pkcs12 file to pem
echo "converteer sandelman pkcs12 file to pem"
$OPENSSL_BIN pkcs12 \
   -in $dir/certs/sandelman_pledge-comb.pfx -out $dir/certs/sandelman_pledge-comb.crt -nodes

#show certificate in registrar combined certificate
$OPENSSL_BIN  x509 -in $dir/certs/sandelman_pledge-comb.crt -text


echo "#############################"
echo "combine esko key and certificate "
echo "#############################"

cp $vnddir/esko_masa.crt $cadir/certs/esko_masa.crt
cp $vnddir/esko_pledge.crt $dir/certs/esko_pledge.crt
cp $vnddir/esko_pledge.key $dir/private/esko_pledge.key
cp $vnddir/esko_masa.crt $dir/certs/esko_masa_srv.crt

$OPENSSL_BIN pkcs12 \
 -inkey $dir/private/esko_pledge.key \
 -in $dir/certs/esko_pledge.crt -export  \
-out $dir/certs/esko_pledge-comb.pfx

# converteer esko pkcs12 file to pem
echo "converteer esko pkcs12 file to pem"
$OPENSSL_BIN pkcs12 \
   -in $dir/certs/esko_pledge-comb.pfx -out $dir/certs/esko_pledge-comb.crt -nodes

#show certificate in registrar combined certificate
$OPENSSL_BIN  x509 -in $dir/certs/esko_pledge-comb.crt -text

echo "#############################"
echo "combine siemens key and certificate "
echo "#############################"

cp $vnddir/siemens_masa.crt $cadir/certs/siemens_masa.crt
cp $vnddir/siemens_pledge.crt $dir/certs/siemens_pledge.crt
cp $vnddir/siemens_pledge.key $dir/private/siemens_pledge.key
cp $vnddir/siemens_masa.crt $dir/certs/siemens_masa_srv.crt

$OPENSSL_BIN pkcs12 \
 -inkey $dir/private/siemens_pledge.key \
 -in $dir/certs/siemens_pledge.crt -export  \
-out $dir/certs/siemens_pledge-comb.pfx

# converteer siemens pkcs12 file to pem
echo "converteer siemens pkcs12 file to pem"
$OPENSSL_BIN pkcs12 \
   -in $dir/certs/siemens_pledge-comb.pfx -out $dir/certs/siemens_pledge-comb.crt -nodes

#show certificate in registrar combined certificate
$OPENSSL_BIN  x509 -in $dir/certs/siemens_pledge-comb.crt -text

