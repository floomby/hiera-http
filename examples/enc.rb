#!/usr/bin/ruby

require 'openssl'
require 'base64'

# read in the certificate
cert = OpenSSL::X509::Certificate.new File.read('cert.pem')

# create a cipher to use
cipher = OpenSSL::Cipher.new 'AES-128-CBC'

# line by line from stdin
while line = gets
  puts Base64.encode64 (OpenSSL::PKCS7::encrypt [cert], line, cipher, OpenSSL::PKCS7::BINARY).to_der
end

