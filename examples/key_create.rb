#!/usr/bin/env ruby
require 'openssl'
require 'time'
require 'date'

# create a key
key = OpenSSL::PKey::RSA.new 2048

# write the private key out in pem format
open 'key.pem', 'w' do |io| io.write key.to_pem end

# create a certificate to encrypt with
name = OpenSSL::X509::Name.parse 'CN=hiera-http/DC=neverland'

cert = OpenSSL::X509::Certificate.new

cert.version    = 2
cert.serial     = 0
cert.not_after  = Time.now
cert.not_before = Time.now + (60*60*24*365)

cert.public_key = key.public_key
cert.subject    = name
cert.issuer     = name

# write the cert in pem format
open 'cert.pem', 'w' do |io| io.write cert.to_pem end
