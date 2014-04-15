#!/usr/bin/env ruby

str = 'ENC[PKCS7,ThisWouldBeABase64String==]'

a = /ENC\[([^,]),[^\]]\]/.match(str)

