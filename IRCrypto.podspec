Pod::Spec.new do |s|

  s.name         = "IRCrypto"
  s.version      = "0.9.1"
  s.summary      = "iOS Crypto library: Provides Symmetric and Asymmetric Encryption as well as AEAD using RNCryptor Data Format v3"
  s.description  = <<-DESC 
  IRCrypto aims to provide the following:

Cryptographic Key Derivation (using PBKDF2 with 10,000 rounds) from a String
Symmetric AES Key generation (128, 256, 512 bits)
Asymmetric RSA Key generation (1024, 2048 and 4096 bits)
Asymmetric EC Key generation (256, 384 and 521 bits) (Read More)
Data hashing (using SHA256)
Data signing (using HMAC - SHA256 + 256 bit key)
Symmetric Encryption (AES in CBC mode)
Asymmetric Encryption (RSA)
Authenticated Encryption using the Encrypt-then-MAC scheme (AES in CBC mode and HMAC) [RNCryptor Data Format v4.0]
Public Key Encryption with Authenticated Encryption (RSA + AES in CBC mode and HMAC) [RNCryptor Data Format v4.0]
You can also:

Save the generated keys (AES, RSA, EC) in the Keychain and protect them with TouchID and/or a user generated password
Generate an asymmetric key pair (RSA) for signing data, where the private key will never be returned and just used for singning directly from the Secure Enclave
DESC
  s.homepage     = "https://github.com/ivRodriguezCA/IRCrypto"
  s.license      = { :type => 'MIT', :file => 'MIT-LICENSE.txt' }
  s.author             = { "Ivan E. Rodriguez" => "iv.rodriguez@ivrodriguez.com" }
  s.social_media_url   = "http://twitter.com/ivRodriguezCA"
  s.platform     = :ios, "9.0"
  s.source       = { :git => "https://github.com/ivRodriguezCA/IRCrypto.git", :tag => "v#{s.version}" }
  s.source_files  = "IRCrypto/**/*.{h,m}"
  s.public_header_files = "IRCrypto/IRCryptoHeader.h", "IRCrypto/IRCrypto.h", "IRCrypto/IRPublicConstants.h"
end