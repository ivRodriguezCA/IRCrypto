# IRCrypto - iOS Crypto library

#### **Warning: I'm not a cryptographer, this library has not been reviewed by a crypto expert (and may never happen), use at your own risk**
## Why?
On any crypto course the first thing you **always** learn is: **DO NOT IMPLEMENT YOUR OWN CRYPTO**, although I'm trying my best to use crypto correctly and using all best practices, there are probably issues within this library. Why am I creating this library then? Short answer: I want to learn. Although this library **is not intended to be used in real world applications** (*maybe in the future?*), I learned a lot implementing it, insted of just understanding the theory behind these cryptographic concepts, I also wanted to experiment with them with real code. That being said, if you find any issues please let me know, I'll fix them and we can all learn from it.

## Overview
#### IRCrypto aims to provide the following:
- Cryptographic Key Derivation (using PBKDF2 with 10,000 rounds) from a String
- Symmetric AES Key generation (128, 256, 512 bits)
- Asymmetric RSA Key generation (1024, 2048 and 4096 bits)
- Asymmetric EC Key generation (256, 384 and 521 bits) ([Read More][ec-type])
- Data hashing (using SHA256)
- Data signing (using HMAC - SHA256 + 256 bit key)
- Symmetric Encryption (AES in CBC mode)
- Asymmetric Encryption (RSA)
- Authenticated Encryption using the Encrypt-then-MAC scheme (AES in CBC mode and HMAC) [RNCryptor Data Format v4.0]
- Public Key Encryption with Authenticated Encryption (RSA + AES in CBC mode and HMAC) [RNCryptor Data Format v4.0]

#### You can also:
- Save the generated keys (AES, RSA, EC) in the Keychain and protect them with TouchID and/or a user generated password
- Generate an asymmetric key pair (RSA) for signing data, where the private key will never be returned and just used for singning directly from the Secure Enclave

### Version
0.7

### Import
- Clone the repo:
```sh
$ git clone https://github.com/ivRodriguezCA/IRCrypto
```
- Drag and drop the IRCrypto project on your project or
- Select the `Build Framework` scheme and build the project (`⌘ + b`), this is going to generate a `IRCrypto.framework` framework in your desktop directory.

### Usage
Create an instance of `IRCrypto` and configure it with options (read more about the options on the [`IRPublicConstants` header][IRPublicConstants-header]). When you use the default options IRCrypto is going to generate a RSA key pair (2048 bits) an AES key (256 bits) and a signing RSA key pair (the private key will never leave the secure enclave) and a HMAC key (256 bits). All these keys are going to be saved in the Keychain using the TouchID protection.
- For the default uptions:
```Objc
- (void)someMethod {
	IRCrypto *crypto = [IRCrypto new];
}
```
- For using IRCrypto just to encrypt/decrypt using your own Keys (or secret password):
```Objc
- (void)someMethod {
	IRCrypto *crypto = [[IRCrypto alloc] initWithOptions:@{kIREncryptionOptionsKey:@(kEncryptionOptionsNone)}];
}
```

#### Symmetric Encryption
If you use the default options you can simply call the `encryptData:completion:failure:` method with your plaintext data (remember to save the returned IV for decryption):
```Objc
- (void)someEncryptionMethod {
	IRCrypto *crypto = ...
	NSData *plaintext = ...
	[crypto encryptData:plaintext
             completion:^(NSData *cipherData, NSData *iv, NSData *salt) {
             	// Salt will be nil
             	// Do something with iv and cipherData
             } 
             failure:^(NSError *error) {
             	// Handle error
             }
    ];
}
```
You can also encrypt with your own key using the `encryptData:withKey:completion:failure:` method:
```Objc
- (void)someEncryptionMethod {
	IRCrypto *crypto = ...
	NSData *plaintext = ...
	NSData *key = ... // This should be a 256 bit random key
	[crypto encryptData:plaintext
                withKey:key
             completion:^(NSData *cipherData, NSData *iv, NSData *salt) {
             	// Salt will be nil
             	// Do something with iv and cipherData
             } 
             failure:^(NSError *error) {
             	// Handle error
             }
    ];
}
```

If you don't want to generate a random key, you can use a simple text password with the `encryptData:withPassword:completion:failure:` method (be aware of the fact that in this case you also need to save the `salt` for decryption):
```Objc
- (void)someEncryptionMethod {
	IRCrypto *crypto = ...
	NSData *plaintext = ...
	NSString *password = ... // This can be a string of any length
	[crypto encryptData:plaintext
           withPassword:password
             completion:^(NSData *cipherData, NSData *iv, NSData *salt) {
             	// Note that salt will *not* be nil
             	// Do something with iv, cipherData *and* salt
             } 
             failure:^(NSError *error) {
             	// Handle error
             }
    ];
}
```

#### Symmetric Decryption
If you use the default options you can simply call the `decryptData:iv:completion:failure:` method with your ciphertext and the iv returned during encryption:
```Objc
- (void)someDecryptionMethod {
	IRCrypto *crypto = ...
	NSData *ciphertext = ...
	NSData *iv = ... // The iv returned after encryption
	[crypto decryptData:ciphertext
					 iv:iv
             completion:^(NSData *decryptedData) {
             	// Do something with decryptedData
             } 
             failure:^(NSError *error) {
             	// Handle error
             }
    ];
}
```
Decrypting with your own key using the `decryptData:withKey:iv:completion:failure:` method:
```Objc
- (void)someDecryptionMethod {
	IRCrypto *crypto = ...
	NSData *ciphertext = ...
	NSData *key = ... // This should be a 256 bit random key
	NSData *iv = ... // The iv returned after encryption
	[crypto decryptData:ciphertext
                withKey:key
                	iv:iv
             completion:^(NSData *decryptedData) {
             	// Do something with decryptedData
             } 
             failure:^(NSError *error) {
             	// Handle error
             }
    ];
}
```

And of course you can decrypt using a password with the `decryptData:withPassword:iv:salt:completion:failure:` method:
```Objc
- (void)someDecryptionMethod {
	IRCrypto *crypto = ...
	NSData *ciphertext = ...
	NSString *password = ... // This can be a string of any length
	NSData *iv = ... // The iv returned after encryption
	NSData *salt = ... // The salt returned after encryption
	[crypto decryptData:plaintext
           withPassword:password
           			 iv:iv
           		   salt:salt
             completion:^(NSData *decryptedData) {
             	// Do something with decryptedData
             } 
             failure:^(NSError *error) {
             	// Handle error
             }
    ];
}
```

### Tests
Tests are written in Objective-c using the XCTest Framework, select the `IRCrypto` scheme and `⌘ + u`.

### Development

Want to contribute? Great!

Again, this is a learning experiment, if you find issues or want to add more features I'll be happy to merge your pull requests :)

### Todos

 - Receive all the hate from the Internet for creating this library in the first place
 - Get some crypto experts to look at this code
 - Iterate on the first 2 points ;)
 - Error handling
 - Add RSA and EC key pair enum for key sizes (right now is 2048 for RSA and 256 for EC)
 - Incremental Symmetric Encryption
 - Add Documentation
 - Add Data Signing functionality to `IRCrypto`
 - Finish the export public key functionality
 - Add a CHANGELOG file
 - Implement Public Key Encryption with Authenticated Encryption

License
----

The MIT License (MIT)
Copyright (c) 2016 Ivan Rodriguez

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

[ec-type]: <http://opensource.apple.com/source/Security/Security-55471/sec/Security/SecECKey.c>
[IRPublicConstants-header]: <https://github.com/ivRodriguezCA/IRCrypto/blob/master/IRCrypto/IRPublicConstants.h>