/*
 The MIT License (MIT)
 Copyright © 2016 Ivan Rodriguez. All rights reserved.
 
 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all copies or substantial
 portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
 LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#import <Foundation/Foundation.h>
#import "IRPublicConstants.h"

@interface IRCrypto : NSObject

- (_Nonnull instancetype)initWithOptions:(NSDictionary<NSString *, id> * _Nonnull)options;

#pragma mark - Authenticated Encryption (RNCryptor Data Format v3.0)
#pragma mark - AE Encryption

/**
 Tries to encrypt data using AEAD (AES in CBC mode with HMAC-SHA256 for integrity). 
 The ciphertext returned in the completion block uses the RNCryptor Data Format v3.
 It uses the encryption and integrity keys automatically generated and saved in
 the Keychain protected with User Generated Password and/or TouchID.

 @param plaintextData Plaintext data to encrypt. Cannot be nil.
 @param completion    When encryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure       When encryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)aeEncryptData:(NSData * _Nonnull)plaintextData
           completion:(AEEncryptionCompletion _Nonnull)completion
              failure:(AEEncryptionFailure _Nonnull)failure;

/**
 Tries to encrypt data using AEAD (AES in CBC mode with HMAC-SHA256 for integrity)
 using the provided AES and HMAC Keys

 @param plaintextData Plaintext data to encrypt. Cannot be nil.
 @param symmetricKey  AES encryption key (128, 256, 512 bits)
 @param hmacKey       HMAC key (128, 256 bits)
 @param completion    When encryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure       When encryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)aeEncryptData:(NSData * _Nonnull)plaintextData
         symmetricKey:(NSData * _Nonnull)symmetricKey
              hmacKey:(NSData * _Nonnull)hmacKey
           completion:(AEEncryptionCompletion _Nonnull)completion
              failure:(AEEncryptionFailure _Nonnull)failure;

/**
 Tries to encrypt data using AEAD (AES in CBC mode with HMAC-SHA256 for integrity)
 with a user generated password

 @param plaintextData Plaintext data to encrypt. Cannot be nil.
 @param password      User generated password. Cannot be nil.
 @param completion    When encryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure       When encryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)aeEncryptData:(NSData * _Nonnull)plaintextData
             password:(NSString * _Nonnull)password
           completion:(AEEncryptionCompletion _Nonnull)completion
              failure:(AEEncryptionFailure _Nonnull)failure;

/**
 Tries to encrypt data using AEAD (AES in CBC mode with HMAC-SHA1 for integrity),
 is called `compatibility mode` because it uses HMAC-SHA1 like the RNCryptor library.
 The RNCryptor library uses HMAC-SHA1 because of "Broader availability. 
 Made the C# implementation much easier for example. Has no impact on security."
 https://twitter.com/cocoaphony/status/740541166173687813

 @param plaintextData Plaintext data to encrypt. Cannot be nil.
 @param password      User generated password. Cannot be nil.
 @param completion    When encryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure       When encryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)aeCompatibilityModeEncryptData:(NSData * _Nonnull)plaintextData
                              password:(NSString * _Nonnull)password
                            completion:(AEEncryptionCompletion _Nonnull)completion
                               failure:(AEEncryptionFailure _Nonnull)failure;

#pragma mark - Authenticated Encryption (RNCryptor Data Format v3.0)
#pragma mark - AE Encryption

/**
 Tries to decrypt data using AEAD (AES in CBC mode with HMAC-SHA256 for integrity). 
 The ciphertext needs to use the RNCryptor Data Format v3.
 It uses the encryption and integrity keys automatically generated and saved in
 the Keychain protected with User Generated Password and/or TouchID.

 @param cipherData Ciphertext using the RNCryptor Data Format v3.
 @param completion When decryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure    When decryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)aeDecryptData:(NSData * _Nonnull)cipherData
           completion:(AEDecryptionCompletion _Nonnull)completion
              failure:(AEDecryptionFailure _Nonnull)failure;

/**
 Tries to decrypt data using AEAD (AES in CBC mode with HMAC-SHA256 for integrity)
 using the provided AES and HMAC Keys

 @param cipherData   Ciphertext using the RNCryptor Data Format v3.
 @param symmetricKey AES encryption key (128, 256, 512 bits)
 @param hmacKey      HMAC key (128, 256 bits)
 @param completion   When decryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure      When decryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)aeDecryptData:(NSData * _Nonnull)cipherData
         symmetricKey:(NSData * _Nonnull)symmetricKey
              hmacKey:(NSData * _Nonnull)hmacKey
           completion:(AEDecryptionCompletion _Nonnull)completion
              failure:(AEDecryptionFailure _Nonnull)failure;

/**
 Tries to decrypt data using AEAD (AES in CBC mode with HMAC-SHA256 for integrity)
 with a user generated password

 @param cipherData Ciphertext using the RNCryptor Data Format v3.
 @param password   User generated password. Cannot be nil.
 @param completion When decryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure    When decryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)aeDecryptData:(NSData * _Nonnull)cipherData
             password:(NSString * _Nonnull)password
           completion:(AEDecryptionCompletion _Nonnull)completion
              failure:(AEDecryptionFailure _Nonnull)failure;

/**
 Tries to decrypt data using AEAD (AES in CBC mode with HMAC-SHA1 for integrity),
 is called `compatibility mode` because it uses HMAC-SHA1 like the RNCryptor library.
 The RNCryptor library uses HMAC-SHA1 because of "Broader availability.
 Made the C# implementation much easier for example. Has no impact on security."
 https://twitter.com/cocoaphony/status/740541166173687813

 @param cipherData Ciphertext using the RNCryptor Data Format v3.
 @param password   User generated password. Cannot be nil.
 @param completion When decryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure    When decryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)aeCompatibilityModeDecryptData:(NSData * _Nonnull)cipherData
                              password:(NSString * _Nonnull)password
                            completion:(AEDecryptionCompletion _Nonnull)completion
                               failure:(AEDecryptionFailure _Nonnull)failure;

#pragma mark - Symmetric Encryption (AES)

/**
 Tries to encrypt data using AES in CBC mode.
 It uses the encryption key automatically generated and saved in
 the Keychain protected with User Generated Password and/or TouchID.
 Note: This method provides no integrity.

 @param plaintextData Plaintext data to encrypt. Cannot be nil.
 @param completion    When encryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure       When encryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)encryptData:(NSData * _Nonnull)plaintextData
         completion:(SymmetricEncryptionCompletion _Nonnull)completion
            failure:(SymmetricEncryptionFailure _Nonnull)failure;

/**
 Tries to encrypt data using AES in CBC mode using the provided AES key.
 Note: This method provides no integrity.

 @param plaintextData Plaintext data to encrypt. Cannot be nil.
 @param keyData       AES encryption key (128, 256, 512 bits)
 @param completion    When encryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure       When encryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)encryptData:(NSData * _Nonnull)plaintextData
            withKey:(NSData * _Nonnull)keyData
         completion:(SymmetricEncryptionCompletion _Nonnull)completion
            failure:(SymmetricEncryptionFailure _Nonnull)failure;

/**
 Tries to encrypt data using AES in CBC mode deriving an AES key from the provided password.
 Note: This method provides no integrity.

 @param plaintextData Plaintext data to encrypt. Cannot be nil.
 @param password      User generated password. Cannot be nil.
 @param completion    When encryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure       When encryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)encryptData:(NSData * _Nonnull)plaintextData
       withPassword:(NSString * _Nonnull)password
         completion:(SymmetricEncryptionCompletion _Nonnull)completion
            failure:(SymmetricEncryptionFailure _Nonnull)failure;

#pragma mark - Symmetric Decryption (AES)

/**
 Tries to decrypt data using AES in CBC mode using the provided IV returned during encryption
 Note: This method provides no integrity.

 @param cipherData Ciphertext to decrypt. Cannot be nil.
 @param iv         IV returned during encryption for AES' CBC mode.
 @param completion When decryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure    When decryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)decryptData:(NSData * _Nonnull)cipherData
                 iv:(NSData * _Nonnull)iv
         completion:(SymmetricDecryptionCompletion _Nonnull)completion
            failure:(SymmetricDecryptionFailure _Nonnull)failure;

/**
 Tries to decrypt data using AES in CBC mode using the provided AES key and IV returned during encryption
 Note: This method provides no integrity.

 @param cipherData Ciphertext to decrypt. Cannot be nil.
 @param keyData    AES encryption key (128, 256, 512 bits)
 @param iv         IV returned during encryption for AES' CBC mode.
 @param completion When decryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure    When decryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)decryptData:(NSData * _Nonnull)cipherData
            withKey:(NSData * _Nonnull)keyData
                 iv:(NSData * _Nonnull)iv
         completion:(SymmetricDecryptionCompletion _Nonnull)completion
            failure:(SymmetricDecryptionFailure _Nonnull)failure;

/**
 Tries to decrypt data using AES in CBC mode deriving an AES key from the provided password,
 using the provided Salt and IV returned during encryption
 Note: This method provides no integrity.

 @param cipherData Ciphertext to decrypt. Cannot be nil.
 @param password   User generated password. Cannot be nil.
 @param iv         IV returned during encryption for AES' CBC mode.
 @param salt       Salt returned during encryption for key derivation (PBKDF2)
 @param completion When decryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure    When decryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)decryptData:(NSData * _Nonnull)cipherData
       withPassword:(NSString * _Nonnull)password
                 iv:(NSData * _Nonnull)iv
               salt:(NSData * _Nonnull)salt
         completion:(SymmetricDecryptionCompletion _Nonnull)completion
            failure:(SymmetricDecryptionFailure _Nonnull)failure;

#pragma mark - Asymmetric Encryption (RSA)

/**
 Tries to encrypt data using the RSA public key automatically generated and saved in
 the Keychain protected with User Generated Password and/or TouchID.

 @param plaintextData Plaintext data to encrypt. Cannot be nil.
 @param completion    When encryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure       When encryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)publicKeyEncryptData:(NSData * _Nonnull)plaintextData
                  completion:(AsymmetricEncryptionCompletion _Nonnull)completion
                     failure:(AsymmetricEncryptionFailure _Nonnull)failure;

/**
 Tries to encrypt data using the provided RSA public key.

 @param plaintextData Plaintext data to encrypt. Cannot be nil.
 @param publicKey     RSA Public key. Cannot be nil.
 @param completion    When encryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure       When encryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)publicKeyEncryptData:(NSData * _Nonnull)plaintextData
               withPublicKey:(SecKeyRef _Nonnull)publicKey
                  completion:(AsymmetricEncryptionCompletion _Nonnull)completion
                     failure:(AsymmetricEncryptionFailure _Nonnull)failure;

#pragma mark - Asymmetric Decryption (RSA)

/**
 Tries to decrypt data using the RSA private key automatically generated and saved in
 the Keychain protected with User Generated Password and/or TouchID.

 @param cipherData Ciphertext to decrypt. Cannot be nil.
 @param completion When decryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure    When decryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)privateKeyDecryptData:(NSData * _Nonnull)cipherData
                   completion:(AsymmetricDecryptionCompletion _Nonnull)completion
                      failure:(AsymmetricDecryptionFailure _Nonnull)failure;

/**
 Tries to decrypt data using the provided RSA private key.

 @param cipherData Ciphertext to decrypt. Cannot be nil.
 @param privateKey RSA Private key. Cannot be nil.
 @param completion When decryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure    When decryption fails this failure block is executed. See IRPublicConstants.hs
*/
- (void)privateKeyDecryptData:(NSData * _Nonnull)cipherData
               withPrivateKey:(SecKeyRef _Nonnull)privateKey
                   completion:(AsymmetricDecryptionCompletion _Nonnull)completion
                      failure:(AsymmetricDecryptionFailure _Nonnull)failure;

#pragma mark - Data Integrity (HMAC)

/**
 Provides data integrity using HMAC-SHA256, it uses the HMAC key automatically generated
 and saved in the Keychain protected with User Generated Password and/or TouchID.

 @param data       Data to HMAC
 @param completion When HMAC succeeds this completion block is executed. See IRPublicConstants.h
 @param failure    When HMAC fails this failure block is executed. See IRPublicConstants.hs
*/
- (void)hmacData:(NSData * _Nonnull)data
      completion:(HMACCompletion _Nonnull)completion
         failure:(HMACFailure _Nonnull)failure;

/**
 Provides data integrity using HMAC-SHA256 with the provided HMAC key.

 @param data       Data to HMAC
 @param key        HMAC key
 @param completion When HMAC succeeds this completion block is executed. See IRPublicConstants.h
 @param failure    When HMAC fails this failure block is executed. See IRPublicConstants.hs
*/
- (void)hmacData:(NSData * _Nonnull)data
         withKey:(NSData * _Nonnull)key
      completion:(HMACCompletion _Nonnull)completion
         failure:(HMACFailure _Nonnull)failure;

#pragma mark - Hashing

/**
 Hashes the data using SHA256

 @param dataToHash Data to Hash

 @return SHA256 digest of the data
*/
- (NSData * _Nonnull)hashData:(NSData * _Nonnull)dataToHash;

#pragma mark - Key Generation

/**
 Generates a cryptographically secure AES key of the provided length.

 @param length Size in bytes of the AES key

 @return NSData representing an AES key of length `length`
*/
- (NSData * _Nonnull)randomAESEncryptionKeyOfLength:(NSUInteger)length;

/**
 Generates a cryptographically secure HMAC key of the provided length.

 @param length Size in bytes of the HMAC key

 @return NSData representing an HMAC key of length `length`
*/
- (NSData * _Nonnull)randomHMACKeyOfLength:(NSUInteger)length;

/**
 Generates a cryptographically secure AES key using PBKDF2 with 10,000 rounds,
 See IRPublicConstants.h for return values. 
 Note: The completion block is NOT executed in the main thread.

 @param password   User generated password. Cannot be nil.
 @param length     Size in bytes of the AES key
 @param completion Completion block returning the AES key. See IRPublicConstants.h
 */
- (void)keyFromPassword:(NSString * _Nonnull)password
               ofLength:(NSUInteger)length
             completion:(KeyDerivationCompletion _Nonnull)completion;

@end
