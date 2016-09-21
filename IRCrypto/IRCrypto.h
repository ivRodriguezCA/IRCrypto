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
 Tries to encrypt data using AEAD (AES in CBC mode with HMAC for integrity). The ciphertext
 returned in the completion block uses the RNCryptor Data Format v3.

 @param plaintextData Plaintext data to encrypt. Cannot be nil.
 @param completion    When encryption succeeds this completion block is executed. See IRPublicConstants.h
 @param failure       When encryption fails this failure block is executed. See IRPublicConstants.h
*/
- (void)aeEncryptData:(NSData * _Nonnull)plaintextData
           completion:(AEEncryptionCompletion _Nonnull)completion
              failure:(AEEncryptionFailure _Nonnull)failure;


/**
 Tries to encrypt data using AEAD (AES in CBC mode with HMAC for integrity)
 with custom AES and HMAC Keys

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

- (void)aeEncryptData:(NSData * _Nonnull)plaintextData
             password:(NSString * _Nonnull)password
           completion:(AEEncryptionCompletion _Nonnull)completion
              failure:(AEEncryptionFailure _Nonnull)failure;

- (void)aeCompatibilityModeEncryptData:(NSData * _Nonnull)plaintextData
                              password:(NSString * _Nonnull)password
                            completion:(AEEncryptionCompletion _Nonnull)completion
                               failure:(AEEncryptionFailure _Nonnull)failure;

#pragma mark - Authenticated Encryption (RNCryptor Data Format v3.0)
#pragma mark - AE Encryption

- (void)aeDecryptData:(NSData * _Nonnull)cipherData
           completion:(AEDecryptionCompletion _Nonnull)completion
              failure:(AEDecryptionFailure _Nonnull)failure;

- (void)aeDecryptData:(NSData * _Nonnull)cipherData
         symmetricKey:(NSData * _Nonnull)symmetricKey
              hmacKey:(NSData * _Nonnull)hmacKey
           completion:(AEDecryptionCompletion _Nonnull)completion
              failure:(AEDecryptionFailure _Nonnull)failure;

- (void)aeDecryptData:(NSData * _Nonnull)cipherData
             password:(NSString * _Nonnull)password
           completion:(AEDecryptionCompletion _Nonnull)completion
              failure:(AEDecryptionFailure _Nonnull)failure;

- (void)aeCompatibilityModeDecryptData:(NSData * _Nonnull)cipherData
                              password:(NSString * _Nonnull)password
                            completion:(AEDecryptionCompletion _Nonnull)completion
                               failure:(AEDecryptionFailure _Nonnull)failure;

#pragma mark - Symmetric Encryption (AES)

- (void)encryptData:(NSData * _Nonnull)plaintextData
         completion:(SymmetricEncryptionCompletion _Nonnull)completion
            failure:(SymmetricEncryptionFailure _Nonnull)failure;

- (void)encryptData:(NSData * _Nonnull)plaintextData
            withKey:(NSData * _Nonnull)keyData
         completion:(SymmetricEncryptionCompletion _Nonnull)completion
            failure:(SymmetricEncryptionFailure _Nonnull)failure;

- (void)encryptData:(NSData * _Nonnull)plaintextData
       withPassword:(NSString * _Nonnull)password
         completion:(SymmetricEncryptionCompletion _Nonnull)completion
            failure:(SymmetricEncryptionFailure _Nonnull)failure;

#pragma mark - Symmetric Decryption (AES)

- (void)decryptData:(NSData * _Nonnull)cipherData
                 iv:(NSData * _Nonnull)iv
         completion:(SymmetricDecryptionCompletion _Nonnull)completion
            failure:(SymmetricDecryptionFailure _Nonnull)failure;

- (void)decryptData:(NSData * _Nonnull)cipherData
            withKey:(NSData * _Nonnull)keyData
                 iv:(NSData * _Nonnull)iv
         completion:(SymmetricDecryptionCompletion _Nonnull)completion
            failure:(SymmetricDecryptionFailure _Nonnull)failure;

- (void)decryptData:(NSData * _Nonnull)cipherData
       withPassword:(NSString * _Nonnull)password
                 iv:(NSData * _Nonnull)iv
               salt:(NSData * _Nonnull)salt
         completion:(SymmetricDecryptionCompletion _Nonnull)completion
            failure:(SymmetricDecryptionFailure _Nonnull)failure;

#pragma mark - Asymmetric Encryption (RSA)

- (void)publicKeyEncryptData:(NSData * _Nonnull)plaintextData
                  completion:(AsymmetricEncryptionCompletion _Nonnull)completion
                     failure:(AsymmetricEncryptionFailure _Nonnull)failure;

- (void)publicKeyEncryptData:(NSData * _Nonnull)plaintextData
               withPublicKey:(SecKeyRef _Nonnull)publicKey
                  completion:(AsymmetricEncryptionCompletion _Nonnull)completion
                     failure:(AsymmetricEncryptionFailure _Nonnull)failure;

#pragma mark - Asymmetric Decryption (RSA)

- (void)privateKeyDecryptData:(NSData * _Nonnull)cipherData
                   completion:(AsymmetricDecryptionCompletion _Nonnull)completion
                      failure:(AsymmetricDecryptionFailure _Nonnull)failure;

- (void)privateKeyDecryptData:(NSData * _Nonnull)cipherData
               withPrivateKey:(SecKeyRef _Nonnull)privateKey
                   completion:(AsymmetricDecryptionCompletion _Nonnull)completion
                      failure:(AsymmetricDecryptionFailure _Nonnull)failure;

#pragma mark - Key Generation

- (NSData * _Nonnull)randomAESEncryptionKeyOfLength:(NSUInteger)length;
- (NSData * _Nonnull)randomHMACKeyOfLength:(NSUInteger)length;
- (void)keyFromPassword:(NSString * _Nonnull)password
               ofLength:(NSUInteger)length
             completion:(KeyDerivationCompletion _Nonnull)completion;

@end
