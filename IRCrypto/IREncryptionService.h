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

typedef void (^keyPairBlock)(SecKeyRef publicKey, SecKeyRef privateKey);

@interface IREncryptionService : NSObject

#pragma mark - Key Generation
- (BOOL)generateRSAKeyPair:(keyPairBlock)completion;
- (BOOL)generateECKeyPair:(keyPairBlock)completion;
- (BOOL)generateSigningKeyPairInSecureEnclave;
- (NSData *)generateAESEncryptionKeyOfLength:(NSUInteger)length;
- (NSData *)generateHMACKeyOfLength:(NSUInteger)length;

#pragma mark - Key Deletion
- (BOOL)deleteSigningKeyPairInSecureEnclave;

#pragma mark - Signing
- (NSData *)signData:(NSData *)plainData userPromptReason:(NSString *)reason;

#pragma mark - Key Derivation
- (NSData *)keyFromString:(NSString *)string salt:(NSData *)salt keySize:(NSUInteger)keySize;
- (NSData *)keyFromData:(NSData *)rawData salt:(NSData *)salt keySize:(NSUInteger)keySize;
- (NSData *)keyFromStringUsingSHA1:(NSString *)string salt:(NSData *)salt keySize:(NSUInteger)keySize;

#pragma mark - Hashing
- (NSData *)hashData:(NSData *)dataToHash;

#pragma mark - Random Data Generation
- (NSData *)randomBytesOfLength:(NSUInteger)length;

#pragma mark - Data Integrity (HMAC)
- (NSData *)hmacData:(NSData *)cipherData withKey:(NSData *)key;

#pragma mark - Symmetric Encryption (AES)
- (NSData *)encryptData:(NSData *)plainTextData withKey:(NSData *)key iv:(NSData **)iv;
- (NSData *)decryptData:(NSData *)cipherData withKey:(NSData *)key iv:(NSData *)iv;

#pragma mark - Asymmetric Encryption (RSA)
- (NSData *)encryptData:(NSData *)plainTextData publicKey:(SecKeyRef)publicKey;
- (NSData *)decryptData:(NSData *)cipherData privateKey:(SecKeyRef)privateKey;

@end