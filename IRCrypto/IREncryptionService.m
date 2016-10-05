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

#import "IREncryptionService.h"
#import <CommonCrypto/CommonCrypto.h>
#import "IRConstants.h"

@implementation IREncryptionService

#pragma mark - Key Generation

- (BOOL)generateRSAKeyPair:(keyPairBlock)completion {
    NSDictionary *parameters = @{
                                 (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                                 (__bridge id)kSecAttrKeySizeInBits: @2048,
                                 (__bridge id)kSecPrivateKeyAttrs: @{
                                         (__bridge id)kSecAttrIsPermanent: @NO
                                         },
                                 (__bridge id)kSecPublicKeyAttrs: @{
                                         (__bridge id)kSecAttrIsPermanent: @NO
                                         }
                                 };
    
    SecKeyRef publicKey, privateKey;
    OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
    
    if (status == errSecSuccess) {
        if (completion) {
            completion(publicKey, privateKey);
        }
        
        CFRelease(publicKey);
        CFRelease(privateKey);
        return YES;
    }
    
    return NO;
}

- (BOOL)generateECKeyPair:(keyPairBlock)completion {
    NSDictionary *parameters = @{
                             (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
                             (__bridge id)kSecAttrKeySizeInBits: @256,
                             (__bridge id)kSecPrivateKeyAttrs: @{
                                     (__bridge id)kSecAttrIsPermanent: @NO
                                     },
                             (__bridge id)kSecPublicKeyAttrs: @{
                                     (__bridge id)kSecAttrIsPermanent: @NO
                                     }
                             };
    
    SecKeyRef publicKey, privateKey;
    OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
    
    if (status == errSecSuccess) {
        if (completion) {
            completion(publicKey, privateKey);
        }
        
        CFRelease(publicKey);
        CFRelease(privateKey);
        return YES;
    }
    
    return NO;
}

- (BOOL)generateSigningKeyPairInSecureEnclave {
    CFErrorRef error = NULL;
    SecAccessControlRef secACL = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                 kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                 kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage,
                                                                 &error);
    
    NSDictionary *parameters = @{
                                 (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
                                 (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
                                 (__bridge id)kSecAttrKeySizeInBits: @256,
                                 (__bridge id)kSecPrivateKeyAttrs: @{
                                         (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)secACL,
                                         (__bridge id)kSecAttrIsPermanent: @YES,
                                         (__bridge id)kSecAttrLabel: kSigningPairLabel,
                                         },
                                 };
    
    SecKeyRef publicKey, privateKey;
    OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
    
    if (status == errSecSuccess) {
        
        CFRelease(privateKey);
        CFRelease(publicKey);
        return YES;
    }
    
    return NO;
}

- (NSData *)generateAESEncryptionKeyOfLength:(NSUInteger)length {
    return [self generateRandomKeyOfLength:length];
}

- (NSData *)generateHMACKeyOfLength:(NSUInteger)length {
    return [self generateRandomKeyOfLength:length];
}

- (NSData *)generateRandomKeyOfLength:(NSUInteger)length {
    NSData *randomData = [self randomBytesOfLength:length];
    NSData *salt = [self randomBytesOfLength:length];
    return [self keyFromData:randomData salt:salt keySize:length];
}

#pragma mark - Key Deletion

- (BOOL)deleteSigningKeyPairInSecureEnclave {
    NSDictionary *query = @{
                            (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                            (__bridge id)kSecAttrLabel: kSigningPairLabel,
                            (__bridge id)kSecReturnRef: @YES,
                            };
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status == errSecSuccess) {
        return YES;
    }
    
    return NO;
}

#pragma mark - Signing

- (NSData *)signData:(NSData *)plainData userPromptReason:(NSString *)reason {
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
                            (__bridge id)kSecAttrLabel: kSigningPairLabel,
                            (__bridge id)kSecReturnRef: @YES,
                            (__bridge id)kSecUseOperationPrompt: reason
                            };
    
    SecKeyRef privateKey;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);
    
    if (status == errSecSuccess) {
        uint8_t signature[SecKeyGetBlockSize(privateKey)];
        size_t signatureLength = sizeof(signature);
        NSData *digestData = [self hashData:plainData];
        
        status = SecKeyRawSign(privateKey,
                               kSecPaddingPKCS1,
                               digestData.bytes,
                               digestData.length,
                               signature,
                               &signatureLength);
        
        if (status == errSecSuccess) {
            return [NSData dataWithBytes:signature length:signatureLength];
        }
        
        CFRelease(privateKey);
    }
    
    return nil;
}

#pragma mark - Key Derivation

- (NSData *)keyFromString:(NSString *)string salt:(NSData *)salt keySize:(NSUInteger)keySize {
    return [self keyFromData:[string dataUsingEncoding:NSUTF8StringEncoding] salt:salt keySize:keySize];
}

- (NSData *)keyFromData:(NSData *)rawData salt:(NSData *)salt keySize:(NSUInteger)keySize {
    uint rounds  = 10000;
    NSMutableData *derivedKey = [NSMutableData dataWithLength:keySize];
    CCKeyDerivationPBKDF(kCCPBKDF2,
                         rawData.bytes,
                         rawData.length,
                         salt.bytes,
                         salt.length,
                         kCCPRFHmacAlgSHA256,
                         rounds,
                         derivedKey.mutableBytes,
                         derivedKey.length);
    return derivedKey;
}

- (NSData *)keyFromStringUsingSHA1:(NSString *)string salt:(NSData *)salt keySize:(NSUInteger)keySize {
    NSData *rawData = [string dataUsingEncoding:NSUTF8StringEncoding];
    uint rounds  = 10000;
    NSMutableData *derivedKey = [NSMutableData dataWithLength:keySize];
    CCKeyDerivationPBKDF(kCCPBKDF2,
                         rawData.bytes,
                         rawData.length,
                         salt.bytes,
                         salt.length,
                         kCCPRFHmacAlgSHA1,
                         rounds,
                         derivedKey.mutableBytes,
                         derivedKey.length);
    return derivedKey;
}

#pragma mark - Hashing

- (NSData *)hashData:(NSData *)dataToHash {
    uint8_t digestData[CC_SHA256_DIGEST_LENGTH];
    size_t digestLength = sizeof(digestData);
    
    CC_SHA256(dataToHash.bytes,
              (CC_LONG)dataToHash.length,
              digestData);
    
    return [NSData dataWithBytes:digestData length:digestLength];
}

#pragma mark - Random Data Generation

- (NSData *)randomBytesOfLength:(NSUInteger)length {
    NSMutableData *randomBytes = [NSMutableData dataWithLength:length];
    
    __unused uint result = SecRandomCopyBytes(kSecRandomDefault,
                                              length,
                                              randomBytes.mutableBytes);
    return [randomBytes copy];
}

#pragma mark - Data Integrity (HMAC)

- (NSData *)hmacData:(NSData *)cipherData withKey:(NSData *)key {
    NSMutableData *hmacData = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256,
           key.bytes,
           key.length,
           cipherData.bytes,
           cipherData.length,
           hmacData.mutableBytes);
    
    memset((void *)key.bytes, 0, key.length);
    *(volatile char*)key.bytes = *(volatile char*)key.bytes;
    
    return [hmacData copy];
}

#pragma mark - Symmetric Encryption (AES)

- (NSData *)encryptData:(NSData *)plainTextData withKey:(NSData *)key iv:(NSData **)iv {
    size_t cipherLength = 0;
    NSMutableData *cipherData = [NSMutableData dataWithLength:plainTextData.length + kCCBlockSizeAES128];
    [cipherData resetBytesInRange:NSMakeRange(0, cipherData.length)];
    *iv = [self randomBytesOfLength:kCCBlockSizeAES128];

    OSStatus status = CCCrypt(kCCEncrypt,
                              kCCAlgorithmAES128,
                              kCCOptionPKCS7Padding,
                              key.bytes,
                              key.length,
                              (*iv).bytes,
                              plainTextData.bytes,
                              plainTextData.length,
                              cipherData.mutableBytes,
                              cipherData.length,
                              &cipherLength);
    
    memset((void *)key.bytes, 0, key.length);
    *(volatile char*)key.bytes = *(volatile char*)key.bytes;
    
    if (status == errSecSuccess) {
        return [cipherData subdataWithRange:NSMakeRange(0, cipherLength)];
    }
    
    return nil;
}

- (NSData *)decryptData:(NSData *)cipherData withKey:(NSData *)key iv:(NSData *)iv {
    size_t plainTextLength = 0;
    NSMutableData *plainTextData = [NSMutableData dataWithLength:cipherData.length];
    [plainTextData resetBytesInRange:NSMakeRange(0, plainTextData.length)];
    
    OSStatus status = CCCrypt(kCCDecrypt,
                              kCCAlgorithmAES128,
                              kCCOptionPKCS7Padding,
                              key.bytes,
                              key.length,
                              iv.bytes,
                              cipherData.bytes,
                              cipherData.length,
                              plainTextData.mutableBytes,
                              plainTextData.length,
                              &plainTextLength);
    
    memset((void *)key.bytes, 0, key.length);
    *(volatile char*)key.bytes = *(volatile char*)key.bytes;
    
    if (status == errSecSuccess) {
        return [plainTextData subdataWithRange:NSMakeRange(0, plainTextLength)];
    }
    
    return nil;
}

#pragma mark - Asymmetric Encryption (RSA)

- (NSData *)encryptData:(NSData *)plainTextData publicKey:(SecKeyRef)publicKey {
    size_t cipherLength = SecKeyGetBlockSize(publicKey);
    NSMutableData *cipherData = [NSMutableData dataWithLength:cipherLength];
    [cipherData resetBytesInRange:NSMakeRange(0, cipherData.length)];
    
    OSStatus status = SecKeyEncrypt(publicKey,
                                    kSecPaddingPKCS1,
                                    plainTextData.bytes,
                                    plainTextData.length,
                                    cipherData.mutableBytes,
                                    &cipherLength);
    
    if (status == errSecSuccess) {
        return [cipherData subdataWithRange:NSMakeRange(0, cipherLength)];
    }
    
    return nil;
}

- (NSData *)decryptData:(NSData *)cipherData privateKey:(SecKeyRef)privateKey {
    size_t plainTextLength = SecKeyGetBlockSize(privateKey);
    NSMutableData *plainTextData = [NSMutableData dataWithLength:plainTextLength];
    [plainTextData resetBytesInRange:NSMakeRange(0, plainTextData.length)];
    
    OSStatus status = SecKeyDecrypt(privateKey,
                                    kSecPaddingPKCS1,
                                    cipherData.bytes,
                                    cipherData.length,
                                    plainTextData.mutableBytes,
                                    &plainTextLength);
    
    if (status == errSecSuccess) {
        return [plainTextData subdataWithRange:NSMakeRange(0, plainTextLength)];
    }
    
    return nil;
}

@end
