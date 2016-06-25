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

@interface IRPublicConstants : NSObject

//Blocks
typedef void (^SymmetricEncryptionCompletion)(NSData * _Nonnull cipherData, NSData * _Nonnull iv, NSData * _Nullable salt);
typedef void (^SymmetricEncryptionFailure)(NSError * _Nonnull error);

typedef void (^SymmetricDecryptionCompletion)(NSData * _Nonnull decryptedData);
typedef void (^SymmetricDecryptionFailure)(NSError * _Nonnull error);

typedef void (^AsymmetricEncryptionCompletion)(NSData * _Nonnull cipherData);
typedef void (^AsymmetricEncryptionFailure)(NSError * _Nonnull error);

typedef void (^AsymmetricDecryptionCompletion)(NSData * _Nonnull decryptedData);
typedef void (^AsymmetricDecryptionFailure)(NSError * _Nonnull error);

typedef void (^AEEncryptionCompletion)(NSData * _Nonnull cipherData, NSData * _Nonnull iv, NSData * _Nullable encryptionSalt, NSData * _Nullable hmacSalt);
typedef void (^AEEncryptionFailure)(NSError * _Nonnull error);

typedef void (^AEDecryptionCompletion)(NSData * _Nonnull decryptedData);
typedef void (^AEDecryptionFailure)(NSError * _Nonnull error);

//Option Keys
FOUNDATION_EXTERN NSString * _Nonnull const kIREncryptionOptionsKey;
FOUNDATION_EXTERN NSString * _Nonnull const kIRAsymmetricEncryptionAlgorithmKey;
FOUNDATION_EXTERN NSString * _Nonnull const kIRSigningKeysKey;

FOUNDATION_EXTERN NSString * _Nonnull const kIRAsymmetricEncryptionProtectionKey;
FOUNDATION_EXTERN NSString * _Nonnull const kIRSymmetricEncryptionProtectionKey;
FOUNDATION_EXTERN NSString * _Nonnull const kIRHMACProtectionKey;

FOUNDATION_EXTERN NSString * _Nonnull const kIRAsymmetricEncryptionProtectionReasonKey;
FOUNDATION_EXTERN NSString * _Nonnull const kIRSymmetricEncryptionProtectionReasonKey;
FOUNDATION_EXTERN NSString * _Nonnull const kIRHMACProtectionReasonKey;

FOUNDATION_EXTERN NSString * _Nonnull const kIRSymmetricEncryptionKeySizeKey;
FOUNDATION_EXTERN NSString * _Nonnull const kIRHMACKeySizeKey;

//Enums
typedef NS_ENUM(NSUInteger, kEncryptionOptions) {
    kEncryptionOptionsNone = 1
};

typedef NS_ENUM(NSUInteger, kIRAsymmetricEncryptionAlgorithm) {
    kIRAsymmetricEncryptionRSA,
    kIRAsymmetricEncryptionEC
};

typedef NS_ENUM(NSUInteger, kIRSigningKeys) {
    kIRSigningKeysNone,
    kIRSigningKeysRSA
};

typedef NS_OPTIONS(NSUInteger, kIRKeyProtection) {
    kIRKeyProtectionTouchID = 0,
    kIRKeyProtectionPassword = 1 << 0
};

typedef NS_ENUM(NSUInteger, AttributeService) {
    kAttributeServiceSymmetricKey,
    kAttributeServicePublicKey,
    kAttributeServicePrivateKey,
    kAttributeServiceHMACKey
};

@end