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

#pragma mark - Blocks

/*
 Name: AEEncryptionCompletion
 Type: Block
 Return type: void
 Parameters:
 [*] NSData _Nonnull cipherData: Cipher data returned from AEAD encryption
 [*] NSData _Nonnull iv: Initialization Vector used in the AEAD encryption
 [*] NSData _Nullable encryptionSalt: Only returned when AEAD encryption uses a password (instead of a key)
 [*] NSData _Nullable hmacSalt: Only returned when AEAD encryption uses a password (instead of a key)
*/
typedef void (^AEEncryptionCompletion)(NSData * _Nonnull cipherData, NSData * _Nonnull iv, NSData * _Nullable encryptionSalt, NSData * _Nullable hmacSalt);

/*
 Name: AEEncryptionFailure
 Type: Block
 Return type: void
 Parameters:
 [*] NSError _Nonnull error: Error returned from AEAD encryption
*/
typedef void (^AEEncryptionFailure)(NSError * _Nonnull error);

/*
 Name: AEDecryptionCompletion
 Type: Block
 Return type: void
 Parameters:
 [*] NSData _Nonnull decryptedData: Plaintext data returned from AEAD decryption
*/
typedef void (^AEDecryptionCompletion)(NSData * _Nonnull decryptedData);

/*
 Name: AEDecryptionFailure
 Type: Block
 Return type: void
 Parameters:
 [*] NSError _Nonnull error: Error returned from AEAD decryption
*/
typedef void (^AEDecryptionFailure)(NSError * _Nonnull error);

/*
 Name: SymmetricEncryptionCompletion
 Type: Block
 Return type: void
 Parameters:
    [*] NSData _Nonnull cipherData: Cipher data returned from symmetric encryption
    [*] NSData _Nonnull iv: Initialization Vector used in the symmetric encryption
    [*] NSData _Nullable salt: Salt returned only when symmetric encryption uses a password (instead of a key)
*/
typedef void (^SymmetricEncryptionCompletion)(NSData * _Nonnull cipherData, NSData * _Nonnull iv, NSData * _Nullable salt);

/*
 Name: SymmetricEncryptionFailure
 Type: Block
 Return type: void
 Parameters:
 [*] NSError _Nonnull error: Error returned from symmetric encryption
*/
typedef void (^SymmetricEncryptionFailure)(NSError * _Nonnull error);

/*
 Name: SymmetricDecryptionCompletion
 Type: Block
 Return type: void
 Parameters:
 [*] NSData _Nonnull decryptedData: Plaintext data returned from symmetric decryption
*/
typedef void (^SymmetricDecryptionCompletion)(NSData * _Nonnull decryptedData);

/*
 Name: SymmetricDecryptionFailure
 Type: Block
 Return type: void
 Parameters:
 [*] NSError _Nonnull error: Error returned from symmetric decryption
*/
typedef void (^SymmetricDecryptionFailure)(NSError * _Nonnull error);

/*
 Name: AsymmetricEncryptionCompletion
 Type: Block
 Return type: void
 Parameters:
 [*] NSData _Nonnull cipherData: Cipher data returned from asymmetric encryption
*/
typedef void (^AsymmetricEncryptionCompletion)(NSData * _Nonnull cipherData);

/*
 Name: AsymmetricEncryptionFailure
 Type: Block
 Return type: void
 Parameters:
 [*] NSError _Nonnull error: Error returned from asymmetric encryption
*/
typedef void (^AsymmetricEncryptionFailure)(NSError * _Nonnull error);

/*
 Name: AsymmetricDecryptionCompletion
 Type: Block
 Return type: void
 Parameters:
 [*] NSData _Nonnull decryptedData: Plaintext data returned from asymmetric decryption
*/
typedef void (^AsymmetricDecryptionCompletion)(NSData * _Nonnull decryptedData);

/*
 Name: AsymmetricDecryptionFailure
 Type: Block
 Return type: void
 Parameters:
 [*] NSError _Nonnull error: Error returned from asymmetric decryption
*/
typedef void (^AsymmetricDecryptionFailure)(NSError * _Nonnull error);

/*
 Name: HMACCompletion
 Type: Block
 Return type: void
 Parameters:
 [*] NSData _Nonnull hmacData: HMAC data
*/
typedef void (^HMACCompletion)(NSData * _Nonnull hmacData);

/*
 Name: HMACFailure
 Type: Block
 Return type: void
 Parameters:
 [*] NSError _Nonnull error: Error returned from HMAC
*/
typedef void (^HMACFailure)(NSError * _Nonnull error);

/*
 Name: KeyDerivationCompletion
 Type: Block
 Return type: void
 Parameters:
 [*] NSData _Nonnull key: Derived key using PBKDF2 with 10,000 rounds
 [*] NSData _Nonnull salt: Salt usded to derive the key
*/
typedef void (^KeyDerivationCompletion)(NSData * _Nonnull key, NSData * _Nonnull salt);

//----------------------------------------------------------------------------------

#pragma mark - Option Keys

/*
 Name: kIREncryptionOptionsKey
 Descryption: Enable/Disable default encryption options. See kEncryptionOptions.
 Default: nil
*/
FOUNDATION_EXTERN NSString * _Nonnull const kIREncryptionOptionsKey;

/*
 Name: kIRAsymmetricEncryptionAlgorithmKey
 Descryption: Specifies the Asymmetric Encryption Algorithm. See kIRAsymmetricEncryptionAlgorithm.
 Default: kIRAsymmetricEncryptionRSA
*/
FOUNDATION_EXTERN NSString * _Nonnull const kIRAsymmetricEncryptionAlgorithmKey;

/*
 Name: kIRSigningKeysKey
 Descryption: Specifies the type of Signing Keys. See kIRSigningKeys.
 Default: kIRSigningKeysRSA
*/
FOUNDATION_EXTERN NSString * _Nonnull const kIRSigningKeysKey;

/*
 Name: kIRAsymmetricEncryptionProtectionKey
 Descryption: Specifies the type of protection used to save Asymmetric Keys
 on the Keychain. See kIRKeyProtection.
 Default: kIRKeyProtectionTouchID
*/
FOUNDATION_EXTERN NSString * _Nonnull const kIRAsymmetricEncryptionProtectionKey;

/*
 Name: kIRSymmetricEncryptionProtectionKey
 Descryption: Specifies the type of protection used to save Symmetric Keys
 on the Keychain. See kIRKeyProtection.
 Default: kIRKeyProtectionTouchID
*/
FOUNDATION_EXTERN NSString * _Nonnull const kIRSymmetricEncryptionProtectionKey;

/*
 Name: kIRHMACProtectionKey
 Descryption: Specifies the type of protection used to save HMAC Keys
 on the Keychain. See kIRKeyProtection.
 Default: kIRKeyProtectionTouchID
*/
FOUNDATION_EXTERN NSString * _Nonnull const kIRHMACProtectionKey;

/*
 Name: kIRAsymmetricEncryptionProtectionReasonKey
 Descryption: Specifies the text shown to the user as a reason for asking for TouchID
 or a password to load Asymmetric Keys from the Keychain. This could be any String.
 Default: @"This is necessary to protect your data"
*/
FOUNDATION_EXTERN NSString * _Nonnull const kIRAsymmetricEncryptionProtectionReasonKey;

/*
 Name: kIRSymmetricEncryptionProtectionReasonKey
 Descryption: Specifies the text shown to the user as a reason for asking for TouchID
 or a password to load Symmetric Keys from the Keychain. This could be any String.
 Default: @"This is necessary to protect your data"
*/
FOUNDATION_EXTERN NSString * _Nonnull const kIRSymmetricEncryptionProtectionReasonKey;

/*
 Name: kIRHMACProtectionReasonKey
 Descryption: Specifies the text shown to the user as a reason for asking for TouchID
 or a password to load HMAC Keys from the Keychain. This could be any String.
 Default: @"This is necessary to protect your data"
*/
FOUNDATION_EXTERN NSString * _Nonnull const kIRHMACProtectionReasonKey;

/*
 Name: kIRSymmetricEncryptionKeySizeKey
 Descryption: Specifies the size in bytes of the Symmetric Encryption Key.
 Default: 32 bytes
*/
FOUNDATION_EXTERN NSString * _Nonnull const kIRSymmetricEncryptionKeySizeKey;

/*
 Name: kIRHMACKeySizeKey
 Descryption: Specifies the size in bytes of the HMAC Key.
 Default: 32 bytes
*/
FOUNDATION_EXTERN NSString * _Nonnull const kIRHMACKeySizeKey;

/*
 Name: kIRAppPasswordKey
 Descryption: Specifies Application Password to protect keys on the Keychain.
 MUST be present if TouchID is not supported.
 Default: nil
*/
FOUNDATION_EXTERN NSString * _Nonnull const kIRAppPasswordKey;

//----------------------------------------------------------------------------------

#pragma mark - Enums

/*
 Name: kEncryptionOptions
 Options:
    [*] kEncryptionOptionsNone: Doesn't generate any keys
*/
typedef NS_ENUM(NSUInteger, kEncryptionOptions) {
    kEncryptionOptionsNone = 1
};

/*
 Name: kIRAsymmetricEncryptionAlgorithm
 Options:
 [*] kIRAsymmetricEncryptionRSA: Uses RSA asymmetric keys for encryption
 [*] kIRAsymmetricEncryptionEC: Uses Elliptic Curve (Curve25519) asymmetric keys for encryption
*/
typedef NS_ENUM(NSUInteger, kIRAsymmetricEncryptionAlgorithm) {
    kIRAsymmetricEncryptionRSA,
    kIRAsymmetricEncryptionEC
};

/*
 Name: kIRSigningKeys
 Options:
 [*] kIRSigningKeysNone: Doesn't generate signing keys
 [*] kIRSigningKeysRSA: Uses RSA asymmetric keys for signing
*/
typedef NS_ENUM(NSUInteger, kIRSigningKeys) {
    kIRSigningKeysNone,
    kIRSigningKeysRSA
};

/*
 Name: kIRKeyProtection
 Options:
 [*] kIRKeyProtectionTouchID: Protect keys with TouchID on Keychain
 [*] kIRKeyProtectionPassword: Protect keys with Application Password on Keychain
*/
typedef NS_OPTIONS(NSUInteger, kIRKeyProtection) {
    kIRKeyProtectionTouchID = 0,
    kIRKeyProtectionPassword = 1 << 0
};

/*
 Name: AttributeService
 Options:
 [*] kAttributeServiceSymmetricKey: Keychain Attribute for Symmetric Keys
 [*] kAttributeServicePublicKey: Keychain Attribute for Public Keys
 [*] kAttributeServicePrivateKey: Keychain Attribute for Private Keys
 [*] kAttributeServiceHMACKey: Keychain Attribute for HMAC Keys
*/
typedef NS_ENUM(NSUInteger, AttributeService) {
    kAttributeServiceSymmetricKey,
    kAttributeServicePublicKey,
    kAttributeServicePrivateKey,
    kAttributeServiceHMACKey
};

@end
