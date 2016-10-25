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

#import "IRCrypto.h"
#import "IRKeychainService.h"
#import "IREncryptionService.h"
#import "IRErrorProvider.h"

#define isOptionEqualToValue(option, value) (((option) & (value)) == (value))

static size_t const kIVSizeAES128 = 16;
static size_t const kPBKDF2SaltSize = 16;
static size_t const kIRSymmetricEncryptionDefaultKeySize = 32;
static size_t const kIRHMACDefaultKeySize = 32;
static size_t const kIRSymmetricEncryptionDefaultSaltSize = 8;
static size_t const kIRHMACDefaultSaltSize = 8;

@interface IRAEMessageModel : NSObject

@property (nonatomic, strong, readonly) NSData *dataValue;
@property (nonatomic, assign, readonly) NSUInteger primitiveValue;

- (instancetype)initWithDataValue:(NSData *)data
                   primitiveValue:(NSUInteger)primitive;

@end

@implementation IRAEMessageModel

- (instancetype)initWithDataValue:(NSData *)data
                   primitiveValue:(NSUInteger)primitive {
    if (self == [super init]) {
        _dataValue = data;
        _primitiveValue = primitive;
    }
    
    return self;
}

- (NSString *)hexadecimalString:(NSData *)data {
    const unsigned char *dataBuffer = (const unsigned char *)data.bytes;
    
    if (!dataBuffer)
        return [NSString string];
    
    NSUInteger          dataLength  = data.length;
    NSMutableString     *hexString  = [NSMutableString stringWithCapacity:(dataLength * 2)];
    
    for (int i = 0; i < dataLength; ++i)
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long)dataBuffer[i]]];
    
    return [NSString stringWithString:hexString];
}

- (NSString *)description {
    NSString *primiteValue = self.primitiveValue == 0 ? @"<none>" : [@(self.primitiveValue) stringValue];
    return [NSString stringWithFormat:@"%@[%@,%@]",NSStringFromClass([self class]),[self hexadecimalString:self.dataValue],primiteValue];
}

@end

@interface IRCrypto ()

@property (nonatomic, strong) IRKeychainService *keychainService;
@property (nonatomic, strong) IREncryptionService *encryptionService;

@property (nonatomic, assign) kIRAsymmetricEncryptionAlgorithm asymmetricAlgorithm;

//Sizes
@property (nonatomic, assign) size_t symmetricEncryptionKeySize;
@property (nonatomic, assign) size_t hmacKeySize;
@property (nonatomic, assign) size_t symmetricEncryptionSaltSize;
@property (nonatomic, assign) size_t hmacSaltSize;

//Prompts
@property (nonatomic, copy) NSString *symmetricUserPromptReason;
@property (nonatomic, copy) NSString *hmacUserPromptReason;

@end

@implementation IRCrypto

#pragma mark - Initializers

- (instancetype)init {
    if (self = [super init]) {
        _keychainService = [IRKeychainService new];
        _encryptionService = [IREncryptionService new];
        [self setupWithOptions:[self defaultOptions]];
    }
    
    return self;
}

- (instancetype)initWithOptions:(NSDictionary<NSString *, id> *)options {
    if (self = [super init]) {
        _keychainService = [IRKeychainService new];
        _encryptionService = [IREncryptionService new];
        [self setupWithOptions:options];
    }
    
    return self;
}

#pragma mark - Authenticated Encryption (RNCryptor Data Format v3.0)
#pragma mark - AE Encryption

- (void)aeEncryptData:(NSData *)plaintextData
           completion:(AEEncryptionCompletion)completion
              failure:(AEEncryptionFailure)failure {
    
    //Load AES Key (Default 256 bits)
    [self.keychainService loadKeyWithReason:self.symmetricUserPromptReason
                           attributeService:kAttributeServiceSymmetricKey
                                 completion:^(id aesKey) {
        
        //Load HMAC Key (Default 256 bits)
        [self.keychainService loadKeyWithReason:self.hmacUserPromptReason
                               attributeService:kAttributeServiceHMACKey
                                     completion:^(id hmacKey) {
            
             [self aeEncryptData:plaintextData
                    symmetricKey:aesKey
                         hmacKey:hmacKey
                      completion:completion
                         failure:failure];
            
        } failure:^(NSError *error) {
            if (failure) {
                failure(error);
            }
        }];
        
    } failure:^(NSError *error) {
        if (failure) {
            failure(error);
        }
    }];
}

- (void)aeEncryptData:(NSData *)plaintextData
         symmetricKey:(NSData *)symmetricKey
              hmacKey:(NSData *)hmacKey
           completion:(AEEncryptionCompletion)completion
              failure:(AEEncryptionFailure)failure {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSData *iv = nil;
        NSData *cipherData = [self.encryptionService encryptData:plaintextData withKey:symmetricKey iv:&iv];
        if (cipherData.length == 0) {
            if (failure) {
                failure([IRErrorProvider genericError]);
            }
            return;
        }
        
        //Create Header
        NSMutableData *headerData = [NSMutableData new];
        
        //Add version (1 byte)
        const char version[1] = {0x03};
        [headerData appendBytes:version length:sizeof(version)];
        
        //Add Options (1 byte)
        const char options[1] = {0x00};
        [headerData appendBytes:options length:sizeof(options)];
        
        //Add IV
        [headerData appendData:iv];
        
        //Create HMAC Data from header + cipher
        NSMutableData *dataToHMAC = [NSMutableData new];
        [dataToHMAC appendData:headerData];
        [dataToHMAC appendData:cipherData];
        
        //HMAC header and cipher
        NSData *hmacData = [self.encryptionService hmacData:dataToHMAC withKey:hmacKey];
        
        //All together
        NSMutableData *aeCipherData = [NSMutableData new];
        [aeCipherData appendData:headerData];
        [aeCipherData appendData:cipherData];
        [aeCipherData appendData:hmacData];
        
        if (completion) {
            completion(aeCipherData, iv, nil, nil);
        }
    });
}

- (void)aeEncryptData:(NSData *)plaintextData
             password:(NSString *)password
           completion:(AEEncryptionCompletion)completion
              failure:(AEEncryptionFailure)failure {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSData *symmetricKeySalt = [self.encryptionService randomBytesOfLength:self.symmetricEncryptionSaltSize];
        NSData *symmetricKey = [self.encryptionService keyFromString:password salt:symmetricKeySalt keySize:self.symmetricEncryptionKeySize];
        
        NSData *hmacKeySalt = [self.encryptionService randomBytesOfLength:self.hmacSaltSize];
        NSData *hmacKey = [self.encryptionService keyFromString:password salt:hmacKeySalt keySize:self.hmacKeySize];
        
        NSData *iv = nil;
        NSData *cipherData = [self.encryptionService encryptData:plaintextData withKey:symmetricKey iv:&iv];
        if (cipherData.length == 0) {
            if (failure) {
                failure([IRErrorProvider genericError]);
            }
            return;
        }
        
        //Create Header
        NSMutableData *headerData = [NSMutableData new];
        
        //Add version (1 byte)
        const char version[1] = {0x03};
        [headerData appendBytes:version length:sizeof(version)];
        
        //Add Options (1 byte)
        const char options[1] = {0x01};
        [headerData appendBytes:options length:sizeof(options)];
        
        //Add Encryption Salt
        [headerData appendData:symmetricKeySalt];
        
        //Add HMAC Salt
        [headerData appendData:hmacKeySalt];
        
        //Add IV
        [headerData appendData:iv];
        
        //Create HMAC Data from header + cipher
        NSMutableData *dataToHMAC = [NSMutableData new];
        [dataToHMAC appendData:headerData];
        [dataToHMAC appendData:cipherData];
        
        //HMAC header and cipher
        NSData *hmacData = [self.encryptionService hmacData:dataToHMAC withKey:hmacKey];
        
        //All together
        NSMutableData *aeCipherData = [NSMutableData new];
        [aeCipherData appendData:headerData];
        [aeCipherData appendData:cipherData];
        [aeCipherData appendData:hmacData];
        
        if (completion) {
            completion(aeCipherData, iv, symmetricKeySalt, hmacKeySalt);
        }
    });
}

- (void)aeCompatibilityModeEncryptData:(NSData *)plaintextData
                              password:(NSString *)password
                            completion:(AEEncryptionCompletion)completion
                               failure:(AEEncryptionFailure)failure {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSData *symmetricKeySalt = [self.encryptionService randomBytesOfLength:self.symmetricEncryptionSaltSize];
        NSData *symmetricKey = [self.encryptionService keyFromStringUsingSHA1:password salt:symmetricKeySalt keySize:self.symmetricEncryptionKeySize];
        
        NSData *hmacKeySalt = [self.encryptionService randomBytesOfLength:self.hmacSaltSize];
        NSData *hmacKey = [self.encryptionService keyFromStringUsingSHA1:password salt:hmacKeySalt keySize:self.hmacKeySize];
        
        NSData *iv = nil;
        NSData *cipherData = [self.encryptionService encryptData:plaintextData withKey:symmetricKey iv:&iv];
        if (cipherData.length == 0) {
            if (failure) {
                failure([IRErrorProvider genericError]);
            }
            return;
        }
        
        //Create Header
        NSMutableData *headerData = [NSMutableData new];
        
        //Add version (1 byte)
        const char version[1] = {0x03};
        [headerData appendBytes:version length:sizeof(version)];
        
        //Add Options (1 byte)
        const char options[1] = {0x01};
        [headerData appendBytes:options length:sizeof(options)];
        
        //Add Encryption Salt
        [headerData appendData:symmetricKeySalt];
        
        //Add HMAC Salt
        [headerData appendData:hmacKeySalt];
        
        //Add IV
        [headerData appendData:iv];
        
        //Create HMAC Data from header + cipher
        NSMutableData *dataToHMAC = [NSMutableData new];
        [dataToHMAC appendData:headerData];
        [dataToHMAC appendData:cipherData];
        
        //HMAC header and cipher
        NSData *hmacData = [self.encryptionService hmacData:dataToHMAC withKey:hmacKey];
        
        //All together
        NSMutableData *aeCipherData = [NSMutableData new];
        [aeCipherData appendData:headerData];
        [aeCipherData appendData:cipherData];
        [aeCipherData appendData:hmacData];
        
        if (completion) {
            completion(aeCipherData, iv, symmetricKeySalt, hmacKeySalt);
        }
    });
}

#pragma mark - Authenticated Encryption (RNCryptor Data Format v3.0)
#pragma mark - AE Decryption

- (void)aeDecryptData:(NSData *)cipherData
           completion:(AEDecryptionCompletion)completion
              failure:(AEDecryptionFailure)failure {
    
    //Load AES Key (Default 256 bits)
    [self.keychainService loadKeyWithReason:self.symmetricUserPromptReason
                           attributeService:kAttributeServiceSymmetricKey
                                 completion:^(id aesKey) {
                                     
         //Load HMAC Key (Default 256 bits)
         [self.keychainService loadKeyWithReason:self.hmacUserPromptReason
                                attributeService:kAttributeServiceHMACKey
                                      completion:^(id hmacKey) {
              
              [self aeDecryptData:cipherData
                     symmetricKey:aesKey
                          hmacKey:hmacKey
                       completion:completion
                          failure:failure];
              
          } failure:^(NSError *error) {
              if (failure) {
                  failure(error);
              }
          }];
         
     } failure:^(NSError *error) {
         if (failure) {
             failure(error);
         }
     }];
}

- (void)aeDecryptData:(NSData *)cipherData
         symmetricKey:(NSData *)symmetricKey
              hmacKey:(NSData *)hmacKey
           completion:(AEDecryptionCompletion)completion
              failure:(AEDecryptionFailure)failure {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray<IRAEMessageModel *> *components = [self cipherDataComponents:cipherData];
        if (components) {
            IRAEMessageModel *version = components[0];
            IRAEMessageModel *options = components[1];
            IRAEMessageModel *iv = components[2];
            IRAEMessageModel *hmac = components[3];
            IRAEMessageModel *ciphertext = components[4];
            
            NSData *decryptedData = [self.encryptionService decryptData:ciphertext.dataValue
                                                                withKey:symmetricKey
                                                                     iv:iv.dataValue];
            
            NSMutableData *dataToHMAC = [NSMutableData new];
            [dataToHMAC appendData:version.dataValue];
            [dataToHMAC appendData:options.dataValue];
            [dataToHMAC appendData:iv.dataValue];
            [dataToHMAC appendData:ciphertext.dataValue];
            NSData *hmacData = [self.encryptionService hmacData:dataToHMAC withKey:hmacKey];
            
            if ([self consistentTimeEqual:hmacData hmachToCompare:hmac.dataValue]) {
                if (completion) {
                    completion(decryptedData);
                }
                
            } else {
                if (failure) {
                    failure([IRErrorProvider errorWithMessage:NSLocalizedString(@"Incorrect Data Format", nil) errorCode:7008]);
                }
            }
        }
    });
}

- (void)aeDecryptData:(NSData *)cipherData
             password:(NSString *)password
           completion:(AEDecryptionCompletion)completion
              failure:(AEDecryptionFailure)failure {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray<IRAEMessageModel *> *components = [self cipherDataComponents:cipherData];
        if (components) {
            IRAEMessageModel *version = components[0];
            IRAEMessageModel *options = components[1];
            IRAEMessageModel *encryptionSalt = components[2];
            IRAEMessageModel *hmacSalt = components[3];
            IRAEMessageModel *iv = components[4];
            IRAEMessageModel *hmac = components[5];
            IRAEMessageModel *ciphertext = components[6];
            
            NSData *symmetricKey = [self.encryptionService
                                    keyFromString:password
                                    salt:encryptionSalt.dataValue
                                    keySize:self.symmetricEncryptionKeySize];
            
            NSData *hmacKey = [self.encryptionService
                               keyFromString:password
                               salt:hmacSalt.dataValue
                               keySize:self.hmacKeySize];
            
            NSData *decryptedData = [self.encryptionService decryptData:ciphertext.dataValue
                                                                withKey:symmetricKey
                                                                     iv:iv.dataValue];
            
            NSMutableData *dataToHMAC = [NSMutableData new];
            [dataToHMAC appendData:version.dataValue];
            [dataToHMAC appendData:options.dataValue];
            [dataToHMAC appendData:encryptionSalt.dataValue];
            [dataToHMAC appendData:hmacSalt.dataValue];
            [dataToHMAC appendData:iv.dataValue];
            [dataToHMAC appendData:ciphertext.dataValue];
            NSData *hmacData = [self.encryptionService hmacData:dataToHMAC withKey:hmacKey];
            
            if ([self consistentTimeEqual:hmacData hmachToCompare:hmac.dataValue]) {
                if (completion) {
                    completion(decryptedData);
                }
                
            } else {
                if (failure) {
                    failure([IRErrorProvider errorWithMessage:NSLocalizedString(@"Incorrect Data Format", nil) errorCode:7008]);
                }
            }
            
        }
    });
}

- (void)aeCompatibilityModeDecryptData:(NSData *)cipherData
                              password:(NSString *)password
                            completion:(AEDecryptionCompletion)completion
                               failure:(AEDecryptionFailure)failure {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSArray<IRAEMessageModel *> *components = [self cipherDataComponents:cipherData];
        if (components) {
            IRAEMessageModel *version = components[0];
            IRAEMessageModel *options = components[1];
            IRAEMessageModel *encryptionSalt = components[2];
            IRAEMessageModel *hmacSalt = components[3];
            IRAEMessageModel *iv = components[4];
            IRAEMessageModel *hmac = components[5];
            IRAEMessageModel *ciphertext = components[6];
            
            NSData *symmetricKey = [self.encryptionService keyFromStringUsingSHA1:password
                                                                             salt:encryptionSalt.dataValue
                                                                          keySize:self.symmetricEncryptionKeySize];
            
            NSData *hmacKey = [self.encryptionService keyFromStringUsingSHA1:password
                                                                        salt:hmacSalt.dataValue
                                                                     keySize:self.hmacKeySize];
            
            NSData *decryptedData = [self.encryptionService decryptData:ciphertext.dataValue
                                                                withKey:symmetricKey
                                                                     iv:iv.dataValue];
            
            NSMutableData *dataToHMAC = [NSMutableData new];
            [dataToHMAC appendData:version.dataValue];
            [dataToHMAC appendData:options.dataValue];
            [dataToHMAC appendData:encryptionSalt.dataValue];
            [dataToHMAC appendData:hmacSalt.dataValue];
            [dataToHMAC appendData:iv.dataValue];
            [dataToHMAC appendData:ciphertext.dataValue];
            NSData *hmacData = [self.encryptionService hmacData:dataToHMAC withKey:hmacKey];
            
            if ([self consistentTimeEqual:hmacData hmachToCompare:hmac.dataValue]) {
                if (completion) {
                    completion(decryptedData);
                }
                
            } else {
                if (failure) {
                    failure([IRErrorProvider errorWithMessage:NSLocalizedString(@"Incorrect Data Format", nil) errorCode:7008]);
                }
            }
            
        }
    });
}

#pragma mark - Symmetric Encryption (AES)

- (void)encryptData:(NSData *)plaintextData
         completion:(SymmetricEncryptionCompletion)completion
            failure:(SymmetricEncryptionFailure)failure {
    
    [self.keychainService loadKeyWithReason:self.symmetricUserPromptReason
                           attributeService:kAttributeServiceSymmetricKey
                                 completion:^(id keyData) {
                                     
         [self encryptData:plaintextData
                   withKey:keyData
                completion:completion
                   failure:failure];
        
    } failure:^(NSError *error) {
        if (failure) {
            failure(error);
        }
    }];
}

- (void)encryptData:(NSData *)plaintextData
            withKey:(NSData *)keyData
         completion:(SymmetricEncryptionCompletion)completion
            failure:(SymmetricEncryptionFailure)failure {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if (keyData.length != self.symmetricEncryptionKeySize) {
            if (failure) {
                failure([IRErrorProvider errorWithMessage:NSLocalizedString(@"Invalid Key Length", nil) errorCode:7005]);
            }
            return;
        }
        
        NSData *iv = nil;
        NSData *cipherData = [self.encryptionService encryptData:plaintextData withKey:keyData iv:&iv];
        if (cipherData.length == 0) {
            if (failure) {
                failure([IRErrorProvider genericError]);
            }
            return;
        }
        
        if (completion) {
            completion(cipherData, iv, nil);
        }
    });
}

- (void)encryptData:(NSData *)plaintextData
       withPassword:(NSString *)password
         completion:(SymmetricEncryptionCompletion)completion
            failure:(SymmetricEncryptionFailure)failure {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSData *salt = [self.encryptionService randomBytesOfLength:self.symmetricEncryptionSaltSize];
        NSData *keyData = [self.encryptionService keyFromString:password salt:salt keySize:self.symmetricEncryptionKeySize];
        
        [self encryptData:plaintextData
                  withKey:keyData
               completion:^(NSData *cipherData, NSData *iv, NSData *nilSalt) {
                   if (completion) {
                       completion(cipherData, iv, salt);
                   }
               } failure:failure];
    });
}

#pragma mark - Symmetric Decryption (AES)

- (void)decryptData:(NSData *)cipherData
                 iv:(NSData *)iv
         completion:(SymmetricDecryptionCompletion)completion
            failure:(SymmetricDecryptionFailure)failure {
    
    [self.keychainService loadKeyWithReason:self.symmetricUserPromptReason
                           attributeService:kAttributeServiceSymmetricKey
                                 completion:^(id keyData) {
                                     
        [self decryptData:cipherData
                  withKey:keyData
                       iv:iv
               completion:completion
                  failure:failure];
        
    } failure:^(NSError *error) {
        if (failure) {
            failure(error);
        }
    }];
}

- (void)decryptData:(NSData *)cipherData
            withKey:(NSData *)keyData
                 iv:(NSData *)iv
         completion:(SymmetricDecryptionCompletion)completion
            failure:(SymmetricDecryptionFailure)failure {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if (keyData.length == 0 || iv.length == 0) {
            if (failure) {
                failure([IRErrorProvider errorWithMessage:NSLocalizedString(@"Invalid Parameters",nil) errorCode:7006]);
            }
            return;
        }
        
        NSData *decryptedData = [self.encryptionService decryptData:cipherData withKey:keyData iv:iv];
        if (decryptedData.length == 0) {
            if (failure) {
                failure([IRErrorProvider genericError]);
            }
            return;
        }
        
        if (completion) {
            completion(decryptedData);
        }
    });
}

- (void)decryptData:(NSData *)cipherData
       withPassword:(NSString *)password
                 iv:(NSData *)iv
               salt:(NSData *)salt
         completion:(SymmetricDecryptionCompletion)completion
            failure:(SymmetricDecryptionFailure)failure {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if (password.length == 0 || iv.length == 0 || salt.length == 0) {
            if (failure) {
                failure([IRErrorProvider errorWithMessage:NSLocalizedString(@"Invalid Parameters",nil) errorCode:7006]);
            }
            return;
        }
        
        NSData *keyData = [self.encryptionService keyFromString:password salt:salt keySize:self.symmetricEncryptionKeySize];
        
        [self decryptData:cipherData
                  withKey:keyData
                       iv:iv
               completion:completion
                  failure:failure];
    });
}

#pragma mark - Asymmetric Encryption (RSA)

- (void)publicKeyEncryptData:(NSData *)plaintextData
                  completion:(AsymmetricEncryptionCompletion)completion
                     failure:(AsymmetricEncryptionFailure)failure {
    
    [self.keychainService loadKeyWithReason:self.symmetricUserPromptReason
                           attributeService:kAttributeServicePublicKey
                                 completion:^(id publicKey) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            NSData *cipherData = [self.encryptionService encryptData:plaintextData publicKey:(__bridge SecKeyRef)publicKey];
            if (cipherData.length == 0) {
                if (failure) {
                    failure([IRErrorProvider genericError]);
                }
                return;
            }
            
            if (completion) {
                completion(cipherData);
            }
        });
        
    } failure:^(NSError *error) {
        if (failure) {
            failure(error);
        }
    }];
}

- (void)publicKeyEncryptData:(NSData *)plaintextData
               withPublicKey:(SecKeyRef)publicKey
                  completion:(AsymmetricEncryptionCompletion)completion
                     failure:(AsymmetricEncryptionFailure)failure {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSData *cipherData = [self.encryptionService encryptData:plaintextData publicKey:publicKey];
        if (cipherData.length == 0) {
            if (failure) {
                failure([IRErrorProvider genericError]);
            }
            return;
        }
        
        if (completion) {
            completion(cipherData);
        }
    });
}

#pragma mark - Asymmetric Decryption (RSA)

- (void)privateKeyDecryptData:(NSData *)cipherData
                   completion:(AsymmetricDecryptionCompletion)completion
                      failure:(AsymmetricDecryptionFailure)failure {
    
    [self.keychainService loadKeyWithReason:self.symmetricUserPromptReason
                           attributeService:kAttributeServicePrivateKey
                                 completion:^(id privateKey) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            NSData *decryptedData = [self.encryptionService decryptData:cipherData privateKey:(__bridge SecKeyRef)privateKey];
            if (decryptedData.length == 0) {
                if (failure) {
                    failure([IRErrorProvider genericError]);
                }
                return;
            }
            
            if (completion) {
                completion(decryptedData);
            }
        });
        
    } failure:^(NSError *error) {
        if (failure) {
            failure(error);
        }
    }];
}

- (void)privateKeyDecryptData:(NSData *)cipherData
               withPrivateKey:(SecKeyRef)privateKey
                   completion:(AsymmetricDecryptionCompletion)completion
                      failure:(AsymmetricDecryptionFailure)failure {
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSData *decryptedData = [self.encryptionService decryptData:cipherData privateKey:privateKey];
        if (decryptedData.length == 0) {
            if (failure) {
                failure([IRErrorProvider genericError]);
            }
            return;
        }
        
        if (completion) {
            completion(cipherData);
        }
    });
}

#pragma mark - Data Integrity (HMAC)

- (void)hmacData:(NSData *)data
      completion:(HMACCompletion)completion
         failure:(HMACFailure)failure {
    [self.keychainService loadKeyWithReason:self.symmetricUserPromptReason
                           attributeService:kAttributeServiceHMACKey
                                 completion:^(id keyData) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            NSData *hmacData = [self.encryptionService hmacData:data withKey:keyData];
            if (hmacData.length == 0) {
                if (failure) {
                    failure([IRErrorProvider genericError]);
                }
            } else {
                if (completion) {
                    completion(hmacData);
                }
            }
        });

    } failure:^(NSError *error) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            if (failure) {
                failure(error);
            }
        });
    }];
}

- (void)hmacData:(NSData *)data
         withKey:(NSData *)key
      completion:(HMACCompletion)completion
         failure:(HMACFailure)failure {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSData *hmacData = [self.encryptionService hmacData:data withKey:key];
        if (hmacData.length == 0) {
            if (failure) {
                failure([IRErrorProvider genericError]);
            }
        } else {
            if (completion) {
                completion(hmacData);
            }
        }
    });
}

#pragma mark - Hashing

- (NSData *)hashData:(NSData *)dataToHash {
    return [self.encryptionService hashData:dataToHash];
}

#pragma mark - Key Generation

- (NSData *)randomAESEncryptionKeyOfLength:(NSUInteger)length {
    return [self.encryptionService generateAESEncryptionKeyOfLength:length];
}

- (NSData *)randomHMACKeyOfLength:(NSUInteger)length {
    return [self.encryptionService generateHMACKeyOfLength:length];
}

- (void)keyFromPassword:(NSString * _Nonnull)password
               ofLength:(NSUInteger)length
             completion:(KeyDerivationCompletion _Nonnull)completion {
    if (completion) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            NSData *salt = [self.encryptionService randomBytesOfLength:kPBKDF2SaltSize];
            NSData *key = [self.encryptionService keyFromString:password salt:salt keySize:length];
            completion(key, salt);
        });
    }
}

#pragma mark - Helpers

- (NSDictionary<NSString *, id> *)defaultOptions {
    NSString *touchIDReason = NSLocalizedString(@"This is necessary to protect your data", nil);
    return @{
             kIRAsymmetricEncryptionAlgorithmKey:           @(kIRAsymmetricEncryptionRSA),
             kIRSigningKeysKey:                             @(kIRSigningKeysRSA),
             kIRAsymmetricEncryptionProtectionKey:          @(kIRKeyProtectionTouchID),
             kIRAsymmetricEncryptionProtectionReasonKey:    touchIDReason,
             kIRSymmetricEncryptionProtectionKey:           @(kIRKeyProtectionTouchID),
             kIRSymmetricEncryptionProtectionReasonKey:     touchIDReason,
             kIRHMACProtectionKey:                          @(kIRKeyProtectionTouchID),
             kIRHMACProtectionReasonKey:                    touchIDReason,
             kIRSymmetricEncryptionKeySizeKey:              @(kIRSymmetricEncryptionDefaultKeySize),
             kIRHMACKeySizeKey:                             @(kIRHMACDefaultKeySize)
            };
}

- (void)setupWithOptions:(NSDictionary<NSString *, id> *)options {
    NSNumber *encryptionOptions = [self options:options valueForKey:kIREncryptionOptionsKey];
    if ([encryptionOptions integerValue] == kEncryptionOptionsNone) {
        self.symmetricEncryptionKeySize = kIRSymmetricEncryptionDefaultKeySize;
        self.hmacKeySize = kIRHMACDefaultKeySize;
        self.symmetricEncryptionSaltSize = kIRSymmetricEncryptionDefaultSaltSize;
        self.hmacSaltSize = kIRHMACDefaultSaltSize;
        return;
    }

    NSString *appPassword = [self options:options valueForKey:kIRAppPasswordKey];

    NSNumber *asymmetricAlgorithm = [self options:options valueForKey:kIRAsymmetricEncryptionAlgorithmKey];
    NSNumber *asymmetricProtection = [self options:options valueForKey:kIRAsymmetricEncryptionProtectionKey];
    NSString *asymmetricProtectionReason = [self options:options valueForKey:kIRAsymmetricEncryptionProtectionReasonKey];
    [self setupAsymmetricEncryptionAlgorithm:[asymmetricAlgorithm integerValue] forOption:[asymmetricProtection integerValue] applicationPassword:appPassword userPromptReason:asymmetricProtectionReason];
    
    NSNumber *symmetricProtection = [self options:options valueForKey:kIRSymmetricEncryptionProtectionKey];
    NSString *symmetricProtectionReason = [self options:options valueForKey:kIRSymmetricEncryptionProtectionReasonKey];
    NSNumber *symmetricKeySize = [self options:options valueForKey:kIRSymmetricEncryptionKeySizeKey];
    [self setupSymmetricEncryptionForOption:[symmetricProtection integerValue] applicationPassword:appPassword userPromptReason:symmetricProtectionReason keySize:[symmetricKeySize integerValue]];

    NSNumber *signingKeys = [self options:options valueForKey:kIRSigningKeysKey];
    [self setupSigningKeysForOption:[signingKeys integerValue]];

    NSNumber *hmacProtection = [self options:options valueForKey:kIRHMACProtectionKey];
    NSString *hmacProtectionReason = [self options:options valueForKey:kIRHMACProtectionReasonKey];
    NSNumber *hmacKeySize = [self options:options valueForKey:kIRHMACKeySizeKey];
    [self setupHMACWithProtection:[hmacProtection integerValue] applicationPassword:appPassword userPromptReason:hmacProtectionReason keySize:[hmacKeySize integerValue]];
}

- (void)setupAsymmetricEncryptionAlgorithm:(kIRAsymmetricEncryptionAlgorithm)algorithm
                                 forOption:(kIRKeyProtection)option
                       applicationPassword:(NSString *)appPassword
                          userPromptReason:(NSString *)reason {
    
    self.asymmetricAlgorithm = algorithm;
    
    if (algorithm == kIRAsymmetricEncryptionRSA) {
        [self.encryptionService generateRSAKeyPair:^(SecKeyRef publicKey, SecKeyRef privateKey) {
            [self savePublicKey:publicKey privateKey:privateKey withOption:option applicationPassword:appPassword userPromptReason:reason];
        }];
        
    } else {
        [self.encryptionService generateECKeyPair:^(SecKeyRef publicKey, SecKeyRef privateKey) {
            [self savePublicKey:publicKey privateKey:privateKey withOption:option applicationPassword:appPassword userPromptReason:reason];
        }];
    }
}

- (void)setupSymmetricEncryptionForOption:(kIRKeyProtection)option
                      applicationPassword:(NSString *)appPassword
                         userPromptReason:(NSString *)reason
                                  keySize:(NSUInteger)keySize {
    
    self.symmetricEncryptionKeySize = keySize;
    self.symmetricUserPromptReason = reason;
    
    NSData *masterKey = [self.encryptionService generateAESEncryptionKeyOfLength:keySize];
    
    if (isOptionEqualToValue(kIRKeyProtectionTouchID, option) &&
        isOptionEqualToValue(kIRKeyProtectionPassword, option)) {
        [self.keychainService saveKeyProtectedWithTouchIDAndPassword:masterKey userPromptReason:reason attributeService:kAttributeServiceSymmetricKey failure:nil];
        
    } else if (isOptionEqualToValue(kIRKeyProtectionTouchID, option)) {
        [self.keychainService saveKeyProtectedWithTouchID:masterKey userPromptReason:reason attributeService:kAttributeServiceSymmetricKey];
        
    } else if (isOptionEqualToValue(kIRKeyProtectionPassword, option)) {
        NSAssert(appPassword != nil, NSLocalizedString(@"Error: Must provide an application password to protect keys on the Keychain", nil));
        [self.keychainService saveKeyProtectedWithPassword:masterKey applicationPassword:appPassword userPromptReason:reason attributeService:kAttributeServiceSymmetricKey failure:nil];
    }
}

- (void)setupHMACWithProtection:(kIRKeyProtection)option
            applicationPassword:(NSString *)appPassword
               userPromptReason:(NSString *)reason
                        keySize:(NSUInteger)keySize {
    
    self.hmacKeySize = keySize;
    self.hmacUserPromptReason = reason;
    
    NSData *hamacKey = [self.encryptionService generateHMACKeyOfLength:keySize];
    
    if (isOptionEqualToValue(kIRKeyProtectionTouchID, option) &&
        isOptionEqualToValue(kIRKeyProtectionPassword, option)) {
        [self.keychainService saveKeyProtectedWithTouchIDAndPassword:hamacKey userPromptReason:reason attributeService:kAttributeServiceHMACKey failure:nil];
        
    } else if (isOptionEqualToValue(kIRKeyProtectionTouchID, option)) {
        [self.keychainService saveKeyProtectedWithTouchID:hamacKey userPromptReason:reason attributeService:kAttributeServiceHMACKey];
        
    } else if (isOptionEqualToValue(kIRKeyProtectionPassword, option)) {
        NSAssert(appPassword != nil, NSLocalizedString(@"Error: Must provide an application password to protect keys on the Keychain", nil));
        [self.keychainService saveKeyProtectedWithPassword:hamacKey applicationPassword:appPassword userPromptReason:reason attributeService:kAttributeServiceHMACKey failure:nil];
    }
}

- (void)setupSigningKeysForOption:(kIRSigningKeys)option {
    if (option == kIRSigningKeysRSA) {
        [self.encryptionService generateSigningKeyPairInSecureEnclave];
    }
}

- (id)options:(NSDictionary<NSString *, id> *)options valueForKey:(NSString *)key {
    id value = options[key];
    if (!value) {
        value = [self defaultOptions][key];
    }
    
    return value;
}

- (void)savePublicKey:(SecKeyRef)publicKey
           privateKey:(SecKeyRef)privateKey
           withOption:(kIRKeyProtection)option
  applicationPassword:(NSString *)appPassword
     userPromptReason:(NSString *)reason {
    
    if (isOptionEqualToValue(kIRKeyProtectionTouchID, option) &&
        isOptionEqualToValue(kIRKeyProtectionPassword, option)) {
        [self.keychainService saveKeyProtectedWithTouchIDAndPassword:(__bridge id)publicKey userPromptReason:reason attributeService:kAttributeServicePublicKey failure:nil];
        [self.keychainService saveKeyProtectedWithTouchIDAndPassword:(__bridge id)privateKey userPromptReason:reason attributeService:kAttributeServicePrivateKey failure:nil];
        
    } else if (isOptionEqualToValue(kIRKeyProtectionTouchID, option)) {
        [self.keychainService saveKeyProtectedWithTouchID:(__bridge id)publicKey userPromptReason:reason attributeService:kAttributeServicePublicKey];
        [self.keychainService saveKeyProtectedWithTouchID:(__bridge id)privateKey userPromptReason:reason attributeService:kAttributeServicePrivateKey];
        
    } else if (isOptionEqualToValue(kIRKeyProtectionPassword, option)) {
        NSAssert(appPassword != nil, NSLocalizedString(@"Error: Must provide an application password to protect keys on the Keychain", nil));
        [self.keychainService saveKeyProtectedWithPassword:(__bridge id)publicKey applicationPassword:appPassword userPromptReason:reason attributeService:kAttributeServicePublicKey failure:nil];
        [self.keychainService saveKeyProtectedWithPassword:(__bridge id)privateKey applicationPassword:appPassword userPromptReason:reason attributeService:kAttributeServicePrivateKey failure:nil];
    }
}

- (NSArray<IRAEMessageModel *> *)cipherDataComponents:(NSData *)cipherData {
    
    //Bad data format
    if (cipherData.length <= (kIVSizeAES128 + 2 + 32)) {
        return nil;
    }
    
    //Get Options
    NSRange range = NSMakeRange(1, 1);
    NSData *optionsData = [cipherData subdataWithRange:range];
    NSUInteger options = *(NSInteger*)optionsData.bytes;
    
    if (options == 0) {
        return [self keyBasedCipherDataComponents:cipherData];
    }
    
    return [self passwordBasedCipherDataComponents:cipherData];
}

- (NSArray<IRAEMessageModel *> *)keyBasedCipherDataComponents:(NSData *)cipherData {
    
    NSMutableArray *dataComponents = [NSMutableArray new];
    
    //Get Version
    NSRange range = NSMakeRange(0, 1);
    NSData *versionData = [cipherData subdataWithRange:range];
    NSUInteger version = *(NSInteger*)versionData.bytes;
    IRAEMessageModel *versionModel = [[IRAEMessageModel alloc] initWithDataValue:versionData
                                                                  primitiveValue:version];
    [dataComponents addObject:versionModel];
    
    //Get Options
    range = NSMakeRange(1, 1);
    NSData *optionsData = [cipherData subdataWithRange:range];
    NSUInteger options = *(NSInteger*)optionsData.bytes;
    IRAEMessageModel *optionsModel = [[IRAEMessageModel alloc] initWithDataValue:optionsData
                                                                  primitiveValue:options];
    [dataComponents addObject:optionsModel];
    
    //Get IV
    range = NSMakeRange(2, kIVSizeAES128);
    NSData *iv = [cipherData subdataWithRange:range];
    IRAEMessageModel *ivModel = [[IRAEMessageModel alloc] initWithDataValue:iv
                                                             primitiveValue:0];
    [dataComponents addObject:ivModel];
    
    //Get HMAC
    range = NSMakeRange(cipherData.length - 32, 32);
    NSData *hmac = [cipherData subdataWithRange:range];
    IRAEMessageModel *hmacModel = [[IRAEMessageModel alloc] initWithDataValue:hmac
                                                               primitiveValue:0];
    [dataComponents addObject:hmacModel];
    
    //Get Ciphertext
    range = NSMakeRange(kIVSizeAES128 + 2, cipherData.length - (kIVSizeAES128 + 2 + 32));
    NSData *ciphertext = [cipherData subdataWithRange:range];
    IRAEMessageModel *ciphertextModel = [[IRAEMessageModel alloc] initWithDataValue:ciphertext
                                                                     primitiveValue:0];
    [dataComponents addObject:ciphertextModel];
    
    return [dataComponents copy];
}

- (NSArray<IRAEMessageModel *> *)passwordBasedCipherDataComponents:(NSData *)cipherData {
    NSMutableArray *dataComponents = [NSMutableArray new];
    
    //Get Version
    NSRange range = NSMakeRange(0, 1);
    NSData *versionData = [cipherData subdataWithRange:range];
    NSUInteger version = *(NSInteger*)versionData.bytes;
    IRAEMessageModel *versionModel = [[IRAEMessageModel alloc] initWithDataValue:versionData
                                                                  primitiveValue:version];
    [dataComponents addObject:versionModel];
    
    //Get Options
    range = NSMakeRange(1, 1);
    NSData *optionsData = [cipherData subdataWithRange:range];
    NSUInteger options = *(NSInteger*)optionsData.bytes;
    IRAEMessageModel *optionsModel = [[IRAEMessageModel alloc] initWithDataValue:optionsData
                                                                  primitiveValue:options];
    [dataComponents addObject:optionsModel];
    
    //Get Encryption Salt
    range = NSMakeRange(2, self.symmetricEncryptionSaltSize);
    NSData *encryptionSalt = [cipherData subdataWithRange:range];
    IRAEMessageModel *encryptionSaltModel = [[IRAEMessageModel alloc] initWithDataValue:encryptionSalt
                                                                         primitiveValue:0];
    [dataComponents addObject:encryptionSaltModel];
    
    //Get HMAC Salt
    range = NSMakeRange(2 + self.symmetricEncryptionSaltSize, self.hmacSaltSize);
    NSData *hmacSalt = [cipherData subdataWithRange:range];
    IRAEMessageModel *hmacSaltModel = [[IRAEMessageModel alloc] initWithDataValue:hmacSalt
                                                                   primitiveValue:0];
    [dataComponents addObject:hmacSaltModel];
    
    //Get IV
    range = NSMakeRange(2 + self.symmetricEncryptionSaltSize + self.hmacSaltSize, kIVSizeAES128);
    NSData *iv = [cipherData subdataWithRange:range];
    IRAEMessageModel *ivModel = [[IRAEMessageModel alloc] initWithDataValue:iv
                                                             primitiveValue:0];
    [dataComponents addObject:ivModel];
    
    //Get HMAC
    range = NSMakeRange(cipherData.length - 32, 32);
    NSData *hmac = [cipherData subdataWithRange:range];
    IRAEMessageModel *hmacModel = [[IRAEMessageModel alloc] initWithDataValue:hmac
                                                               primitiveValue:0];
    [dataComponents addObject:hmacModel];
    
    //Get Ciphertext
    NSUInteger versionLength = 1;
    NSUInteger optionsLength = 1;
    NSUInteger saltsLength = self.symmetricEncryptionSaltSize + self.hmacSaltSize;
    NSUInteger start = versionLength + optionsLength + saltsLength + kIVSizeAES128;
    NSUInteger hmacLength = 32;
    range = NSMakeRange(start, cipherData.length - (start + hmacLength));
    NSData *ciphertext = [cipherData subdataWithRange:range];
    IRAEMessageModel *ciphertextModel = [[IRAEMessageModel alloc] initWithDataValue:ciphertext
                                                                     primitiveValue:0];
    [dataComponents addObject:ciphertextModel];
    
    return [dataComponents copy];
}

- (BOOL)consistentTimeEqual:(NSData *)computedHMAC hmachToCompare:(NSData *)HMAC {
    uint8_t result = computedHMAC.length - HMAC.length;
    
    const uint8_t *hmacBytes = [HMAC bytes];
    const NSUInteger hmacLength = [HMAC length];
    const uint8_t *computedHMACBytes = [computedHMAC bytes];
    const NSUInteger computedHMACLength = [computedHMAC length];
    
    for (NSUInteger i = 0; i < computedHMACLength; ++i) {
        result |= hmacBytes[i % hmacLength] ^ computedHMACBytes[i];
    }
    
    return result == 0;
}

@end
