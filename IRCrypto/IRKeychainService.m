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

#import "IRKeychainService.h"
#import "IRErrorProvider.h"
#import "IRConstants.h"

@import Security;
@import LocalAuthentication;

typedef NS_ENUM(NSUInteger, KeyProtection) {
    kKeyProtectionTouchID,
    kKeyProtectionPassword,
    kKeyProtectionPasswordAndTouchID
};

typedef NS_ENUM(NSUInteger, AsymmetricKeyType) {
    kAsymmetricKeyTypeUnknown,
    kAsymmetricKeyTypeRSA,
    kAsymmetricKeyTypeEC
};

static NSString * const kRSAKeyString = @"RSA";
static NSString * const kECKeyString = @"EC";

@implementation IRKeychainService

#pragma mark - Key Storing

- (NSError *)saveKeyProtectedWithTouchID:(id)keyDataOrRef
                        userPromptReason:(NSString *)reason
                        attributeService:(AttributeService)attService {
    
    if (!keyDataOrRef || keyDataOrRef == NULL) {
        return [IRErrorProvider errorWithMessage:NSLocalizedString(@"Invalid Key",nil) errorCode:7003];
    }
    
    if ([self keyExistsWithReason:reason attributeService:attService]) {
        return nil;
    }
    
    CFErrorRef error = NULL;
    
    SecAccessControlRef secACL = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, kSecAccessControlTouchIDCurrentSet, &error);
    if (secACL == NULL || error != NULL) {
        return (__bridge NSError *)(error);
    }
    
    NSDictionary *attributes = [self attributesForKeyProtection:kKeyProtectionTouchID keyDataOrRef:keyDataOrRef accessControl:secACL attributeService:(AttributeService)attService context:nil];
    OSStatus status =  SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
    if (status != errSecSuccess) {
        return [IRErrorProvider errorWithMessage:[self keychainErrorFromStatus:status] errorCode:[self keychainErrorCodeFromStatus:status]];
    }

    return nil;
}

- (void)saveKeyProtectedWithPassword:(id)keyDataOrRef
                 applicationPassword:(NSString *)appPassword
                    userPromptReason:(NSString *)reason
                    attributeService:(AttributeService)attService
                             failure:(failure)faillure {
    
    if (!keyDataOrRef || keyDataOrRef == NULL) {
        if (faillure) {
            faillure([IRErrorProvider errorWithMessage:NSLocalizedString(@"Invalid Key",nil) errorCode:7003]);
        }
        return;
    }

    if (appPassword == nil) {
        if (faillure) {
            faillure([IRErrorProvider errorWithMessage:NSLocalizedString(@"Invalid Application Password",nil) errorCode:7005]);
        }
        return;
    }
    
    if ([self keyExistsWithReason:reason attributeService:attService]) {
        return;
    }
    
    CFErrorRef error = NULL;
    SecAccessControlRef secACL = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                    kSecAccessControlApplicationPassword,
                                                                    &error);
    
    if (secACL == NULL || error != NULL) {
        if (faillure) {
            faillure([IRErrorProvider genericError]);
        }
    }
    
    LAContext *context = [LAContext new];
    [context setCredential:[appPassword dataUsingEncoding:NSUTF8StringEncoding]
                      type:LACredentialTypeApplicationPassword];

    NSDictionary *attributes = [self attributesForKeyProtection:kKeyProtectionPassword
                                                   keyDataOrRef:keyDataOrRef
                                                  accessControl:secACL
                                               attributeService:attService
                                                        context:context];
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
    if (status != errSecSuccess && faillure) {
        faillure([IRErrorProvider errorWithMessage:[self keychainErrorFromStatus:status] errorCode:[self keychainErrorCodeFromStatus:status]]);
    }
}

- (void)saveKeyProtectedWithTouchIDAndPassword:(id)keyDataOrRef
                              userPromptReason:(NSString *)reason
                              attributeService:(AttributeService)attService
                                       failure:(failure)faillure {
    
    if (!keyDataOrRef || keyDataOrRef == NULL) {
        if (faillure) {
            faillure([IRErrorProvider errorWithMessage:NSLocalizedString(@"Invalid Key",nil) errorCode:7003]);
        }
        return;
    }
    
    if ([self keyExistsWithReason:reason attributeService:attService]) {
        return;
    }

    CFErrorRef error = NULL;
    SecAccessControlRef secACL = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                    kSecAccessControlTouchIDAny | kSecAccessControlApplicationPassword,
                                                                    &error);
    
    if (secACL == NULL || error != NULL) {
        if (faillure) {
            faillure([IRErrorProvider genericError]);
        }
    }
    
    LAContext *context = [LAContext new];
    [context evaluateAccessControl:secACL operation:LAAccessControlOperationCreateItem localizedReason:reason reply:^(BOOL success, NSError * error) {
        if (success) {
            NSDictionary *attributes = [self attributesForKeyProtection:kKeyProtectionPasswordAndTouchID keyDataOrRef:keyDataOrRef accessControl:secACL attributeService:(AttributeService)attService context:context];
            OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
            if (status != errSecSuccess && faillure) {
                if (error) {
                    faillure(error);
                } else {
                    faillure([IRErrorProvider errorWithMessage:[self keychainErrorFromStatus:status] errorCode:[self keychainErrorCodeFromStatus:status]]);
                }
            }
            
        } else {
            CFRelease(secACL);
        }
    }];
}

#pragma mark - Key Deletion

- (NSError *)deleteKeyWithAttributeService:(AttributeService)attService {
    NSMutableDictionary *query = [NSMutableDictionary new];
    CFStringRef attributeService = [self secAttServiceFromService:attService];

    if (attService == kAttributeServicePublicKey || attService == kAttributeServicePrivateKey) {
        [query setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [query setObject:(__bridge id)attributeService forKey:(__bridge id)kSecAttrApplicationTag];
    } else {
        [query setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
        [query setObject:(__bridge id)attributeService forKey:(__bridge id)kSecAttrService];
    }

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)([query copy]));
    if (status != errSecSuccess) {
        return [IRErrorProvider errorWithMessage:[self keychainErrorFromStatus:status] errorCode:[self keychainErrorCodeFromStatus:status]];
    }
    
    return nil;
}

#pragma mark - Key Querying

- (void)loadKeyWithReason:(NSString *)reason
         attributeService:(AttributeService)attService
               completion:(completion)completion
                  failure:(failure)faillure {

    NSMutableDictionary *query = [@{
                                    (__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
                                    (__bridge id)kSecReturnRef: (__bridge id)kCFBooleanTrue,
                                    (__bridge id)kSecUseOperationPrompt: reason
                                  } mutableCopy];

    CFStringRef attributeService = [self secAttServiceFromService:attService];
    if (attService == kAttributeServicePublicKey || attService == kAttributeServicePrivateKey) {
        [query setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [query setObject:(__bridge id)attributeService forKey:(__bridge id)kSecAttrApplicationTag];
    } else {
        [query setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
        [query setObject:(__bridge id)attributeService forKey:(__bridge id)kSecAttrService];
    }

    CFTypeRef dataTypeRef = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)([query copy]), &dataTypeRef);
    if (status == errSecSuccess) {
        NSDictionary *resultDictionary = (__bridge_transfer NSDictionary *)dataTypeRef;
        if (completion) {
            if (resultDictionary[(__bridge id)kSecValueRef]) {
                completion(resultDictionary[(__bridge id)kSecValueRef]);
            } else {
                completion(resultDictionary[(__bridge id)kSecValueData]);
            }
        }
        
    } else {
        if (faillure) {
            NSError *error = [IRErrorProvider errorWithMessage:[self keychainErrorFromStatus:status] errorCode:[self keychainErrorCodeFromStatus:status]];
            faillure(error);
        }
    }
}

- (BOOL)shouldGenerateEncryptionKey {
    return YES;
}

#pragma mark - Helpers

- (NSString *)keychainErrorFromStatus:(OSStatus)status {
    switch (status) {
        case errSecDuplicateItem:
            return NSLocalizedString(@"Key already exists",nil);
        case errSecItemNotFound:
            return NSLocalizedString(@"Key not found",nil);
        case errSecAuthFailed:
            return NSLocalizedString(@"Authentication failed",nil);
        case errSecParam:
            return NSLocalizedString(@"One or more parameters are not valid", nil);
    }
    
    return NSLocalizedString(@"Unknown Error",nil);
}

- (NSUInteger)keychainErrorCodeFromStatus:(OSStatus)status {
    switch (status) {
        case errSecDuplicateItem:
            return 7001;
        case errSecItemNotFound :
            return 7002;
        case errSecAuthFailed:
            return 7003;
    }
    
    return 7000;
}

- (BOOL)keyExistsWithReason:(NSString *)reason
           attributeService:(AttributeService)attService {

    NSMutableDictionary *query = [@{
                                    (__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
                                    (__bridge id)kSecReturnRef: (__bridge id)kCFBooleanTrue,
                                    (__bridge id)kSecUseOperationPrompt: reason
                                  } mutableCopy];

    CFStringRef attributeService = [self secAttServiceFromService:attService];
    if (attService == kAttributeServicePublicKey || attService == kAttributeServicePrivateKey) {
        [query setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [query setObject:(__bridge id)attributeService forKey:(__bridge id)kSecAttrApplicationTag];
    } else {
        [query setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
        [query setObject:(__bridge id)attributeService forKey:(__bridge id)kSecAttrService];
    }

    CFTypeRef dataTypeRef = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)([query copy]), &dataTypeRef);
    if (status == errSecSuccess) {
        NSDictionary *resultDictionary = (__bridge_transfer NSDictionary *)dataTypeRef;
        if (resultDictionary[(__bridge id)kSecValueData] ||
            resultDictionary[(__bridge id)kSecAttrAccessControl] ||
            resultDictionary[(__bridge id)kSecValueRef]) {
            return YES;
        }
    }
    
    return NO;
}

- (NSDictionary *)attributesForKeyProtection:(KeyProtection)keyProtection
                                keyDataOrRef:(id)keyDataOrRef
                               accessControl:(SecAccessControlRef)secACL
                            attributeService:(AttributeService)attService
                                     context:(LAContext *)context {

    NSMutableDictionary *attributes = [@{
                                        (__bridge id)kSecUseAuthenticationUI: (__bridge id)kCFBooleanFalse,
                                        (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)secACL,
                                        (__bridge id)kSecAttrSynchronizable: (__bridge id)kCFBooleanFalse,
                                        } mutableCopy];

    CFStringRef secClass = [self secClassFromService:attService];
    if (secClass != NULL) {
        [attributes setObject:(__bridge id)secClass forKey:(__bridge id)kSecClass];
    }

    CFStringRef keyAttClass = [self secAttrKeyClassFromService:attService];
    if (keyAttClass != NULL) {
        [attributes setObject:(__bridge id)keyAttClass forKey:(__bridge id)kSecAttrKeyClass];
    }

    CFStringRef attributeService = [self secAttServiceFromService:attService];
    if (attService == kAttributeServicePublicKey || attService == kAttributeServicePrivateKey) {
        [attributes setObject:(__bridge id)attributeService forKey:(__bridge id)kSecAttrApplicationTag];
    } else {
        [attributes setObject:(__bridge id)attributeService forKey:(__bridge id)kSecAttrService];
    }

    if ([keyDataOrRef isKindOfClass:[NSData class]]) {
        [attributes setObject:keyDataOrRef forKey:(__bridge id)kSecValueData];
    } else {
        [attributes setObject:keyDataOrRef forKey:(__bridge id)kSecValueRef];
    }
    
    if (keyProtection == kKeyProtectionPassword || keyProtection == kKeyProtectionPasswordAndTouchID) {
        if (context) {
            [attributes setObject:context forKey:(__bridge id)kSecUseAuthenticationContext];
        }
    }

    if (attService == kAttributeServicePublicKey || attService == kAttributeServicePrivateKey) {
        AsymmetricKeyType keyType = [self asymmetricKeyTypeFrom:(SecKeyRef)keyDataOrRef];
        switch (keyType) {
            case kAsymmetricKeyTypeEC:
                [attributes setObject:(__bridge id)kSecAttrKeyTypeEC forKey:(__bridge id)kSecAttrKeyType];
                break;
            case kAsymmetricKeyTypeRSA:
            case kAsymmetricKeyTypeUnknown:
            default:
                [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
                break;
        }
        [attributes setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnPersistentRef];
    }

    return [attributes copy];
}

- (CFStringRef)secAttServiceFromService:(AttributeService)service {
    switch (service) {
        case kAttributeServiceSymmetricKey:
            return kKeychainServiceSymmetricKey;

        case kAttributeServicePublicKey:
            return kKeychainServicePublicKey;
            
        case kAttributeServicePrivateKey:
            return kKeychainServicePrivateKey;

        case kAttributeServiceHMACKey:
            return kKeychainServiceHMACKey;
    }

    return kKeychainServiceDefault;
}

- (CFStringRef)secAttrKeyClassFromService:(AttributeService)service {
    switch (service) {
        case kAttributeServiceSymmetricKey:
        case kAttributeServiceHMACKey:
            return NULL;

        case kAttributeServicePublicKey:
            return kSecAttrKeyClassPublic;

        case kAttributeServicePrivateKey:
            return kSecAttrKeyClassPrivate;
    }

    return NULL;
}

- (CFStringRef)secClassFromService:(AttributeService)service {
    switch (service) {
        case kAttributeServiceSymmetricKey:
        case kAttributeServiceHMACKey:
            return kSecClassGenericPassword;

        case kAttributeServicePublicKey:
        case kAttributeServicePrivateKey:
            return kSecClassKey;
    }

    return kSecClassGenericPassword;
}

- (AsymmetricKeyType)asymmetricKeyTypeFrom:(SecKeyRef)keyRef {
    NSString *desc = (__bridge id)CFCopyDescription((SecKeyRef)keyRef);
    if ([desc containsString:kRSAKeyString]) {
        return kAsymmetricKeyTypeRSA;
    } else if ([desc containsString:kECKeyString]) {
        return kAsymmetricKeyTypeEC;
    }

    return kAsymmetricKeyTypeUnknown;
}

@end
