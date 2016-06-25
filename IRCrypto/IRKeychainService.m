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
                                                                    kSecAccessControlApplicationPassword,
                                                                    &error);
    
    if (secACL == NULL || error != NULL) {
        if (faillure) {
            faillure([IRErrorProvider genericError]);
        }
    }
    
    LAContext *context = [LAContext new];
    [context evaluateAccessControl:secACL operation:LAAccessControlOperationCreateItem localizedReason:reason reply:^(BOOL success, NSError *error) {
        if (success) {
            NSDictionary *attributes = [self attributesForKeyProtection:kKeyProtectionPasswordAndTouchID keyDataOrRef:keyDataOrRef accessControl:secACL attributeService:attService context:context];
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
    NSString *attributeService = [self attServiceFromService:attService];
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: attributeService
                            };
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
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
    
    NSString *attributeService = [self attServiceFromService:attService];
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: attributeService,
                            (__bridge id)kSecReturnData: @YES,
                            (__bridge id)kSecReturnRef: @YES,
                            (__bridge id)kSecUseOperationPrompt: reason
                            };

    CFTypeRef dataTypeRef = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
    if (status == errSecSuccess) {
        NSDictionary *resultDictionary = (__bridge_transfer NSDictionary *)dataTypeRef;
        if (completion) {
            if (attService == kAttributeServiceSymmetricKey) {
                completion(resultDictionary[@"v_Data"]);
            } else {
                completion(resultDictionary[@"accc"]);
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
    
    NSString *attributeService = [self attServiceFromService:attService];
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: attributeService,
                            (__bridge id)kSecReturnData: @YES,
                            (__bridge id)kSecReturnRef: @YES,
                            (__bridge id)kSecUseOperationPrompt: reason
                            };
    
    CFTypeRef dataTypeRef = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
    if (status == errSecSuccess) {
        NSDictionary *resultDictionary = (__bridge_transfer NSDictionary *)dataTypeRef;
        if (resultDictionary[@"v_Data"] || resultDictionary[@"accc"]) {
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
    
    NSString *attributeService = [self attServiceFromService:attService];
    NSMutableDictionary *attributes = [@{
                                        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                        (__bridge id)kSecAttrService: attributeService,
                                        (__bridge id)kSecUseAuthenticationUI: @NO,
                                        (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)secACL
                                        } mutableCopy];
    
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
    
    return [attributes copy];
}

- (NSString *)attServiceFromService:(AttributeService)service {
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

@end