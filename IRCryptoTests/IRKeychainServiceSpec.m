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

#import <XCTest/XCTest.h>
#import "IRKeychainService.h"

@interface IRKeychainServiceSpec : XCTestCase

@property (nonatomic, strong) IRKeychainService *subject;

@end

@implementation IRKeychainServiceSpec

- (void)setUp {
    [super setUp];
    
    self.subject = [IRKeychainService new];
}

- (void)tearDown {
    [super tearDown];
}

//Fail Cases

- (void)testSavingAnInvalidKeyWithTouchID {
    NSError *error = [self.subject saveKeyProtectedWithTouchID:nil userPromptReason:@"my-user-reason" attributeService:kAttributeServiceSymmetricKey];
    XCTAssertNotNil(error);
    XCTAssertEqualObjects(error.userInfo[NSLocalizedDescriptionKey], @"Invalid Key");
}

- (void)testSavingAnInvalidPasswordProtectedWithPassword {
    XCTestExpectation *failureExpectation = [self expectationWithDescription:@"Failure block"];
    //Generate Random Key
    NSData *key = [self dataOfLength:16];
    [self.subject saveKeyProtectedWithPassword:key applicationPassword:nil userPromptReason:@"my-user-reason" attributeService:kAttributeServicePublicKey failure:^(NSError *error) {
        XCTAssertNotNil(error);
        XCTAssertEqualObjects(error.userInfo[NSLocalizedDescriptionKey], @"Invalid Application Password");
        [failureExpectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testSavingAnInvalidKeyProtectedWithPassword {
    XCTestExpectation *failureExpectation = [self expectationWithDescription:@"Failure block"];
    [self.subject saveKeyProtectedWithPassword:nil applicationPassword:nil userPromptReason:@"my-user-reason" attributeService:kAttributeServicePublicKey failure:^(NSError *error) {
        XCTAssertNotNil(error);
        XCTAssertEqualObjects(error.userInfo[NSLocalizedDescriptionKey], @"Invalid Key");
        [failureExpectation fulfill];
    }];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}


- (void)testSavingAnInvalidKeyProtectedWithPasswordAndTouchID {
    XCTestExpectation *failureExpectation = [self expectationWithDescription:@"Failure block"];
    [self.subject saveKeyProtectedWithTouchIDAndPassword:nil userPromptReason:@"my-user-reason" attributeService:kAttributeServicePublicKey failure:^(NSError *error) {
        XCTAssertNotNil(error);
        XCTAssertEqualObjects(error.userInfo[NSLocalizedDescriptionKey], @"Invalid Key");
        [failureExpectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testDeletingANonExistingKey {
    NSError *error = [self.subject deleteKeyWithAttributeService:kAttributeServiceSymmetricKey];
    XCTAssertNotNil(error);
    XCTAssertEqualObjects(error.userInfo[NSLocalizedDescriptionKey], @"Key not found");
}

- (void)testLoadingAnInvalidKey {
    XCTestExpectation *failureExpectation = [self expectationWithDescription:@"Failure block"];
    [self.subject loadKeyWithReason:@"my-user-reason" attributeService:kAttributeServicePublicKey completion:nil failure:^(NSError *error) {
        XCTAssertNotNil(error);
        XCTAssertEqualObjects(error.userInfo[NSLocalizedDescriptionKey], @"Key not found");
        [failureExpectation fulfill];
    }];
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

//Success Cases

- (void)testSavingAValidSymmetricKeyWithTouchIDLoadingTheKeyAndDeletingTheKey {
    //Generate Random Key
    NSData *key = [self dataOfLength:16];
    
    //Save Random Key as Symmetric Key
    NSError *error = [self.subject saveKeyProtectedWithTouchID:key userPromptReason:@"my-user-reason" attributeService:kAttributeServiceSymmetricKey];
    XCTAssertNil(error);
    
    //Load Symmetric Key
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion block"];
    [self.subject loadKeyWithReason:@"my-user-reason" attributeService:kAttributeServiceSymmetricKey completion:^(NSData *keyData) {
        XCTAssertNotNil(keyData);
        XCTAssertEqualObjects(keyData, key);
        [completionExpectation fulfill];
    } failure:nil];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
    
    //Delete Key After test
    [self.subject deleteKeyWithAttributeService:kAttributeServiceSymmetricKey];
}

- (void)testSavingAValidSymmetricKeyWithPasswordAndDeletingTheKey {
    //Generate Random Key
    NSData *key = [self dataOfLength:16];
    [self.subject saveKeyProtectedWithPassword:key applicationPassword:@"my-password" userPromptReason:@"my-user-reason" attributeService:kAttributeServiceSymmetricKey failure:nil];

    //Load Symmetric Key
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion block"];
    [self.subject loadKeyWithReason:@"my-user-reason" attributeService:kAttributeServiceSymmetricKey completion:^(NSData *keyData) {
        XCTAssertNotNil(keyData);
        XCTAssertEqualObjects(keyData, key);
        [completionExpectation fulfill];
    } failure:nil];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];

    //Delete Key After test
    [self.subject deleteKeyWithAttributeService:kAttributeServiceSymmetricKey];
}

- (void)testSavingAValidECPublicKeyWithPasswordAndDeletingTheKey {
    SecKeyRef publicKey = [self ecPublicKey];
    [self.subject saveKeyProtectedWithPassword:(__bridge id)publicKey applicationPassword:@"my-password" userPromptReason:@"my-user-reason" attributeService:kAttributeServicePublicKey failure:nil];

    //Load Public Key
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion block"];
    [self.subject loadKeyWithReason:@"my-user-reason" attributeService:kAttributeServicePublicKey completion:^(id keyData) {
        SecKeyRef publicKeyData = (__bridge SecKeyRef)keyData;
        XCTAssertNotNil((__bridge id)publicKeyData);
        XCTAssertEqualObjects((__bridge id)publicKeyData, (__bridge id)publicKey);
        CFRelease(publicKey);
        [completionExpectation fulfill];
    } failure:nil];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];

    //Delete Key After test
    [self.subject deleteKeyWithAttributeService:kAttributeServicePublicKey];
}

- (void)testSavingAValidECPrivateKeyWithPasswordAndDeletingTheKey {
    SecKeyRef privateKey = [self ecPrivateKey];
    [self.subject saveKeyProtectedWithPassword:(__bridge id)privateKey applicationPassword:@"my-password" userPromptReason:@"my-user-reason" attributeService:kAttributeServicePrivateKey failure:nil];

    //Load Private Key
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion block"];
    [self.subject loadKeyWithReason:@"my-user-reason" attributeService:kAttributeServicePrivateKey completion:^(id keyData) {
        SecKeyRef privateKeyData = (__bridge SecKeyRef)keyData;
        XCTAssertNotNil((__bridge id)privateKeyData);
        XCTAssertEqualObjects((__bridge id)privateKeyData, (__bridge id)privateKey);
        CFRelease(privateKey);
        [completionExpectation fulfill];
    } failure:nil];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];

    //Delete Key After test
    [self.subject deleteKeyWithAttributeService:kAttributeServicePrivateKey];
}

- (void)testSavingAValidRSAPublicKeyWithPasswordAndDeletingTheKey {
    SecKeyRef publicKey = [self rsaPublicKey];
    [self.subject saveKeyProtectedWithPassword:(__bridge id)publicKey applicationPassword:@"my-password" userPromptReason:@"my-user-reason" attributeService:kAttributeServicePublicKey failure:nil];

    //Load Public Key
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion block"];
    [self.subject loadKeyWithReason:@"my-user-reason" attributeService:kAttributeServicePublicKey completion:^(id keyData) {
        SecKeyRef publicKeyData = (__bridge SecKeyRef)keyData;
        XCTAssertNotNil((__bridge id)publicKeyData);
        XCTAssertEqualObjects((__bridge id)publicKeyData, (__bridge id)publicKey);
        CFRelease(publicKey);
        [completionExpectation fulfill];
    } failure:nil];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];

    //Delete Key After test
    [self.subject deleteKeyWithAttributeService:kAttributeServicePublicKey];
}

- (void)testSavingAValidRSAPrivateKeyWithPasswordAndDeletingTheKey {
    SecKeyRef privateKey = [self rsaPrivateKey];
    [self.subject saveKeyProtectedWithPassword:(__bridge id)privateKey applicationPassword:@"my-password" userPromptReason:@"my-user-reason" attributeService:kAttributeServicePrivateKey failure:nil];

    //Load Public Key
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion block"];
    [self.subject loadKeyWithReason:@"my-user-reason" attributeService:kAttributeServicePrivateKey completion:^(id keyData) {
        SecKeyRef privateKeyData = (__bridge SecKeyRef)keyData;
        XCTAssertNotNil((__bridge id)privateKeyData);
        XCTAssertEqualObjects((__bridge id)privateKeyData, (__bridge id)privateKey);
        CFRelease(privateKey);
        [completionExpectation fulfill];
    } failure:nil];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];

    //Delete Key After test
    [self.subject deleteKeyWithAttributeService:kAttributeServicePrivateKey];
}

//TODO: Figure out how to test [LAContext] evaluateAccessControl:operation:localizedReason:reply

// Helpers

- (NSData *)dataOfLength:(NSUInteger)length {
    unsigned char r_data[length];
    for (NSUInteger i=0;i<length;++i) {
        r_data[i] = arc4random() % 255;
    }
    return [NSData dataWithBytes:r_data length:length];
}

- (SecKeyRef)ecPublicKey {
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
        CFRelease(privateKey);

        return publicKey;
    }

    return NULL;
}

- (SecKeyRef)ecPrivateKey {
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
        CFRelease(publicKey);

        return privateKey;
    }

    return NULL;
}

- (SecKeyRef)rsaPublicKey {
    NSDictionary *parameters = @{
                                 (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                                 (__bridge id)kSecAttrKeySizeInBits: @1024,
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
        CFRelease(privateKey);

        return publicKey;
    }

    return NULL;
}

- (SecKeyRef)rsaPrivateKey {
    NSDictionary *parameters = @{
                                 (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                                 (__bridge id)kSecAttrKeySizeInBits: @1024,
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
        CFRelease(publicKey);

        return privateKey;
    }

    return NULL;
}

@end
