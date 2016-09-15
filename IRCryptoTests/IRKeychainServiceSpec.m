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

- (void)testSavingAValidKeyWithTouchIDLoadingTheKeyAndDeletingTheKey {
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

//TODO: Figure out how to test [LAContext] evaluateAccessControl:operation:localizedReason:reply

// Helpers

- (NSData *)dataOfLength:(NSUInteger)length {
    unsigned char r_data[length];
    for (NSUInteger i=0;i<length;++i) {
        r_data[i] = arc4random() % 255;
    }
    return [NSData dataWithBytes:r_data length:length];
}

@end
