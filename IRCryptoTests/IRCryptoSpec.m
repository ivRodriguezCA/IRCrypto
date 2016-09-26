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
#import "IRCrypto.h"

@interface IRCryptoSpec : XCTestCase

@property (nonnull, strong) IRCrypto *subject;

@end

@implementation IRCryptoSpec

- (void)setUp {
    [super setUp];
    
    self.subject = [[IRCrypto alloc] initWithOptions:@{kIREncryptionOptionsKey:@(kEncryptionOptionsNone)}];
}

- (void)tearDown {
    [super tearDown];
}

#pragma mark - Authenticated Encryption (RNCryptor Data Format v3.0)

- (void)testAuthenticatedEncryptionWithKey {
    NSData *mySecretData = [@"my-long-long-long-long-long-long-long-long-secret-string" dataUsingEncoding:NSUTF8StringEncoding];
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    NSData *aesKey = [self dataOfLength:32];
    NSData *hmacKey = [self dataOfLength:32];
    [self.subject aeEncryptData:mySecretData
                   symmetricKey:aesKey
                        hmacKey:hmacKey
                     completion:^(NSData *cipherData, NSData *iv, NSData *encryptionSalt, NSData *hmacSalt) {

                         XCTAssertNotNil(cipherData);
                         XCTAssertNotNil(iv);
                         XCTAssertNil(encryptionSalt);
                         XCTAssertNil(hmacSalt);
                         [completionExpectation fulfill];

                     } failure:^(NSError *error) {}];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testAuthenticatedEncryptionWithPassword {
    NSData *mySecretData = [@"my-long-long-long-long-long-long-long-long-secret-string" dataUsingEncoding:NSUTF8StringEncoding];
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    NSString *password = @"my-secret-password";
    [self.subject aeEncryptData:mySecretData
                       password:password
                     completion:^(NSData *cipherData, NSData *iv, NSData *encryptionSalt, NSData *hmacSalt) {

                         XCTAssertNotNil(cipherData);
                         XCTAssertNotNil(iv);
                         XCTAssertNotNil(encryptionSalt);
                         XCTAssertNotNil(hmacSalt);
                         [completionExpectation fulfill];

                     } failure:^(NSError *error) {}];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testAuthenticatedDecryptionWithKey {
    NSData *mySecretData = [@"my-long-long-long-long-long-long-long-long-secret-string" dataUsingEncoding:NSUTF8StringEncoding];
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    NSData *aesKey = [self staticKeyOfLength:32];
    NSData *hmacKey = [self staticKeyOfLength:32];
    [self.subject aeEncryptData:mySecretData
                   symmetricKey:aesKey
                        hmacKey:hmacKey
                     completion:^(NSData *cipherData, NSData *iv, NSData *encryptionSalt, NSData *hmacSalt) {

                         XCTAssertNotNil(cipherData);
                         XCTAssertNotNil(iv);
                         XCTAssertNil(encryptionSalt);
                         XCTAssertNil(hmacSalt);

                         NSData *aesKey = [self staticKeyOfLength:32];
                         NSData *hmacKey = [self staticKeyOfLength:32];
                         [self.subject aeDecryptData:cipherData
                                        symmetricKey:aesKey
                                             hmacKey:hmacKey
                                          completion:^(NSData *decryptedData) {

                                              NSString *plaintext = [[NSString alloc] initWithData:decryptedData
                                                                                          encoding:NSUTF8StringEncoding];
                                              XCTAssertNotNil(decryptedData);
                                              XCTAssertEqualObjects(plaintext, @"my-long-long-long-long-long-long-long-long-secret-string");
                                              [completionExpectation fulfill];

                                          } failure:^(NSError *error) {}];

                     } failure:^(NSError *error) {}];

    [self waitForExpectationsWithTimeout:10.0 handler:nil];
}

- (void)testAuthenticatedDecryptionWithPassword {
    NSData *mySecretData = [@"my-long-long-long-long-long-long-long-long-secret-string" dataUsingEncoding:NSUTF8StringEncoding];
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    NSString *password = @"my-secret-password";
    [self.subject aeEncryptData:mySecretData
                       password:password
                     completion:^(NSData *cipherData, NSData *iv, NSData *encryptionSalt, NSData *hmacSalt) {

                         XCTAssertNotNil(cipherData);
                         XCTAssertNotNil(iv);
                         XCTAssertNotNil(encryptionSalt);
                         XCTAssertNotNil(hmacSalt);

                         [self.subject aeDecryptData:cipherData
                                            password:password
                                          completion:^(NSData *decryptedData) {
                                              NSString *plaintext = [[NSString alloc] initWithData:decryptedData
                                                                                          encoding:NSUTF8StringEncoding];
                                              XCTAssertNotNil(decryptedData);
                                              XCTAssertEqualObjects(plaintext, @"my-long-long-long-long-long-long-long-long-secret-string");
                                              [completionExpectation fulfill];

                                          } failure:^(NSError *error) {}];

                     } failure:^(NSError *error) {}];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testAuthenticatedDecryptionWithKeyAttack {
    NSData *mySecretData = [@"my-long-long-long-long-long-long-long-long-secret-string" dataUsingEncoding:NSUTF8StringEncoding];
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    NSData *aesKey = [self dataOfLength:32];
    NSData *hmacKey = [self dataOfLength:32];
    [self.subject aeEncryptData:mySecretData
                   symmetricKey:aesKey
                        hmacKey:hmacKey
                     completion:^(NSData *cipherData, NSData *iv, NSData *encryptionSalt, NSData *hmacSalt) {

                         [self.subject aeDecryptData:cipherData
                                        symmetricKey:aesKey
                                             hmacKey:hmacKey
                                          completion:^(NSData *decryptedData) {

                                          } failure:^(NSError *error) {
                                              //Should fail to decrypt trying to reuse the in-memory keys
                                              XCTAssertNotNil(error);
                                              [completionExpectation fulfill];
                                          }];

                     } failure:^(NSError *error) {}];

    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testCompatibilityDecryptionWithRNCryptorLibraryUsingKey {
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    NSData *aesKey = [self staticKeyOfLength:32];
    NSData *hmacKey = [self staticKeyOfLength:32];
    NSData *cipherData = [self readRNCryptorFile:@"RNCryptor-EncryptedDataWithKey"];

    [self.subject aeDecryptData:cipherData
                   symmetricKey:aesKey
                        hmacKey:hmacKey
                     completion:^(NSData *decryptedData) {

                         XCTAssertNotNil(decryptedData);
                         NSString *plaintext = [[NSString alloc] initWithData:decryptedData
                                                                     encoding:NSUTF8StringEncoding];
                         XCTAssertEqualObjects(plaintext, @"My secret message encrypted with Key using RNCryptor library");
                         [completionExpectation fulfill];
                         
                     } failure:^(NSError *error) {}];
    
    [self waitForExpectationsWithTimeout:10.0 handler:nil];
}

- (void)testCompatibilityDecryptionWithRNCryptorLibraryUsingPassword {
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    NSData *cipherData = [self readRNCryptorFile:@"RNCryptor-EncryptedDataWithPassword"];
    NSString *password = @"my-secret-password";
    
    [self.subject aeCompatibilityModeDecryptData:cipherData password:password completion:^(NSData *decryptedData) {
        XCTAssertNotNil(decryptedData);
        NSString *plaintext = [[NSString alloc] initWithData:decryptedData
                                                    encoding:NSUTF8StringEncoding];
        XCTAssertEqualObjects(plaintext, @"My secret message encrypted with Password using RNCryptor library");
        [completionExpectation fulfill];
        
    } failure:^(NSError *error) {}];
    
    [self waitForExpectationsWithTimeout:10.0 handler:nil];
}

#pragma mark - Symmetric Encryption (AES)

- (void)testSymmetricEncryptionWithKey {
    NSData *mySecretData = [@"my-long-long-long-long-long-long-long-long-secret-string" dataUsingEncoding:NSUTF8StringEncoding];
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    NSData *aesKey = [self dataOfLength:32];
    [self.subject encryptData:mySecretData
                      withKey:aesKey
                   completion:^(NSData *cipherData, NSData *iv, NSData *salt) {
           XCTAssertNotNil(cipherData);
           XCTAssertNotNil(iv);
           XCTAssertNil(salt);
           [completionExpectation fulfill];
        
    } failure:^(NSError * _Nonnull error) {}];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testSymmetricEncryptionWithPassword {
    NSData *mySecretData = [@"my-long-long-long-long-long-long-long-long-secret-string" dataUsingEncoding:NSUTF8StringEncoding];
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    NSString *password = @"my-secret-password";
    [self.subject encryptData:mySecretData
                  withPassword:password
                   completion:^(NSData *cipherData, NSData *iv, NSData *salt) {
           XCTAssertNotNil(cipherData);
           XCTAssertNotNil(iv);
           XCTAssertNotNil(salt);
           [completionExpectation fulfill];
                       
    } failure:^(NSError * _Nonnull error) {}];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

#pragma mark - Symmetric Decryption (AES)

- (void)testSymmetricDecryptionWithKey {
    NSData *mySecretData = [@"my-long-long-long-long-long-long-long-long-secret-string" dataUsingEncoding:NSUTF8StringEncoding];
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    NSData *aesKey = [self staticKeyOfLength:32];
    [self.subject encryptData:mySecretData
                      withKey:aesKey
                   completion:^(NSData *cipherData, NSData *iv, NSData *salt) {
           XCTAssertNotNil(cipherData);
           XCTAssertNotNil(iv);
           XCTAssertNil(salt);
                       
           NSData *aesKey = [self staticKeyOfLength:32];
           [self.subject decryptData:cipherData
                             withKey:aesKey
                                  iv:iv
                          completion:^(NSData *decryptedData) {
              
               XCTAssertNotNil(decryptedData);
               NSString *plaintext = [[NSString alloc] initWithData:decryptedData
                                                          encoding:NSUTF8StringEncoding];
               XCTAssertEqualObjects(plaintext, @"my-long-long-long-long-long-long-long-long-secret-string");
               [completionExpectation fulfill];
                              
           } failure:^(NSError * _Nonnull error) {}];
       
    } failure:^(NSError * _Nonnull error) {}];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

- (void)testSymmetricDecryptionWithPassword {
    NSData *mySecretData = [@"my-long-long-long-long-long-long-long-long-secret-string" dataUsingEncoding:NSUTF8StringEncoding];
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    NSString *password = @"my-secret-password";
    [self.subject encryptData:mySecretData
                 withPassword:password
                   completion:^(NSData *cipherData, NSData *iv, NSData *salt) {
           XCTAssertNotNil(cipherData);
           XCTAssertNotNil(iv);
           XCTAssertNotNil(salt);
                       
           [self.subject decryptData:cipherData
                         withPassword:password
                                  iv:iv
                                salt:salt
                          completion:^(NSData *decryptedData) {
                              
              XCTAssertNotNil(decryptedData);
              NSString *plaintext = [[NSString alloc] initWithData:decryptedData
                                                          encoding:NSUTF8StringEncoding];
              XCTAssertEqualObjects(plaintext, @"my-long-long-long-long-long-long-long-long-secret-string");
              [completionExpectation fulfill];
                              
            } failure:^(NSError * _Nonnull error) {}];
                       
    } failure:^(NSError * _Nonnull error) {}];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

#pragma mark - Key Generation

- (void)testRandomAESKeyGeneration {
    NSData *key = [self.subject randomAESEncryptionKeyOfLength:32];
    XCTAssertNotNil(key);
    XCTAssertEqual(key.length, 32);
}

- (void)testRandomHMACKeyGeneration {
    NSData *key = [self.subject randomHMACKeyOfLength:16];
    XCTAssertNotNil(key);
    XCTAssertEqual(key.length, 16);
}

- (void)testKeyFromPasswordGeneration {
    NSString *password = @"my-secret-password";
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    [self.subject keyFromPassword:password
                         ofLength:32
                       completion:^(NSData * _Nonnull key, NSData * _Nonnull salt) {
                           XCTAssertNotNil(key);
                           XCTAssertNotNil(salt);
                           XCTAssertEqual(key.length, 32);

                           [completionExpectation fulfill];
                       }];
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

//Helpers

- (NSData *)dataOfLength:(NSUInteger)length {
    unsigned char r_data[length];
    for (NSUInteger i=0;i<length;++i) {
        r_data[i] = arc4random() % 255;
    }
    return [NSData dataWithBytes:r_data length:length];
}

- (NSData *)staticKeyOfLength:(NSUInteger)length {
    const char key[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return [NSData dataWithBytes:key length:32];
}

- (NSData *)readRNCryptorFile:(NSString *)filename {
    NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:filename ofType:@"txt"];
    NSString *content = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    NSArray *lines = [content componentsSeparatedByString:@"\n"];
    for (NSString *line in lines) {
        if (![line containsString:@"//"]) {
            return [self dataWithHexString:line];
        }
    }
    
    return nil;
}

//Extracted from: https://opensource.apple.com/source/Security/Security-55471.14.18/libsecurity_transform/NSData+HexString.m
- (NSData *)dataWithHexString:(NSString *)hexSring {
    char buf[3];
    buf[2] = '\0';
    unsigned char *bytes = malloc([hexSring length]/2);
    unsigned char *bp = bytes;
    for (CFIndex i = 0; i < [hexSring length]; i += 2) {
        buf[0] = [hexSring characterAtIndex:i];
        buf[1] = [hexSring characterAtIndex:i+1];
        char *b2 = NULL;
        *bp++ = strtol(buf, &b2, 16);
    }
    
    return [NSData dataWithBytesNoCopy:bytes length:[hexSring length]/2 freeWhenDone:YES];
}

@end
