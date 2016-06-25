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
#import "IREncryptionService.h"

@interface IREncryptionServiceSpec : XCTestCase

@property (nonatomic, strong) IREncryptionService *subject;

@end

@implementation IREncryptionServiceSpec

- (void)setUp {
    [super setUp];
    
    self.subject = [IREncryptionService new];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testGenerateRSAKeyPair {
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    BOOL success = [self.subject generateRSAKeyPair:^(SecKeyRef publicKey, SecKeyRef privateKey) {
        XCTAssertNotNil((__bridge id)publicKey);
        XCTAssertNotNil((__bridge id)privateKey);
        
        size_t publicKeySize = SecKeyGetBlockSize(publicKey);
        XCTAssertEqual(publicKeySize, 256); /* 2048bits / 8 */
        size_t privateKeySize = SecKeyGetBlockSize(privateKey);
        XCTAssertEqual(privateKeySize, 256); /* 2048bits / 8 */
        
        [completionExpectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
    
    XCTAssertTrue(success);
}

- (void)testGenerateECKeyPair {
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    BOOL success = [self.subject generateECKeyPair:^(SecKeyRef publicKey, SecKeyRef privateKey) {
        XCTAssertNotNil((__bridge id)publicKey);
        XCTAssertNotNil((__bridge id)privateKey);
        
        size_t publicKeySize = SecKeyGetBlockSize(publicKey);
        XCTAssertEqual(publicKeySize, 32); /* 256bits / 8 */
        size_t privateKeySize = SecKeyGetBlockSize(privateKey);
        XCTAssertEqual(privateKeySize, 32); /* 256bits / 8 */

        [completionExpectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
    
    XCTAssertTrue(success);
}

//TODO: Figure out how to test Keys generated in SecureEnclave

- (void)xtestGenerateKeyPairInSecureEnclave {
    BOOL success = [self.subject generateSigningKeyPairInSecureEnclave];
    XCTAssertTrue(success);
}

- (void)xtestSigningDataWithPrivateKeyStoredInSecureEnclave {
    NSData *randomData = [self dataOfLength:50];
    NSData *signedData = [self.subject signData:randomData userPromptReason:@"my-user-reason"];
    
    XCTAssertNotNil(signedData);
    XCTAssertNotEqual(signedData, randomData);
}

- (void)testGenerateEncryptionKey {
    NSUInteger keyLength = 256;
    NSData *key = [self.subject generateAESEncryptionKeyOfLength:keyLength];
    
    XCTAssertNotNil(key);
    XCTAssertEqual(key.length, keyLength);
}

- (void)testKeyDerivationFromString {
    NSUInteger keyLength = 16;
    NSData *salt = [self dataOfLength:keyLength];
    NSString *myString = @"my-string";
    
    NSData *derivedKey = [self.subject keyFromString:myString salt:salt keySize:keyLength];
    XCTAssertNotNil(derivedKey);
    XCTAssertEqual(derivedKey.length, keyLength);
    XCTAssertNotEqual(derivedKey, [myString dataUsingEncoding:NSUTF8StringEncoding]);
}

- (void)testKeyDerivationFromData {
    NSUInteger keyLength = 16;
    NSData *salt = [self dataOfLength:keyLength];
    NSData *myData = [@"my-string" dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *derivedKey = [self.subject keyFromData:myData salt:salt keySize:keyLength];
    XCTAssertNotNil(derivedKey);
    XCTAssertEqual(derivedKey.length, keyLength);
    XCTAssertNotEqualObjects(derivedKey, myData);
}

- (void)testKeyDerivationFromStringUsingSHA1 {
    NSUInteger keyLength = 16;
    NSData *salt = [self dataOfLength:keyLength];
    NSString *myString = @"my-string";
    
    NSData *derivedKey = [self.subject keyFromStringUsingSHA1:myString salt:salt keySize:keyLength];
    XCTAssertNotNil(derivedKey);
    XCTAssertEqual(derivedKey.length, keyLength);
    XCTAssertNotEqual(derivedKey, [myString dataUsingEncoding:NSUTF8StringEncoding]);
}

- (void)testHashingData {
    NSUInteger dataLength = 100; // Large Data
    NSUInteger hashLength = 32; // SHA256
    NSData *data = [self dataOfLength:dataLength];
    NSData *hash = [self.subject hashData:data];
    
    XCTAssertNotNil(hash);
    XCTAssertEqual(hash.length, hashLength);
}

- (void)testGenerateRandomBytes {
    NSUInteger bytesLength = 256;
    NSData *randomBytes = [self.subject randomBytesOfLength:bytesLength];
    
    XCTAssertNotNil(randomBytes);
    XCTAssertEqual(randomBytes.length, bytesLength);
}

- (void)testSigningCipherData {
    NSUInteger dataLength = 100; // Large Data
    NSUInteger keyLength = 16; // 128bits
    NSUInteger signedDataLength = 32; // SHA256
    NSData *cipherData = [self dataOfLength:dataLength];
    NSData *key = [self dataOfLength:keyLength];
    NSData *signedData = [self.subject hmacData:cipherData withKey:key];
    
    XCTAssertNotNil(signedData);
    XCTAssertEqual(signedData.length, signedDataLength);
}

- (void)testSymmetricEncryptionAndDecryption {
    NSUInteger keyLength = 32; // 256bits
    NSData *key = [self.subject generateAESEncryptionKeyOfLength:keyLength];
    NSData *copyOfKey = [key copy];
    NSData *iv = nil;
    NSData *mySecretData = [@"my-secret-string" dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *cipherData = [self.subject encryptData:mySecretData withKey:key iv:&iv];
    XCTAssertNotNil(cipherData);
    XCTAssertEqual(cipherData.length, keyLength); //Secret fits in 1 AES block
    
    //Key memory is deleted after decryption
    NSData *attackerPlainTextData = [self.subject decryptData:cipherData withKey:key iv:iv];
    XCTAssertNotNil(attackerPlainTextData);
    NSString *attackerPlainText = [[NSString alloc] initWithData:attackerPlainTextData encoding:NSUTF8StringEncoding];
    //Should not decrypt because key is 32bytes of 0xFF
    XCTAssertNil(attackerPlainText);
    
    //Decrypting with the key should still be possible
    NSData *plainTextData = [self.subject decryptData:cipherData withKey:copyOfKey iv:iv];
    XCTAssertNotNil(plainTextData);
    NSString *plainText = [[NSString alloc] initWithData:plainTextData encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(plainText, @"my-secret-string");
}

- (void)testSymmetricEncryptionAndDecryptionOfLongMessage {
    NSUInteger keyLength = 32; // 256bits
    NSData *key = [self.subject generateAESEncryptionKeyOfLength:keyLength];
    NSData *copyOfKey = [key copy];
    NSData *iv = nil;
    NSData *mySecretData = [@"my-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-secret-string" dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *cipherData = [self.subject encryptData:mySecretData withKey:key iv:&iv];
    XCTAssertNotNil(cipherData);
    
    //Key memory is deleted after decryption
    NSData *attackerPlainTextData = [self.subject decryptData:cipherData withKey:key iv:iv];
    XCTAssertNotNil(attackerPlainTextData);
    NSString *attackerPlainText = [[NSString alloc] initWithData:attackerPlainTextData encoding:NSUTF8StringEncoding];
    //Should not decrypt because key is 32bytes of 0xFF
    XCTAssertNil(attackerPlainText);
    
    //Decrypting with the key should still be possible
    NSData *plainTextData = [self.subject decryptData:cipherData withKey:copyOfKey iv:iv];
    XCTAssertNotNil(plainTextData);
    NSString *plainText = [[NSString alloc] initWithData:plainTextData encoding:NSUTF8StringEncoding];
    XCTAssertEqualObjects(plainText, @"my-long-long-long-long-long-long-long-long-long-long-long-long-long-long-long-secret-string");
}

- (void)testAsymmetricEncryption {
    XCTestExpectation *completionExpectation = [self expectationWithDescription:@"Completion Expectation"];
    BOOL success = [self.subject generateRSAKeyPair:^(SecKeyRef publicKey, SecKeyRef privateKey) {
        XCTAssertNotNil((__bridge id)publicKey);
        XCTAssertNotNil((__bridge id)privateKey);
        
        size_t publicKeySize = SecKeyGetBlockSize(publicKey);
        XCTAssertEqual(publicKeySize, 256); /* 2048bits / 8 */
        size_t privateKeySize = SecKeyGetBlockSize(privateKey);
        XCTAssertEqual(privateKeySize, 256); /* 2048bits / 8 */
        
        //Generate an AES key
        NSUInteger keyLength = 16;
        NSData *aesKey = [self.subject generateAESEncryptionKeyOfLength:keyLength];
        NSData *copyOfAESKey = [aesKey copy];
        NSData *iv = nil;
        
        //Encrypt data using AES
        NSData *mySecretData = [@"my-secret-string" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *cipherData = [self.subject encryptData:mySecretData withKey:aesKey iv:&iv];
        XCTAssertNotNil(cipherData);
        XCTAssertNotNil(iv);
        
        //Encrypt the AES key using the asymmetric public key
        NSData *asymmetricCipherData = [self.subject encryptData:copyOfAESKey publicKey:publicKey];
        XCTAssertNotNil(asymmetricCipherData);
        
        //Decrypt the AES key with the asymmetric private key
        NSData *decryptedAESKey = [self.subject decryptData:asymmetricCipherData privateKey:privateKey];
        
        //Decrypt the data using the decrypted AES key
        NSData *plainTextData = [self.subject decryptData:cipherData withKey:decryptedAESKey iv:iv];
        XCTAssertNotNil(plainTextData);
        NSString *plainText = [[NSString alloc] initWithData:plainTextData encoding:NSUTF8StringEncoding];
        XCTAssertEqualObjects(plainText, @"my-secret-string");
        
        [completionExpectation fulfill];
    }];
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
    
    XCTAssertTrue(success);
}

//Helpers

- (NSData *)dataOfLength:(NSUInteger)length {
    unsigned char r_data[length];
    for (NSUInteger i=0;i<length;++i) {
        r_data[i] = arc4random() % 255;
    }
    return [NSData dataWithBytes:r_data length:length];
}

@end