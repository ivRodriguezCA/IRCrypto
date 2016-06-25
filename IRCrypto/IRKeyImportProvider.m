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

/*
 This is literally just an Objc version of https://github.com/DigitalLeaves/CryptoExportImportManager/blob/master/CryptoLoadExternalCertificate/CryptoExportImportManager.swift#L95
 
 Read more: https://digitalleaves.com/blog/2015/10/sharing-public-keys-between-ios-and-the-rest-of-the-world
 
 by Ignacio Nieto Carvajal
*/

#import "IRKeyImportProvider.h"

@implementation IRKeyImportProvider

- (SecKeyRef)publicKeyReferenceFromDERCert:(NSData *)cert {
    SecCertificateRef certRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)cert);
    if (certRef == nil) { return nil; }
    
    SecTrustRef trustRef = NULL;
    OSStatus status = SecTrustCreateWithCertificates(certRef, NULL, &trustRef);
    
    if (status == errSecSuccess) {
        SecTrustResultType resultType = kSecTrustResultInvalid;
        OSStatus newStatus = SecTrustEvaluate(trustRef, &resultType);
        
        if (newStatus == errSecSuccess) {
            return SecTrustCopyPublicKey(trustRef);
        }
    }
    
    return nil;
}

@end