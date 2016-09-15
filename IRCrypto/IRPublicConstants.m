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

#import "IRPublicConstants.h"

@implementation IRPublicConstants

#pragma mark - Option Keys

NSString * const kIREncryptionOptionsKey = @"com.ivrodriguez.IREncryptionOptionsKey";
NSString * const kIRAsymmetricEncryptionAlgorithmKey = @"com.ivrodriguez.IRAsymmetricEncryptionAlgorithmKey";
NSString * const kIRSigningKeysKey = @"com.ivrodriguez.IRSigningKeysKey";

NSString * const kIRAsymmetricEncryptionProtectionKey = @"com.ivrodriguez.IRAsymmetricEncryptionProtectionKey";
NSString * const kIRSymmetricEncryptionProtectionKey = @"com.ivrodriguez.IRSymmetricEncryptionProtectionKey";
NSString * const kIRHMACProtectionKey = @"com.ivrodriguez.IRHMACProtectionKey";

NSString * const kIRAsymmetricEncryptionProtectionReasonKey = @"com.ivrodriguez.IRAsymmetricEncryptionProtectionReasonKey";
NSString * const kIRSymmetricEncryptionProtectionReasonKey = @"com.ivrodriguez.IRSymmetricEncryptionProtectionReasonKey";
NSString * const kIRHMACProtectionReasonKey = @"com.ivrodriguez.IRHMACProtectionReasonKey";

NSString * const kIRSymmetricEncryptionKeySizeKey = @"com.ivrodriguez.IRSymmetricEncryptionKeySizeKey";
NSString * const kIRHMACKeySizeKey = @"com.ivrodriguez.IRHMACKeySizeKey";

NSString * const kIRAppPasswordKey = @"com.ivrodriguez.IRAppPasswordKey";

@end
