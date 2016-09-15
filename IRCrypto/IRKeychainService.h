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
#import "IRPublicConstants.h"

typedef void (^completion)(id keyData);
typedef void (^failure)(NSError *error);

@interface IRKeychainService : NSObject

#pragma mark - Key Storing

- (NSError *)saveKeyProtectedWithTouchID:(id)keyDataOrRef
                        userPromptReason:(NSString *)reason
                        attributeService:(AttributeService)attService;

- (void)saveKeyProtectedWithPassword:(id)keyDataOrRef
                 applicationPassword:(NSString *)appPasword
                    userPromptReason:(NSString *)reason
                    attributeService:(AttributeService)attService
                             failure:(failure)faillure;

- (void)saveKeyProtectedWithTouchIDAndPassword:(id)keyDataOrRef
                              userPromptReason:(NSString *)reason
                              attributeService:(AttributeService)attService
                                       failure:(failure)faillure;

#pragma mark - Key Deletion

- (NSError *)deleteKeyWithAttributeService:(AttributeService)attService;

#pragma mark - Key Querying

- (void)loadKeyWithReason:(NSString *)reason
         attributeService:(AttributeService)attService
               completion:(completion)completion
                  failure:(failure)faillure;

@end
