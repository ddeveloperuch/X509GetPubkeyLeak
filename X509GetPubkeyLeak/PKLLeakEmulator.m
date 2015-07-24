//
//  PKLLeakEmulator.m
//  X509GetPubkeyLeak
//
//  Created by Developer on 7/24/15.
//  Copyright (c) 2015 Developer. All rights reserved.
//
// ********************************************************************************************************************************************************** //

#import "PKLLeakEmulator.h"
#import "PKLX509Certificate.h"

// ********************************************************************************************************************************************************** //

@implementation PKLLeakEmulator

+ (void)startLeakEmulation
{
    sleep(5);
    
    X509 *X509Certificate = NULL;
    EVP_PKEY *orig_pkey = NULL;
    
    for (int i = 0; i < 5; i++)
    {
        X509Certificate = PKLGenerateTestX509Certificate(NID_X9_62_prime256v1);
        orig_pkey = X509_get_pubkey(X509Certificate);
        
        EVP_PKEY_free(orig_pkey);
        X509_free(X509Certificate );
    }
}

@end
