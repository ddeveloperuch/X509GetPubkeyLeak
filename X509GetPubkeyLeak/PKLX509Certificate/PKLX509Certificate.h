//
//  PKLX509Certificate.h
//  X509GetPubkeyLeak
//
//  Created by Developer on 7/24/15.
//  Copyright (c) 2015 Developer. All rights reserved.
//
// ********************************************************************************************************************************************************** //

#ifndef __PKLX509CERTIFICATE_H__
#define __PKLX509CERTIFICATE_H__

#include <openssl/x509v3.h>

X509 * PKLGenerateTestX509Certificate(int curve_name);

#endif // __PKLX509CERTIFICATE_H__