//
//  PKLX509Certificate.m
//  X509GetPubkeyLeak
//
//  Created by Developer on 7/24/15.
//  Copyright (c) 2015 Developer. All rights reserved.
//
// ********************************************************************************************************************************************************** //

static NSString * const kTPPCountryName = @"PG";
static NSString * const kTPPStateOfProvinceName = @"Papua New Guinea";
static NSString * const kTPPLocalityName = @"Papua New Guinea";
static NSString * const kTPPOrganizationName = @"Company Ltd.";
static NSString * const kTPPCommonName = @"EC Test";

// ********************************************************************************************************************************************************** //

EVP_PKEY * PKLGenerateECKeyPair(int curve_name);
X509 * PKLGenerateX509CertificateWithBits(int curve_name, NSString *countryName, NSString *stateOrProvinceName, NSString *localityName, NSString *organizationName, NSString *commonName);
static unsigned long serial_number();

// ********************************************************************************************************************************************************** //

X509 * PKLGenerateTestX509Certificate(int curve_name)
{
    return PKLGenerateX509CertificateWithBits(curve_name, kTPPCountryName, kTPPStateOfProvinceName, kTPPLocalityName, kTPPOrganizationName, kTPPCommonName);
}

EVP_PKEY * PKLGenerateECKeyPair(int curve_name)
{
    int result = 0;
    EVP_PKEY *pkey;
    
    EC_KEY *ec_key = EC_KEY_new();
    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(curve_name);
    
    EC_KEY_set_group(ec_key, ec_group);
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE); //ASN1 OID: prime256v1
    
    EC_KEY_generate_key(ec_key);
    
    result = EC_KEY_check_key(ec_key);
    if (result != 1) {
        goto fail;
    }
    
    pkey = EVP_PKEY_new();
    
    result = EVP_PKEY_set1_EC_KEY(pkey, ec_key);
    if (!result) {
        goto fail;
    }
    else {
        return pkey;
    }
    
fail:
    if (ec_group != NULL) {
        EC_GROUP_free(ec_group);
    }
    if (ec_key != NULL) {
        EC_KEY_free(ec_key);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    
    return NULL;
}

X509 * PKLGenerateX509CertificateWithBits(int curve_name, NSString *countryName, NSString *stateOrProvinceName, NSString *localityName, NSString *organizationName, NSString *commonName)
{
    EVP_PKEY *keyPair = PKLGenerateECKeyPair(curve_name);
    
    X509 *x509Certificate = X509_new();
    
    if (x509Certificate == NULL)
    {
        EVP_PKEY_free(keyPair);
        NSLog(@"Unable to create X509 structure.");
        
        return NULL;
    }
    
    X509_set_version(x509Certificate, 2); // X509v3
    
    ASN1_INTEGER_set(X509_get_serialNumber(x509Certificate), serial_number());
    
    // This certificate is valid from now until exactly one year from now.
    X509_gmtime_adj(X509_get_notBefore(x509Certificate), 0);
    X509_gmtime_adj(X509_get_notAfter(x509Certificate), 60 * 60 * 24 * 365);
    
    // Set the public key for our certificate.
    X509_set_pubkey(x509Certificate, keyPair);
    
    X509_NAME *subjectName = X509_get_subject_name(x509Certificate);
    
    // Set the country code and common name.
    X509_NAME_add_entry_by_txt(subjectName, "C", MBSTRING_ASC, (unsigned char *)[countryName UTF8String], -1, -1, 0);
    X509_NAME_add_entry_by_txt(subjectName, "ST", MBSTRING_ASC, (unsigned char *)[stateOrProvinceName UTF8String], -1, -1, 0);
    X509_NAME_add_entry_by_txt(subjectName, "L", MBSTRING_ASC, (unsigned char *)[localityName UTF8String], -1, -1, 0);
    X509_NAME_add_entry_by_txt(subjectName, "O", MBSTRING_ASC, (unsigned char *)[organizationName UTF8String], -1, -1, 0);
    X509_NAME_add_entry_by_txt(subjectName, "CN", MBSTRING_ASC, (unsigned char *)[commonName UTF8String], -1, -1, 0);
    
    EVP_PKEY_free(keyPair);
    
    return x509Certificate;
}

static unsigned long serial_number()
{
    unsigned long serial = 0;
    unsigned char serial_bytes[sizeof(serial)];
    int i;
    
    // Construct random positive serial number.
    RAND_bytes(serial_bytes, sizeof(serial_bytes));
    serial_bytes[0] &= 0x7F;
    serial = 0;
    for (i = 0; i < sizeof(serial_bytes); i++) {
        serial = (256 * serial) + serial_bytes[i];
    }
    return serial;
}