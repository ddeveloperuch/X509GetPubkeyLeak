//
//  main.c
//  X509GetPubkeyLeak
//
//  Created by Developer on 7/24/15.
//  Copyright (c) 2015 Developer. All rights reserved.
//
// ********************************************************************************************************************************************************** //

#import "PKLLeakEmulator.h"

// ********************************************************************************************************************************************************** //

void sigterm_handler(int sig)
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0),^{
        CFRunLoopStop(CFRunLoopGetMain());
    });
}

int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        [PKLLeakEmulator startLeakEmulation];
        
        CFRunLoopRun();
    }
    
    return 0;
}
