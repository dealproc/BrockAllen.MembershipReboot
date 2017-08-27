/*
 * Copyright (c) Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.Security.Cryptography.X509Certificates;
using BrockAllen.MembershipReboot.Logging;

namespace BrockAllen.MembershipReboot
{
    static class X509Certificate2Extensions
    {
        static ILog _log = LogProvider.GetLogger("BrockAllen.MembershipReboot.X509Certificate2Extensions");

        public static bool Validate(this X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                _log.Trace("[X509Certificate2Extensions.Validate] failed -- null cert");
                return false;
            }
            
            if (certificate.Handle == IntPtr.Zero)
            {
                _log.Trace("[X509Certificate2Extensions.Validate] failed -- invalid cert handle");
                return false;
            }

            return true;
        }
    }
}
