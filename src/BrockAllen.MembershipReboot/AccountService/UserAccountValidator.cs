/*
 * Copyright (c) Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.DataAnnotations;
using BrockAllen.MembershipReboot.Logging;

namespace BrockAllen.MembershipReboot
{
    class UserAccountValidator<TAccount> :
        IEventHandler<CertificateAddedEvent<TAccount>>
        where TAccount : UserAccount
    {
        static ILog _log = LogProvider.For<UserAccountValidator<TAccount>>();

        UserAccountService<TAccount> userAccountService;
        public UserAccountValidator(UserAccountService<TAccount> userAccountService)
        {
            if (userAccountService == null) throw new ArgumentNullException("userAccountService");
            this.userAccountService = userAccountService;
        }

        public void Handle(CertificateAddedEvent<TAccount> evt)
        {
            if (evt == null) throw new ArgumentNullException("event");
            if (evt.Account == null) throw new ArgumentNullException("account");
            if (evt.Certificate == null) throw new ArgumentNullException("certificate");

            var account = evt.Account;
            var otherAccount = userAccountService.GetByCertificate(account.Tenant, evt.Certificate.Thumbprint);
            if (otherAccount != null && otherAccount.ID != account.ID)
            {
                _log.Trace("[UserAccountValidation.CertificateThumbprintMustBeUnique] validation failed: {0}, {1}", account.Tenant, account.Username);
                throw new ValidationException(userAccountService.GetValidationMessage("CertificateAlreadyInUse"));
            }
        }
    }
}
