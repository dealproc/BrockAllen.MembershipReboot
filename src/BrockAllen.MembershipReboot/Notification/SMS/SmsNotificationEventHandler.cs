/*
 * Copyright (c) Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Reflection;
using BrockAllen.MembershipReboot.Logging;

namespace BrockAllen.MembershipReboot
{
    public abstract class SmsEventHandler<TAccount> :
        IEventHandler<MobilePhoneChangeRequestedEvent<TAccount>>,
        IEventHandler<TwoFactorAuthenticationCodeNotificationEvent<TAccount>>
        where TAccount: UserAccount
    {
        static ILog _log = LogProvider.For<SmsEventHandler<TAccount>>();

        IMessageFormatter<TAccount> messageFormatter;

        public SmsEventHandler(IMessageFormatter<TAccount> messageFormatter)
        {
            this.messageFormatter = messageFormatter ?? throw new ArgumentNullException("messageFormatter");
        }

        protected abstract void SendSms(Message message);

        public virtual void Process(UserAccountEvent<TAccount> evt, object extra = null)
        {
            _log.Info("[{0}] Processing Event: {1}", this.GetType(), evt.GetType());

            var data = new Dictionary<string, string>();
            if (extra != null)
            {
#if net46
                foreach (PropertyDescriptor descriptor in TypeDescriptor.GetProperties(extra))
                {
                    object obj2 = descriptor.GetValue(extra);
                    if (obj2 != null)
                    {
                        data.Add(descriptor.Name, obj2.ToString());
                    }
                }
#else
                foreach (var x in extra.GetType().GetTypeInfo().DeclaredMembers)
                {
                    var obj2 = extra.GetType().GetMember(x.Name).GetValue(0);
                    if (obj2 != null)
                    {
                        data.Add(x.Name, obj2.ToString());
                    }
                }
#endif
            }

            var msg = CreateMessage(evt, data);
            if (msg != null)
            {
                SendSms(msg);
            }
        }

        protected virtual Message CreateMessage(UserAccountEvent<TAccount> evt, IDictionary<string, string> extra)
        {
            var msg = this.messageFormatter.Format(evt, extra);
            if (msg != null)
            {
                if (extra.ContainsKey("NewMobilePhoneNumber"))
                {
                    msg.To = extra["NewMobilePhoneNumber"];
                }
                else
                {
                    msg.To = evt.Account.MobilePhoneNumber;
                }
            }
            return msg;
        }

        public void Handle(MobilePhoneChangeRequestedEvent<TAccount> evt)
        {
            Process(evt, new { evt.NewMobilePhoneNumber, evt.Code });
        }

        public void Handle(TwoFactorAuthenticationCodeNotificationEvent<TAccount> evt)
        {
            Process(evt, new { evt.Code });
        }
    }
    
    public abstract class SmsEventHandler : SmsEventHandler<UserAccount>
    {
        public SmsEventHandler(IMessageFormatter<UserAccount> messageFormatter)
            : base(messageFormatter)
        {
        }
    }
}
