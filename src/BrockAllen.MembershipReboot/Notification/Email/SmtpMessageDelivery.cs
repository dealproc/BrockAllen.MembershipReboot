/*
 * Copyright (c) Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using BrockAllen.MembershipReboot.Logging;
using MailKit.Net.Smtp;
using MimeKit;
using MimeKit.Text;

namespace BrockAllen.MembershipReboot
{
    public class SmtpMessageDelivery : IMessageDelivery
    {
        static ILog _log = LogProvider.For<SmtpMessageDelivery>();

        public bool SendAsHtml { get; set; }
        public int SmtpTimeout { get; set; }

        public SmtpMessageDelivery(bool sendAsHtml = false, int smtpTimeout = 5000)
        {
            this.SendAsHtml = sendAsHtml;
            this.SmtpTimeout = smtpTimeout;
        }

        public void Send(Message msg)
        {
            _log.Info("[SmtpMessageDelivery.Send] sending mail to " + msg.To);
            if (!String.IsNullOrWhiteSpace(msg.Cc))
            {
                _log.Info("[SmtpMessageDelivery.Send] cc'ing mail to " + msg.Cc);
            }

            if (String.IsNullOrWhiteSpace(msg.From))
            {
                //SmtpSection smtp = ConfigurationManager.GetSection("system.net/mailSettings/smtp") as SmtpSection;
                //msg.From = smtp.From;
                throw new ArgumentNullException("msg.From", "Whom is the sender of this email?");
            }

            using (SmtpClient smtp = new SmtpClient())
            {
                smtp.Timeout = SmtpTimeout;
                try
                {
                    var mailMessage = new MimeMessage();
                    mailMessage.From.Add(new MailboxAddress(msg.From));
                    mailMessage.To.Add(new MailboxAddress(msg.To));
                    mailMessage.Subject = msg.Subject;
                    
                    mailMessage.Body = new TextPart(this.SendAsHtml ? TextFormat.Html : TextFormat.Text)
                    {
                         Text = msg.Body
                    };

                    if (!String.IsNullOrWhiteSpace(msg.Cc))
                    {
                        foreach (string email in msg.Cc.Split(',', ';'))
                        {
                            mailMessage.Cc.Add(new MailboxAddress(email));
                        }
                    }
                    smtp.Send(mailMessage);
                }
                catch (Exception e)
                {
                    _log.Error("[SmtpMessageDelivery.Send] Exception: " + e.Message);
                }
            }
        }
    }
}
