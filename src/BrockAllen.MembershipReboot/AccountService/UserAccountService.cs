/*
 * Copyright (c) Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using BrockAllen.MembershipReboot.Logging;

namespace BrockAllen.MembershipReboot
{
    public class UserAccountService<TAccount> : IEventSource
        where TAccount : UserAccount
    {
        static ILog _log = LogProvider.For<UserAccountService<TAccount>>();

        public MembershipRebootConfiguration<TAccount> Configuration { get; set; }

        EventBusUserAccountRepository<TAccount> userRepository;
        AggregateCommandBus aggregateCommandBus;

        Lazy<AggregateValidator<TAccount>> usernameValidator;
        Lazy<AggregateValidator<TAccount>> emailValidator;
        Lazy<AggregateValidator<TAccount>> passwordValidator;

        public UserAccountService(IUserAccountRepository<TAccount> userRepository)
            : this(new MembershipRebootConfiguration<TAccount>(), userRepository)
        {
        }

        public UserAccountService(MembershipRebootConfiguration<TAccount> configuration, IUserAccountRepository<TAccount> userRepository)
        {
            if (configuration == null) throw new ArgumentNullException("configuration");
            if (userRepository == null) throw new ArgumentNullException("userRepository");

            configuration.Validate();

            this.Configuration = configuration;

            aggregateCommandBus = new AggregateCommandBus() {
                commandBus, configuration.CommandBus
            };

            var validationEventBus = new EventBus();
            validationEventBus.Add(new UserAccountValidator<TAccount>(this));
            this.userRepository = new EventBusUserAccountRepository<TAccount>(this, userRepository,
                new AggregateEventBus { validationEventBus, configuration.ValidationBus },
                configuration.EventBus);

            this.usernameValidator = new Lazy<AggregateValidator<TAccount>>(() =>
            {
                var val = new AggregateValidator<TAccount>();
                if (!this.Configuration.EmailIsUsername)
                {
                    val.Add(UserAccountValidation<TAccount>.UsernameDoesNotContainAtSign);
                    val.Add(UserAccountValidation<TAccount>.UsernameCanOnlyStartOrEndWithLetterOrDigit);
                    val.Add(UserAccountValidation<TAccount>.UsernameOnlyContainsValidCharacters);
                    val.Add(UserAccountValidation<TAccount>.UsernameOnlySingleInstanceOfSpecialCharacters);
                }
                val.Add(UserAccountValidation<TAccount>.UsernameMustNotAlreadyExist);
                val.Add(configuration.UsernameValidator);
                return val;
            });

            this.emailValidator = new Lazy<AggregateValidator<TAccount>>(() =>
            {
                var val = new AggregateValidator<TAccount>();
                val.Add(UserAccountValidation<TAccount>.EmailIsRequiredIfRequireAccountVerificationEnabled);
                val.Add(UserAccountValidation<TAccount>.EmailIsValidFormat);
                if (configuration.EmailIsUnique)
                {
                    val.Add(UserAccountValidation<TAccount>.EmailMustNotAlreadyExist);
                }
                val.Add(configuration.EmailValidator);
                return val;
            });

            this.passwordValidator = new Lazy<AggregateValidator<TAccount>>(() =>
            {
                var val = new AggregateValidator<TAccount>();
                val.Add(UserAccountValidation<TAccount>.PasswordMustBeDifferentThanCurrent);
                val.Add(configuration.PasswordValidator);
                return val;
            });
        }

        protected void ValidateUsername(TAccount account, string value)
        {
            var result = this.usernameValidator.Value.Validate(this, account, value);
            if (result != null && result != ValidationResult.Success)
            {
                _log.Error("ValidateUsername failed: " + result.ErrorMessage);
                throw new ValidationException(result.ErrorMessage);
            }
        }
        protected void ValidatePassword(TAccount account, string value)
        {
            // null is allowed (e.g. for external providers)
            if (value == null) return;

            var result = this.passwordValidator.Value.Validate(this, account, value);
            if (result != null && result != ValidationResult.Success)
            {
                _log.Error("ValidatePassword failed: " + result.ErrorMessage);
                throw new ValidationException(result.ErrorMessage);
            }
        }
        protected void ValidateEmail(TAccount account, string value)
        {
            var result = this.emailValidator.Value.Validate(this, account, value);
            if (result != null && result != ValidationResult.Success)
            {
                _log.Error("ValidateEmail failed: " + result.ErrorMessage);
                throw new ValidationException(result.ErrorMessage);
            }
        }

        List<IEvent> events = new List<IEvent>();
        IEnumerable<IEvent> IEventSource.GetEvents()
        {
            return events;
        }
        void IEventSource.Clear()
        {
            events.Clear();
        }
        protected void AddEvent<E>(E evt) where E : IEvent
        {
            if (evt is IAllowMultiple ||
                !events.Any(x => x.GetType() == evt.GetType()))
            {
                events.Add(evt);
            }
        }

        public void AddCommandHandler(ICommandHandler handler)
        {
            commandBus.Add(handler);
        }
        CommandBus commandBus = new CommandBus();
        protected internal void ExecuteCommand(ICommand cmd)
        {
            aggregateCommandBus.Execute(cmd);
        }

        public virtual IUserAccountQuery<TAccount> Query 
        {
            get
            {
                return this.userRepository.inner as IUserAccountQuery<TAccount>;
            } 
        }

        public virtual string GetValidationMessage(string id)
        {
            var cmd = new GetValidationMessage { ID = id };
            ExecuteCommand(cmd);
            if (cmd.Message != null) return cmd.Message;

            var result = Resources.ValidationMessages.ResourceManager.GetString(id, Resources.ValidationMessages.Culture);
            if (result == null) throw new Exception("Missing validation message for ID : " + id);
            return result;
        }

        public virtual string GetValidationMessage(AuthenticationFailureCode failureCode)
        {
            return GetValidationMessage(failureCode.ToString());
        }

        public virtual void Update(TAccount account)
        {
            if (account == null)
            {
                _log.Error("[UserAccountService.Update] called -- failed null account");
                throw new ArgumentNullException("account");
            }

            _log.Info("[UserAccountService.Update] called for account: {0}", account.ID);

            account.LastUpdated = UtcNow;
            
            UpdateInternal(account);
        }
        
        internal protected virtual void UpdateInternal(TAccount account)
        {
            if (account == null)
            {
                _log.Error("[UserAccountService.UpdateInternal] called -- failed null account");
                throw new ArgumentNullException("account");
            }

            _log.Info("[UserAccountService.UpdateInternal] called for account: {0}", account.ID);

            this.userRepository.Update(account);
        }

        public virtual TAccount GetByUsername(string username)
        {
            return GetByUsername(null, username);
        }

        public virtual TAccount GetByUsername(string tenant, string username)
        {
            if (!Configuration.MultiTenant)
            {
                _log.Trace("[UserAccountService.GetByUsername] applying default tenant");
                tenant = Configuration.DefaultTenant;
            }

            _log.Info("[UserAccountService.GetByUsername] called for tenant: {0}, username: {1}", tenant, username);

            if (!Configuration.UsernamesUniqueAcrossTenants && String.IsNullOrWhiteSpace(tenant)) return null;
            if (String.IsNullOrWhiteSpace(username)) return null;

            TAccount account = null;
            if (Configuration.UsernamesUniqueAcrossTenants)
            {
                account = userRepository.GetByUsername(username);
            }
            else
            {
                account = userRepository.GetByUsername(tenant, username);
            }

            if (account == null)
            {
                _log.Warn("[UserAccountService.GetByUsername] failed to locate account: {0}, {1}", tenant, username);
            }
            return account;
        }

        public virtual TAccount GetByEmail(string email)
        {
            return GetByEmail(null, email);
        }

        public virtual TAccount GetByEmail(string tenant, string email)
        {
            if (Configuration.EmailIsUnique == false)
            {
                throw new InvalidOperationException("GetByEmail can't be used when EmailIsUnique is false");
            }
            
            if (!Configuration.MultiTenant)
            {
                _log.Trace("[UserAccountService.GetByEmail] applying default tenant");
                tenant = Configuration.DefaultTenant;
            }

            _log.Info("[UserAccountService.GetByEmail] called for tenant: {0}, email: {1}", tenant, email);

            if (String.IsNullOrWhiteSpace(tenant)) return null;
            if (String.IsNullOrWhiteSpace(email)) return null;

            var account = userRepository.GetByEmail(tenant, email);
            if (account == null)
            {
                _log.Warn("[UserAccountService.GetByEmail] failed to locate account: {0}, {1}", tenant, email);
            }
            return account;
        }

        public virtual TAccount GetByID(Guid id)
        {
            _log.Info("[UserAccountService.GetByID] called for id: {0}", id);

            var account = this.userRepository.GetByID(id);
            if (account == null)
            {
                _log.Warn("[UserAccountService.GetByID] failed to locate account: {0}", id);
            }
            return account;
        }

        public virtual TAccount GetByVerificationKey(string key)
        {
            _log.Info("[UserAccountService.GetByVerificationKey] called for key: {0}", key);

            if (String.IsNullOrWhiteSpace(key)) return null;

            key = this.Configuration.Crypto.Hash(key);

            var account = userRepository.GetByVerificationKey(key);
            if (account == null)
            {
                _log.Warn("[UserAccountService.GetByVerificationKey] failed to locate account: {0}", key);
            }
            return account;
        }

        public virtual TAccount GetByLinkedAccount(string provider, string id)
        {
            return GetByLinkedAccount(null, provider, id);
        }

        public virtual TAccount GetByLinkedAccount(string tenant, string provider, string id)
        {
            if (!Configuration.MultiTenant)
            {
                _log.Trace("[UserAccountService.GetByLinkedAccount] applying default tenant");
                tenant = Configuration.DefaultTenant;
            }

            _log.Info("[UserAccountService.GetByLinkedAccount] called for tenant: {0}, provider; {1}, id: {2}", tenant, provider, id);

            if (String.IsNullOrWhiteSpace(tenant)) return null;
            if (String.IsNullOrWhiteSpace(provider)) return null;
            if (String.IsNullOrWhiteSpace(id)) return null;

            var account = userRepository.GetByLinkedAccount(tenant, provider, id);
            if (account == null)
            {
                _log.Warn("[UserAccountService.GetByLinkedAccount] failed to locate by tenant: {0}, provider: {1}, id: {2}", tenant, provider, id);
            }
            return account;
        }

        public virtual TAccount GetByCertificate(string thumbprint)
        {
            return GetByCertificate(null, thumbprint);
        }

        public virtual TAccount GetByCertificate(string tenant, string thumbprint)
        {
            if (!Configuration.MultiTenant)
            {
                _log.Trace("[UserAccountService.GetByCertificate] applying default tenant");
                tenant = Configuration.DefaultTenant;
            }

            _log.Info("[UserAccountService.GetByCertificate] called for tenant: {0}, thumbprint; {1}", tenant, thumbprint);

            if (String.IsNullOrWhiteSpace(tenant)) return null;
            if (String.IsNullOrWhiteSpace(thumbprint)) return null;

            var account = userRepository.GetByCertificate(tenant, thumbprint);
            if (account == null)
            {
                _log.Warn("[UserAccountService.GetByCertificate] failed to locate by certificate thumbprint: {0}, {1}", tenant, thumbprint);
            }
            return account;
        }

        public virtual bool UsernameExists(string username)
        {
            return UsernameExists(null, username);
        }

        public virtual bool UsernameExists(string tenant, string username)
        {
            _log.Info("[UserAccountService.UsernameExists] called for tenant: {0}, username; {1}", tenant, username);

            if (String.IsNullOrWhiteSpace(username)) return false;

            if (Configuration.UsernamesUniqueAcrossTenants)
            {
                return this.userRepository.GetByUsername(username) != null;
            }
            else
            {
                if (!Configuration.MultiTenant)
                {
                    _log.Trace("[UserAccountService.UsernameExists] applying default tenant");
                    tenant = Configuration.DefaultTenant;
                }

                if (String.IsNullOrWhiteSpace(tenant)) return false;

                return this.userRepository.GetByUsername(tenant, username) != null;
            }
        }

        public virtual bool EmailExists(string email)
        {
            return EmailExists(null, email);
        }

        public virtual bool EmailExists(string tenant, string email)
        {
            if (Configuration.EmailIsUnique == false)
            {
                throw new InvalidOperationException("EmailExists can't be used when EmailIsUnique is false");
            }

            if (!Configuration.MultiTenant)
            {
                _log.Trace("[UserAccountService.EmailExists] applying default tenant");
                tenant = Configuration.DefaultTenant;
            }

            _log.Info("[UserAccountService.EmailExists] called for tenant: {0}, email; {1}", tenant, email);

            if (String.IsNullOrWhiteSpace(tenant)) return false;
            if (String.IsNullOrWhiteSpace(email)) return false;

            return this.userRepository.GetByEmail(tenant, email) != null;
        }

        protected internal bool EmailExistsOtherThan(TAccount account, string email)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.EmailExistsOtherThan] called for account id: {0}, email; {1}", account.ID, email);

            if (String.IsNullOrWhiteSpace(email)) return false;

            var acct2 = this.userRepository.GetByEmail(account.Tenant, email);
            if (acct2 != null)
            {
                return account.ID != acct2.ID;
            }
            return false;
        }

        protected internal bool MobilePhoneExistsOtherThan(TAccount account, string phone)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.EmailExistsOtherThan] called for account id: {0}, phone; {1}", account.ID, phone);

            if (String.IsNullOrWhiteSpace(phone)) return false;

            var acct2 = this.userRepository.GetByMobilePhone(account.Tenant, phone);
            if (acct2 != null)
            {
                return account.ID != acct2.ID;
            }
            return false;
        }

        public virtual TAccount CreateAccount(string username, string password, string email, Guid? id = null, DateTime? dateCreated = null, IEnumerable<Claim> claims = null)
        {
            return CreateAccount(null, username, password, email, id, dateCreated, null, claims);
        }

        public virtual TAccount CreateUserAccount()
        {
            return this.userRepository.Create();
        }

        public virtual TAccount CreateAccount(string tenant, string username, string password, string email, Guid? id = null, DateTime? dateCreated = null, TAccount account = null, IEnumerable<Claim> claims = null)
        {
            if (Configuration.EmailIsUsername)
            {
                _log.Trace("[UserAccountService.CreateAccount] applying email is username");
                username = email;
            }

            if (!Configuration.MultiTenant)
            {
                _log.Trace("[UserAccountService.CreateAccount] applying default tenant");
                tenant = Configuration.DefaultTenant;
            }

            _log.Info("[UserAccountService.CreateAccount] called: {0}, {1}, {2}", tenant, username, email);

            account = account ?? CreateUserAccount();
            Init(account, tenant, username, password, email, id, dateCreated, claims);

            ValidateEmail(account, email);
            ValidateUsername(account, username);
            ValidatePassword(account, password);

            _log.Trace("[UserAccountService.CreateAccount] success");

            this.userRepository.Add(account);

            return account;
        }

        protected void Init(TAccount account, string tenant, string username, string password, string email, Guid? id = null, DateTime? dateCreated = null, IEnumerable<Claim> claims = null)
        {
            _log.Info("[UserAccountService.Init] called");

            if (account == null)
            {
                _log.Error("[UserAccountService.Init] failed -- null account");
                throw new ArgumentNullException("account");
            }

            if (String.IsNullOrWhiteSpace(tenant))
            {
                _log.Error("[UserAccountService.Init] failed -- no tenant");
                throw new ArgumentNullException("tenant");
            }

            if (String.IsNullOrWhiteSpace(username))
            {
                _log.Error("[UserAccountService.Init] failed -- no username");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.UsernameRequired));
            }

            if (password != null && String.IsNullOrWhiteSpace(password.Trim()))
            {
                _log.Error("[UserAccountService.Init] failed -- no password");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.PasswordRequired));
            }

            if (account.ID != Guid.Empty)
            {
                _log.Error("[UserAccountService.Init] failed -- ID already assigned");
                throw new Exception("Can't call Init if UserAccount is already assigned an ID");
            }

            var now = UtcNow;
            if (dateCreated > now)
            {
                _log.Error("[UserAccountService.Init] failed -- date created in the future");
                throw new Exception("dateCreated can't be in the future");
            }

            account.ID = id ?? Guid.NewGuid();
            account.Tenant = tenant;
            account.Username = username;
            account.Email = email;
            account.Created = dateCreated ?? now;
            account.LastUpdated = now;
            account.HashedPassword = password != null ?
                Configuration.Crypto.HashPassword(password, this.Configuration.PasswordHashingIterationCount) : null;
            account.PasswordChanged = password != null ? now : (DateTime?)null;
            account.IsAccountVerified = false;
            account.AccountTwoFactorAuthMode = TwoFactorAuthMode.None;
            account.CurrentTwoFactorAuthStatus = TwoFactorAuthMode.None;
            account.IsLoginAllowed = true;

            _log.Trace("[UserAccountService.CreateAccount] SecuritySettings.AllowLoginAfterAccountCreation is set to: {0}", account.IsLoginAllowed);

            string key = null;
            if (!String.IsNullOrWhiteSpace(account.Email))
            {
                _log.Trace("[UserAccountService.CreateAccount] Email was provided, so creating email verification request");
                key = SetVerificationKey(account, VerificationKeyPurpose.ChangeEmail, state: account.Email);
            }

            if (claims != null)
            {
                foreach (var claim in claims)
                {
                    AddClaim(account, new UserClaim(claim.Type, claim.Value));
                }
            }

            this.AddEvent(new AccountCreatedEvent<TAccount> { Account = account, InitialPassword = password, VerificationKey = key });
        }

        public virtual void RequestAccountVerification(Guid accountID)
        {
            _log.Info("[UserAccountService.RequestAccountVerification] called for account id: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null)
            {
                _log.Error("[UserAccountService.RequestAccountVerification] invalid account id");
                throw new Exception("Invalid Account ID");
            }

            if (String.IsNullOrWhiteSpace(account.Email))
            {
                _log.Error("[UserAccountService.RequestAccountVerification] email empty");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.EmailRequired));
            }

            if (account.IsAccountVerified)
            {
                _log.Error("[UserAccountService.RequestAccountVerification] account already verified");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.AccountAlreadyVerified));
            }

            _log.Trace("[UserAccountService.RequestAccountVerification] creating a new verification key");
            var key = SetVerificationKey(account, VerificationKeyPurpose.ChangeEmail, state: account.Email);
            this.AddEvent(new EmailChangeRequestedEvent<TAccount> { Account = account, NewEmail = account.Email, VerificationKey = key });

            UpdateInternal(account);
        }

        public virtual void CancelVerification(string key)
        {
            bool closed;
            CancelVerification(key, out closed);
        }

        public virtual void CancelVerification(string key, out bool accountClosed)
        {
            _log.Info("[UserAccountService.CancelVerification] called: {0}", key);

            accountClosed = false;

            if (String.IsNullOrWhiteSpace(key))
            {
                _log.Error("[UserAccountService.CancelVerification] failed -- key null");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidKey));
            }

            var account = this.GetByVerificationKey(key);
            if (account == null)
            {
                _log.Error("[UserAccountService.CancelVerification] failed -- account not found from key");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidKey));
            }

            if (account.VerificationPurpose == null)
            {
                _log.Error("[UserAccountService.CancelVerification] failed -- no purpose");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidKey));
            }

            var result = Configuration.Crypto.VerifyHash(key, account.VerificationKey);
            if (!result)
            {
                _log.Error("[UserAccountService.CancelVerification] failed -- key verification failed");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidKey));
            }

            if (account.VerificationPurpose == VerificationKeyPurpose.ChangeEmail &&
                account.IsNew())
            {
                _log.Trace("[UserAccountService.CancelVerification] account is new (deleting account)");
                // if last login is null then they've never logged in so we can delete the account
                DeleteAccount(account);
                accountClosed = true;
            }
            else
            {
                _log.Trace("[UserAccountService.CancelVerification] account is not new (canceling clearing verification key)");
                ClearVerificationKey(account);
                UpdateInternal(account);
            }

            _log.Trace("[UserAccountService.CancelVerification] succeeded");
        }

        public virtual void DeleteAccount(Guid accountID)
        {
            _log.Info("[UserAccountService.DeleteAccount] called: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            DeleteAccount(account);
        }

        protected virtual void DeleteAccount(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Trace("[UserAccountService.DeleteAccount] marking account as closed: {0}", account.ID);

            CloseAccount(account);
            Update(account);

            if (Configuration.AllowAccountDeletion || account.IsNew())
            {
                _log.Trace("[UserAccountService.DeleteAccount] removing account record: {0}", account.ID);
                this.userRepository.Remove(account);
            }
        }

        public virtual void CloseAccount(Guid accountID)
        {
            _log.Info("[UserAccountService.CloseAccount] called: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            CloseAccount(account);
            Update(account);
        }
        
        protected virtual void CloseAccount(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.CloseAccount] called for accountID: {0}", account.ID);

            ClearVerificationKey(account);
            ClearMobileAuthCode(account);
            ConfigureTwoFactorAuthentication(account, TwoFactorAuthMode.None);

            if (!account.IsAccountClosed)
            {
                _log.Trace("[UserAccountService.CloseAccount] success");

                account.IsAccountClosed = true;
                account.AccountClosed = UtcNow;

                this.AddEvent(new AccountClosedEvent<TAccount> { Account = account });
            }
            else
            {
                _log.Warn("[UserAccountService.CloseAccount] account already closed");
            }
        }

        public virtual void ReopenAccount(string username, string password)
        {
            ReopenAccount(null, username, password);
        }

        public virtual void ReopenAccount(string tenant, string username, string password)
        {
            if (!Configuration.MultiTenant)
            {
                _log.Trace("[UserAccountService.ReopenAccount] applying default tenant");
                tenant = Configuration.DefaultTenant;
            }

            _log.Info("[UserAccountService.ReopenAccount] called: {0}, {1}", tenant, username);

            var account = GetByUsername(tenant, username);
            if (account == null)
            {
                _log.Error("[UserAccountService.ReopenAccount] invalid account");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidUsername));
            }

            if (!VerifyPassword(account, password))
            {
                _log.Error("[UserAccountService.ReopenAccount] invalid password");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidPassword));
            }

            ReopenAccount(account);
        }

        public virtual void ReopenAccount(Guid accountID)
        {
            _log.Info("[UserAccountService.ReopenAccount] called: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            ReopenAccount(account);
        }

        public virtual void ReopenAccount(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            if (!account.IsAccountClosed)
            {
                _log.Warn("[UserAccountService.ReopenAccount] account is not closed");
                return;
            }

            if (String.IsNullOrWhiteSpace(account.Email))
            {
                _log.Error("[UserAccountService.ReopenAccount] no email to confirm reopen request");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.ReopenErrorNoEmail));
            }

            // this will require the user to confirm via email before logging in
            account.IsAccountVerified = false;
            ClearVerificationKey(account);
            var key = SetVerificationKey(account, VerificationKeyPurpose.ChangeEmail, state: account.Email);
            this.AddEvent(new AccountReopenedEvent<TAccount> { Account = account, VerificationKey = key });

            account.IsAccountClosed = false;
            account.AccountClosed = null;

            Update(account);

            _log.Trace("[UserAccountService.ReopenAccount] success");
        }

        public virtual void ApproveAccount(Guid accountID)
        {
            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            ApproveAccount(account);
        }

        public virtual void ApproveAccount(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            if (account.IsAccountApproved)
            {
                _log.Warn("[UserAccountService.ApproveAccount] account is already approved");
                return;
            }

            if (account.IsAccountClosed)
            {
                _log.Error("[UserAccountService.ApproveAccount] account closed");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.AccountClosed));
            }

            account.AccountApproved = UtcNow;
            account.AccountRejected = null;

            this.AddEvent(new AccountApprovedEvent<TAccount> { Account = account });

            Update(account);

            _log.Trace("[UserAccountService.ApproveAccount] success");
        }

        public virtual void RejectAccount(Guid accountID)
        {
            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            RejectAccount(account);
        }

        public virtual void RejectAccount(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            if (account.IsAccountRejected)
            {
                _log.Warn("[UserAccountService.RejectAccount] account is already rejected");
                return;
            }
            
            if (account.IsAccountClosed)
            {
                _log.Error("[UserAccountService.RejectAccount] account closed");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.AccountClosed));
            }

            if (account.IsAccountApproved)
            {
                _log.Error("[UserAccountService.RejectAccount] account already approved");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.RejectAlreadyApproved));
            }

            account.AccountRejected = UtcNow;

            this.AddEvent(new AccountRejectedEvent<TAccount> { Account = account });

            Update(account);

            _log.Trace("[UserAccountService.RejectAccount] success");
        }


        public virtual bool Authenticate(string username, string password)
        {
            return Authenticate(null, username, password);
        }

        public virtual bool Authenticate(string username, string password, out AuthenticationFailureCode failureCode)
        {
            return Authenticate(null, username, password, out failureCode);
        }

        public virtual bool Authenticate(string username, string password, out TAccount account)
        {
            return Authenticate(null, username, password, out account);
        }

        public virtual bool Authenticate(string username, string password, out TAccount account, out AuthenticationFailureCode failureCode)
        {
            return Authenticate(null, username, password, out account, out failureCode);
        }

        public virtual bool Authenticate(string tenant, string username, string password)
        {
            TAccount account;
            return Authenticate(tenant, username, password, out account);
        }

        public virtual bool Authenticate(string tenant, string username, string password, out AuthenticationFailureCode failureCode)
        {
            TAccount account;
            return Authenticate(tenant, username, password, out account, out failureCode);
        }

        public virtual bool Authenticate(string tenant, string username, string password, out TAccount account)
        {
            AuthenticationFailureCode failureCode;
            return Authenticate(tenant, username, password, out account, out failureCode);
        }

        public virtual bool Authenticate(string tenant, string username, string password, out TAccount account, out AuthenticationFailureCode failureCode)
        {
            account = null;

            if (!Configuration.MultiTenant)
            {
                _log.Trace("[UserAccountService.Authenticate] applying default tenant");
                tenant = Configuration.DefaultTenant;
            }

            _log.Info("[UserAccountService.Authenticate] called: {0}, {1}", tenant, username);

            if (String.IsNullOrWhiteSpace(password))
            {
                _log.Error("[UserAccountService.Authenticate] failed -- empty password");
            }
            if ((!Configuration.UsernamesUniqueAcrossTenants && String.IsNullOrWhiteSpace(tenant)) 
                || String.IsNullOrWhiteSpace(username) || String.IsNullOrWhiteSpace(password))
            {
                failureCode = AuthenticationFailureCode.InvalidCredentials;
                return false;
            }

            account = this.GetByUsername(tenant, username);
            if (account == null)
            {
                failureCode = AuthenticationFailureCode.InvalidCredentials;
                return false;
            }

            return Authenticate(account, password, out failureCode);
        }

        public virtual bool AuthenticateWithEmail(string email, string password)
        {
            return AuthenticateWithEmail(null, email, password);
        }

        public virtual bool AuthenticateWithEmail(string email, string password, out AuthenticationFailureCode failureCode)
        {
            return AuthenticateWithEmail(null, email, password, out failureCode);
        }

        public virtual bool AuthenticateWithEmail(string email, string password, out TAccount account)
        {
            return AuthenticateWithEmail(null, email, password, out account);
        }

        public virtual bool AuthenticateWithEmail(string email, string password, out TAccount account, out AuthenticationFailureCode failureCode)
        {
            return AuthenticateWithEmail(null, email, password, out account, out failureCode);
        }

        public virtual bool AuthenticateWithEmail(string tenant, string email, string password)
        {
            TAccount account;
            return AuthenticateWithEmail(null, email, password, out account);
        }

        public virtual bool AuthenticateWithEmail(string tenant, string email, string password, out AuthenticationFailureCode failureCode)
        {
            TAccount account;
            return AuthenticateWithEmail(null, email, password, out account, out failureCode);
        }

        public virtual bool AuthenticateWithEmail(string tenant, string email, string password, out TAccount account)
        {
            AuthenticationFailureCode failureCode;
            return AuthenticateWithEmail(tenant, email, password, out account, out failureCode);
        }

        public virtual bool AuthenticateWithEmail(string tenant, string email, string password, out TAccount account, out AuthenticationFailureCode failureCode)
        {
            account = null;

            if (Configuration.EmailIsUnique == false)
            {
                throw new InvalidOperationException("AuthenticateWithEmail can't be used when EmailIsUnique is false");
            }
            
            if (!Configuration.MultiTenant)
            {
                _log.Trace("[UserAccountService.AuthenticateWithEmail] applying default tenant");
                tenant = Configuration.DefaultTenant;
            }

            _log.Info("[UserAccountService.AuthenticateWithEmail] called: {0}, {1}", tenant, email);

            if (String.IsNullOrWhiteSpace(password))
            {
                _log.Error("[UserAccountService.AuthenticateWithEmail] failed -- empty password");
            }
            if (String.IsNullOrWhiteSpace(tenant) || String.IsNullOrWhiteSpace(email) || String.IsNullOrWhiteSpace(password))
            {
                failureCode = AuthenticationFailureCode.InvalidCredentials;
                return false;
            }

            account = this.GetByEmail(tenant, email);
            if (account == null)
            {
                failureCode = AuthenticationFailureCode.InvalidCredentials;
                return false;
            }

            return Authenticate(account, password, out failureCode);
        }

        public virtual bool AuthenticateWithUsernameOrEmail(string userNameOrEmail, string password, out TAccount account)
        {
            return AuthenticateWithUsernameOrEmail(null, userNameOrEmail, password, out account);
        }

        public virtual bool AuthenticateWithUsernameOrEmail(string userNameOrEmail, string password, out TAccount account, out AuthenticationFailureCode failureCode)
        {
            return AuthenticateWithUsernameOrEmail(null, userNameOrEmail, password, out account, out failureCode);
        }

        public virtual bool AuthenticateWithUsernameOrEmail(string tenant, string userNameOrEmail, string password, out TAccount account)
        {
            AuthenticationFailureCode failureCode;
            return AuthenticateWithUsernameOrEmail(tenant, userNameOrEmail, password, out account, out failureCode);
        }

        public virtual bool AuthenticateWithUsernameOrEmail(string tenant, string userNameOrEmail, string password, out TAccount account, out AuthenticationFailureCode failureCode)
        {
            account = null;

            if (Configuration.EmailIsUnique == false)
            {
                throw new InvalidOperationException("AuthenticateWithUsernameOrEmail can't be used when EmailIsUnique is false");
            }
            
            if (!Configuration.MultiTenant)
            {
                _log.Trace("[UserAccountService.AuthenticateWithUsernameOrEmail] applying default tenant");
                tenant = Configuration.DefaultTenant;
            }

            _log.Info("[UserAccountService.AuthenticateWithUsernameOrEmail] called {0}, {1}", tenant, userNameOrEmail);

            if (String.IsNullOrWhiteSpace(password))
            {
                _log.Error("[UserAccountService.AuthenticateWithUsernameOrEmail] failed -- empty password");
            }
            if (String.IsNullOrWhiteSpace(tenant) || String.IsNullOrWhiteSpace(userNameOrEmail) || String.IsNullOrWhiteSpace(password))
            {
                failureCode = AuthenticationFailureCode.InvalidCredentials;
                return false;
            }

            if (!Configuration.EmailIsUsername && userNameOrEmail.Contains("@"))
            {
                _log.Trace("[UserAccountService.AuthenticateWithUsernameOrEmail] email detected");
                return AuthenticateWithEmail(tenant, userNameOrEmail, password, out account, out failureCode);
            }
            else
            {
                _log.Trace("[UserAccountService.AuthenticateWithUsernameOrEmail] username detected");
                return Authenticate(tenant, userNameOrEmail, password, out account, out failureCode);
            }
        }

        protected virtual bool Authenticate(TAccount account, string password, out AuthenticationFailureCode failureCode)
        {
            _log.Trace("[UserAccountService.Authenticate] for account: {0}", account.ID);

            bool result = VerifyPassword(account, password, out failureCode);

            if (result)
            {
                try
                {
                    if (!account.IsLoginAllowed)
                    {
                        _log.Error("[UserAccountService.Authenticate] failed -- account not allowed to login");
                        this.AddEvent(new AccountLockedEvent<TAccount> { Account = account });
                        failureCode = AuthenticationFailureCode.LoginNotAllowed;
                        return false;
                    }

                    if (account.IsAccountClosed)
                    {
                        _log.Error("[UserAccountService.Authenticate] failed -- account closed");
                        this.AddEvent(new InvalidAccountEvent<TAccount> { Account = account });
                        failureCode = AuthenticationFailureCode.AccountClosed;
                        return false;
                    }

                    if (Configuration.RequireAccountApproval && !account.IsAccountApproved)
                    {
                        _log.Error("[UserAccountService.Authenticate] failed -- account not approved");
                        this.AddEvent(new AccountLockedEvent<TAccount> { Account = account });
                        failureCode = AuthenticationFailureCode.AccountNotApproved;
                        return false;
                    }

                    if (Configuration.RequireAccountVerification &&
                        !account.IsAccountVerified)
                    {
                        _log.Error("[UserAccountService.Authenticate] failed -- account not verified");
                        this.AddEvent(new AccountNotVerifiedEvent<TAccount>() { Account = account });
                        failureCode = AuthenticationFailureCode.AccountNotVerified;
                        return false;
                    }

                    _log.Trace("[UserAccountService.Authenticate] authentication success");
                    account.LastLogin = UtcNow;
                    this.AddEvent(new SuccessfulPasswordLoginEvent<TAccount> { Account = account });

                    if (account.AccountTwoFactorAuthMode != TwoFactorAuthMode.None)
                    {
                        _log.Trace("[UserAccountService.Authenticate] doing two factor auth checks: {0}, {1}", account.Tenant, account.Username);

                        bool shouldRequestTwoFactorAuthCode = true;

                        GetTwoFactorAuthToken getToken = new GetTwoFactorAuthToken() { Account = account };
                        ExecuteCommand(getToken);

                        if (getToken.Token != null)
                        {
                            _log.Trace("[UserAccountService.Authenticate] GetTwoFactorAuthToken returned token");

                            var verified = VerifyTwoFactorAuthToken(account, getToken.Token);
                            _log.Trace("[UserAccountService.Authenticate] verifying token, result: {0}", verified);
                            shouldRequestTwoFactorAuthCode = !verified;
                        }

                        if (shouldRequestTwoFactorAuthCode)
                        {
                            if (account.AccountTwoFactorAuthMode == TwoFactorAuthMode.Certificate)
                            {
                                _log.Trace("[UserAccountService.Authenticate] requesting 2fa certificate: {0}, {1}", account.Tenant, account.Username);
                                result = RequestTwoFactorAuthCertificate(account);
                                if (!result && !account.Certificates.Any())
                                {
                                    failureCode = AuthenticationFailureCode.AccountNotConfiguredWithCertificates;
                                }
                            }

                            if (account.AccountTwoFactorAuthMode == TwoFactorAuthMode.Mobile)
                            {
                                _log.Trace("[UserAccountService.Authenticate] requesting 2fa mobile code: {0}, {1}", account.Tenant, account.Username);
                                result = RequestTwoFactorAuthCode(account);
                                if (!result && String.IsNullOrWhiteSpace(account.MobilePhoneNumber))
                                {
                                    failureCode = AuthenticationFailureCode.AccountNotConfiguredWithMobilePhone;
                                }
                            }
                        }
                        else
                        {
                            _log.Trace("[UserAccountService.Authenticate] setting two factor auth status to None");
                            account.CurrentTwoFactorAuthStatus = TwoFactorAuthMode.None;
                        }
                    }
                }
                finally
                {
                    UpdateInternal(account);
                }
            }

            _log.Trace("[UserAccountService.Authenticate] authentication outcome: {0}", result ? "Successful Login" : "Failed Login");

            return result;
        }

        protected virtual bool Authenticate(TAccount account, string password)
        {
            AuthenticationFailureCode failureCode;
            return Authenticate(account, password, out failureCode);
        }

        protected virtual bool VerifyPassword(TAccount account, string password, out AuthenticationFailureCode failureCode)
        {
            _log.Info("[UserAccountService.VerifyPassword] called for accountID: {0}", account.ID);

            if (String.IsNullOrWhiteSpace(password))
            {
                _log.Error("[UserAccountService.VerifyPassword] failed -- no password");
                failureCode = AuthenticationFailureCode.InvalidCredentials;
                return false;
            }

            if (!account.HasPassword())
            {
                _log.Error("[UserAccountService.VerifyPassword] failed -- account does not have a password");
                failureCode = AuthenticationFailureCode.InvalidCredentials;
                return false;
            }

            try
            {
                if (CheckHasTooManyRecentPasswordFailures(account))
                {
                    _log.Error("[UserAccountService.VerifyPassword] failed -- account in lockout due to failed login attempts");
                    this.AddEvent(new TooManyRecentPasswordFailuresEvent<TAccount> { Account = account });
                    failureCode = AuthenticationFailureCode.FailedLoginAttemptsExceeded;
                    return false;
                }

                if (VerifyHashedPassword(account, password))
                {
                    _log.Trace("[UserAccountService.VerifyPassword] success");
                    account.FailedLoginCount = 0;
                    failureCode = AuthenticationFailureCode.None;
                    return true;
                }
                else
                {
                    _log.Error("[UserAccountService.VerifyPassword] failed -- invalid password");
                    RecordInvalidLoginAttempt(account);
                    this.AddEvent(new InvalidPasswordEvent<TAccount> { Account = account });
                    failureCode = AuthenticationFailureCode.InvalidCredentials;
                    return false;
                }
            }
            finally
            {
                UpdateInternal(account);
            }
        }

        protected virtual bool VerifyPassword(TAccount account, string password)
        {
            AuthenticationFailureCode code;
            return VerifyPassword(account, password, out code);
        }

        protected internal bool VerifyHashedPassword(TAccount account, string password)
        {
            if (!account.HasPassword()) return false;
            return Configuration.Crypto.VerifyHashedPassword(account.HashedPassword, password);
        }

        protected virtual bool CheckHasTooManyRecentPasswordFailures(TAccount account)
        {
            var result = false;
            if (Configuration.AccountLockoutFailedLoginAttempts <= account.FailedLoginCount)
            {
                result = account.LastFailedLogin >= UtcNow.Subtract(Configuration.AccountLockoutDuration);
                if (!result)
                {
                    // if we're past the lockout window, then reset to zero
                    account.FailedLoginCount = 0;
                }
            }

            if (result)
            {
                account.FailedLoginCount++;
            }

            return result;
        }

        protected virtual void RecordInvalidLoginAttempt(TAccount account)
        {
            account.LastFailedLogin = UtcNow;
            if (account.FailedLoginCount <= 0)
            {
                account.FailedLoginCount = 1;
            }
            else
            {
                account.FailedLoginCount++;
            }
        }

        public virtual bool AuthenticateWithCode(Guid accountID, string code)
        {
            TAccount account;
            return AuthenticateWithCode(accountID, code, out account);
        }

        public virtual bool AuthenticateWithCode(Guid accountID, string code, out TAccount account)
        {
            _log.Info("[UserAccountService.AuthenticateWithCode] called {0}", accountID);

            account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            _log.Info("[UserAccountService.AuthenticateWithCode] called for accountID: {0}", account.ID);

            if (code == null)
            {
                _log.Error("[UserAccountService.AuthenticateWithCode] failed - null code");
                return false;
            }

            if (account.IsAccountClosed)
            {
                _log.Error("[UserAccountService.AuthenticateWithCode] failed -- account closed");
                return false;
            }

            if (!account.IsLoginAllowed)
            {
                _log.Error("[UserAccountService.AuthenticateWithCode] failed -- login not allowed");
                return false;
            }

            if (account.AccountTwoFactorAuthMode != TwoFactorAuthMode.Mobile)
            {
                _log.Error("[UserAccountService.AuthenticateWithCode] failed -- two factor auth mode not mobile");
                return false;
            }

            if (account.CurrentTwoFactorAuthStatus != TwoFactorAuthMode.Mobile)
            {
                _log.Error("[UserAccountService.AuthenticateWithCode] failed -- current auth status not mobile");
                return false;
            }

            if (!VerifyMobileCode(account, code))
            {
                _log.Error("[UserAccountService.AuthenticateWithCode] failed -- mobile code failed to verify");
                return false;
            }

            ClearMobileAuthCode(account);

            account.LastLogin = UtcNow;
            account.CurrentTwoFactorAuthStatus = TwoFactorAuthMode.None;

            this.AddEvent(new SuccessfulTwoFactorAuthCodeLoginEvent<TAccount> { Account = account });

            _log.Trace("[UserAccountService.AuthenticateWithCode] success ");

            CreateTwoFactorAuthToken(account);

            UpdateInternal(account);

            return true;
        }

        public virtual bool AuthenticateWithCertificate(string tenant, X509Certificate2 certificate)
        {
            TAccount account;
            return AuthenticateWithCertificate(tenant, certificate, out account);
        }

        public virtual bool AuthenticateWithCertificate(string tenant, X509Certificate2 certificate, out TAccount account)
        {
            _log.Info("[UserAccountService.AuthenticateWithCertificate] called");

            if (!certificate.Validate())
            {
                _log.Error("[UserAccountService.AuthenticateWithCertificate] failed -- cert failed to validate");
                account = null;
                return false;
            }

            account = this.GetByCertificate(tenant, certificate.Thumbprint);
            if (account == null) return false;

            var result = Authenticate(account, certificate);
            UpdateInternal(account);

            _log.Trace("[UserAccountService.AuthenticateWithCertificate] result {0}", result);

            return result;
        }

        public virtual bool AuthenticateWithCertificate(X509Certificate2 certificate)
        {
            TAccount account;
            return AuthenticateWithCertificate(certificate, out account);
        }

        public virtual bool AuthenticateWithCertificate(X509Certificate2 certificate, out TAccount account)
        {
            _log.Info("[UserAccountService.AuthenticateWithCertificate] called");

            if (!certificate.Validate())
            {
                _log.Error("[UserAccountService.AuthenticateWithCertificate] failed -- cert failed to validate");
                account = null;
                return false;
            }

            account = this.GetByCertificate(certificate.Thumbprint);
            if (account == null) return false;

            var result = Authenticate(account, certificate);
            UpdateInternal(account);

            _log.Trace("[UserAccountService.AuthenticateWithCertificate] result {0}", result);

            return result;
        }

        public virtual bool AuthenticateWithCertificate(Guid accountID, X509Certificate2 certificate)
        {
            TAccount account;
            return AuthenticateWithCertificate(accountID, certificate, out account);
        }

        public virtual bool AuthenticateWithCertificate(Guid accountID, X509Certificate2 certificate, out TAccount account)
        {
            _log.Info("[UserAccountService.AuthenticateWithCertificate] called for userID: {0}", accountID);

            if (!certificate.Validate())
            {
                _log.Error("[UserAccountService.AuthenticateWithCertificate] failed -- cert failed to validate");
                account = null;
                return false;
            }

            account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            var result = Authenticate(account, certificate);
            UpdateInternal(account);

            _log.Trace("[UserAccountService.AuthenticateWithCertificate] result: {0}", result);

            return result;
        }

        protected virtual bool Authenticate(TAccount account, X509Certificate2 certificate)
        {
            _log.Info("[UserAccountService.Authenticate] certificate auth called for account ID: {0}", account.ID);

            if (!certificate.Validate())
            {
                _log.Error("[UserAccountService.Authenticate] failed -- cert failed to validate");
                return false;
            }

            _log.Trace("[UserAccountService.Authenticate] cert: {0}", certificate.Thumbprint);

            if (!(certificate.NotBefore < UtcNow && UtcNow < certificate.NotAfter))
            {
                _log.Error("[UserAccountService.Authenticate] failed -- invalid certificate dates");
                this.AddEvent(new InvalidCertificateEvent<TAccount> { Account = account, Certificate = certificate });
                return false;
            }

            var match = account.Certificates.FirstOrDefault(x => x.Thumbprint.Equals(certificate.Thumbprint, StringComparison.OrdinalIgnoreCase));
            if (match == null)
            {
                _log.Error("[UserAccountService.Authenticate] failed -- no certificate thumbprint match");
                this.AddEvent(new InvalidCertificateEvent<TAccount> { Account = account, Certificate = certificate });
                return false;
            }

            _log.Trace("[UserAccountService.Authenticate] success");

            account.LastLogin = UtcNow;
            account.CurrentTwoFactorAuthStatus = TwoFactorAuthMode.None;

            this.AddEvent(new SuccessfulCertificateLoginEvent<TAccount> { Account = account, UserCertificate = match, Certificate = certificate });

            return true;
        }

        public virtual void SetIsLoginAllowed(Guid accountID, bool isLoginAllowed)
        {
            _log.Info("[UserAccountService.SetIsLoginAllowed] called: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            bool originalIsLoginAllowed = account.IsLoginAllowed;
            account.IsLoginAllowed = isLoginAllowed;

            _log.Trace("[UserAccountService.SetIsLoginAllowed] success");

            if (!originalIsLoginAllowed && isLoginAllowed)
            {
                this.AddEvent(new AccountUnlockedEvent<TAccount> { Account = account });
            }

            Update(account);
        }

        public virtual void SetRequiresPasswordReset(Guid accountID, bool requiresPasswordReset)
        {
            _log.Info("[UserAccountService.SetRequiresPasswordReset] called: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            account.RequiresPasswordReset = requiresPasswordReset;

            _log.Trace("[UserAccountService.SetRequiresPasswordReset] success");

            Update(account);
        }

        public virtual void SetPassword(Guid accountID, string newPassword)
        {
            _log.Info("[UserAccountService.SetPassword] called: {0}", accountID);

            if (String.IsNullOrWhiteSpace(newPassword))
            {
                _log.Error("[UserAccountService.SetPassword] failed -- null newPassword");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidNewPassword));
            }

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            ValidatePassword(account, newPassword);
            SetPassword(account, newPassword);
            Update(account);

            _log.Trace("[UserAccountService.SetPassword] success");
        }

        public virtual void ChangePassword(Guid accountID, string oldPassword, string newPassword)
        {
            _log.Info("[UserAccountService.ChangePassword] called: {0}", accountID);

            if (String.IsNullOrWhiteSpace(oldPassword))
            {
                _log.Error("[UserAccountService.ChangePassword] failed -- null oldPassword");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidOldPassword));
            }
            if (String.IsNullOrWhiteSpace(newPassword))
            {
                _log.Error("[UserAccountService.ChangePassword] failed -- null newPassword");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidNewPassword));
            }

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            if (!VerifyPassword(account, oldPassword))
            {
                _log.Error("[UserAccountService.ChangePassword] failed -- failed authN");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidOldPassword));
            }

            ValidatePassword(account, newPassword);

            _log.Trace("[UserAccountService.ChangePassword] success");

            SetPassword(account, newPassword);
            Update(account);
        }

        public virtual void ResetPassword(Guid id)
        {
            var account = this.GetByID(id);
            if (account == null) throw new ArgumentException("Invalid ID");

            ResetPassword(account);
            UpdateInternal(account);
        }

        public virtual void ResetPassword(string email)
        {
            ResetPassword(null, email);
        }

        public virtual void ResetPassword(string tenant, string email)
        {
            if (Configuration.EmailIsUnique == false)
            {
                throw new InvalidOperationException("ResetPassword via email can't be used when EmailIsUnique is false");
            }
            
            if (!Configuration.MultiTenant)
            {
                _log.Trace("[UserAccountService.ResetPassword] applying default tenant");
                tenant = Configuration.DefaultTenant;
            }

            _log.Info("[UserAccountService.ResetPassword] called: {0}, {1}", tenant, email);

            if (String.IsNullOrWhiteSpace(tenant))
            {
                _log.Error("[UserAccountService.ResetPassword] failed -- null tenant");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidTenant));
            }
            if (String.IsNullOrWhiteSpace(email))
            {
                _log.Error("[UserAccountService.ResetPassword] failed -- null email");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidEmail));
            }

            var account = this.GetByEmail(tenant, email);
            if (account == null) throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidEmail));

            if (account.PasswordResetSecrets.Any())
            {
                _log.Error("[UserAccountService.ResetPassword] failed -- account configured for secret question/answer");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.AccountPasswordResetRequiresSecretQuestion));
            }

            _log.Trace("[UserAccountService.ResetPassword] success");

            ResetPassword(account);
            UpdateInternal(account);
        }

        public virtual void ResetFailedLoginCount(Guid accountID)
        {
            _log.Info("[UserAccountService.ResetFailedLoginCount] called: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            account.FailedLoginCount = 0;

            Update(account);

            _log.Trace("[UserAccountService.ResetFailedLoginCount] success");
        }

        public virtual bool ChangePasswordFromResetKey(string key, string newPassword)
        {
            TAccount account;
            return ChangePasswordFromResetKey(key, newPassword, out account);
        }

        public virtual bool ChangePasswordFromResetKey(string key, string newPassword, out TAccount account)
        {
            _log.Info("[UserAccountService.ChangePasswordFromResetKey] called: {0}", key);

            if (String.IsNullOrWhiteSpace(key))
            {
                _log.Error("[UserAccountService.ChangePasswordFromResetKey] failed -- null key");
                account = null;
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidKey));
            }

            if (String.IsNullOrWhiteSpace(newPassword))
            {
                _log.Error("[UserAccountService.ChangePasswordFromResetKey] failed -- newPassword empty/null");
                account = null;
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.PasswordRequired));
            }

            account = this.GetByVerificationKey(key);
            if (account == null) return false;

            ValidatePassword(account, newPassword);

            if (!account.IsAccountVerified)
            {
                _log.Error("[UserAccountService.ChangePasswordFromResetKey] failed -- account not verified");
                return false;
            }

            if (!IsVerificationKeyValid(account, VerificationKeyPurpose.ResetPassword, key))
            {
                _log.Error("[UserAccountService.ChangePasswordFromResetKey] failed -- key verification failed");
                return false;
            }

            _log.Trace("[UserAccountService.ChangePasswordFromResetKey] success");

            ClearVerificationKey(account);
            SetPassword(account, newPassword);
            Update(account);

            return true;
        }

        public virtual void AddPasswordResetSecret(Guid accountID, string question, string answer)
        {
            _log.Info("[UserAccountService.AddPasswordResetSecret] called: {0}", accountID);

            if (String.IsNullOrWhiteSpace(question))
            {
                _log.Error("[UserAccountService.AddPasswordResetSecret] failed -- null question");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.SecretQuestionRequired));
            }
            if (String.IsNullOrWhiteSpace(answer))
            {
                _log.Error("[UserAccountService.AddPasswordResetSecret] failed -- null answer");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.SecretAnswerRequired));
            }

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            if (account.PasswordResetSecrets.Any(x => x.Question == question))
            {
                _log.Error("[UserAccountService.AddPasswordResetSecret] failed -- question already exists");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.SecretQuestionAlreadyInUse));
            }

            _log.Trace("[UserAccountService.AddPasswordResetSecret] success");

            var secret = new PasswordResetSecret();
            secret.PasswordResetSecretID = Guid.NewGuid();
            secret.Question = question;
            secret.Answer = this.Configuration.Crypto.Hash(answer);
            account.AddPasswordResetSecret(secret);

            this.AddEvent(new PasswordResetSecretAddedEvent<TAccount> { Account = account, Secret = secret });

            Update(account);
        }

        public virtual void RemovePasswordResetSecret(Guid accountID, Guid questionID)
        {
            _log.Info("[UserAccountService.RemovePasswordResetSecret] called: Acct: {0}, Question: {1}", accountID, questionID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            var item = account.PasswordResetSecrets.SingleOrDefault(x => x.PasswordResetSecretID == questionID);
            if (item != null)
            {
                _log.Trace("[UserAccountService.RemovePasswordResetSecret] success -- item removed");

                account.RemovePasswordResetSecret(item);
                this.AddEvent(new PasswordResetSecretRemovedEvent<TAccount> { Account = account, Secret = item });
                Update(account);
            }
            else
            {
                _log.Trace("[UserAccountService.RemovePasswordResetSecret] no matching item found");
            }
        }

        public virtual void ResetPasswordFromSecretQuestionAndAnswer(Guid accountID, PasswordResetQuestionAnswer[] answers)
        {
            _log.Info("[UserAccountService.ResetPasswordFromSecretQuestionAndAnswer] called: {0}", accountID);

            if (answers == null || answers.Length == 0 || answers.Any(x => String.IsNullOrWhiteSpace(x.Answer)))
            {
                _log.Error("[UserAccountService.ResetPasswordFromSecretQuestionAndAnswer] failed -- no answers");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.SecretAnswerRequired));
            }

            var account = this.GetByID(accountID);
            if (account == null)
            {
                _log.Error("[UserAccountService.ResetPasswordFromSecretQuestionAndAnswer] failed -- invalid account id");
                throw new Exception("Invalid Account ID");
            }

            if (String.IsNullOrWhiteSpace(account.Email))
            {
                _log.Error("[UserAccountService.ResetPasswordFromSecretQuestionAndAnswer] no email to use for password reset");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.PasswordResetErrorNoEmail));
            }

            if (!account.PasswordResetSecrets.Any())
            {
                _log.Error("[UserAccountService.ResetPasswordFromSecretQuestionAndAnswer] failed -- account not configured for secret question/answer");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.AccountNotConfiguredWithSecretQuestion));
            }

            if (account.FailedPasswordResetCount >= Configuration.AccountLockoutFailedLoginAttempts &&
                account.LastFailedPasswordReset >= UtcNow.Subtract(Configuration.AccountLockoutDuration))
            {
                account.FailedPasswordResetCount++;

                this.AddEvent(new PasswordResetFailedEvent<TAccount> { Account = account });

                UpdateInternal(account);

                _log.Error("[UserAccountService.ResetPasswordFromSecretQuestionAndAnswer] failed -- too many failed password reset attempts");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidQuestionOrAnswer));
            }

            var secrets = account.PasswordResetSecrets.ToArray();
            var failed = false;
            foreach (var answer in answers)
            {
                var secret = secrets.SingleOrDefault(x => x.PasswordResetSecretID == answer.QuestionID);
                if (secret == null ||
                    !this.Configuration.Crypto.VerifyHash(answer.Answer, secret.Answer))
                {
                    _log.Error("[UserAccountService.ResetPasswordFromSecretQuestionAndAnswer] failed on question id: {0}", answer.QuestionID);
                    failed = true;
                }
            }

            if (failed)
            {
                account.LastFailedPasswordReset = UtcNow;
                if (account.FailedPasswordResetCount <= 0)
                {
                    account.FailedPasswordResetCount = 1;
                }
                else
                {
                    account.FailedPasswordResetCount++;
                }
                this.AddEvent(new PasswordResetFailedEvent<TAccount> { Account = account });
            }
            else
            {
                _log.Trace("[UserAccountService.ResetPasswordFromSecretQuestionAndAnswer] success");

                account.LastFailedPasswordReset = null;
                account.FailedPasswordResetCount = 0;
                ResetPassword(account);
            }

            UpdateInternal(account);

            if (failed)
            {
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidQuestionOrAnswer));
            }
        }

        public virtual void SendUsernameReminder(string email)
        {
            SendUsernameReminder(null, email);
        }

        public virtual void SendUsernameReminder(string tenant, string email)
        {
            if (Configuration.EmailIsUnique == false)
            {
                throw new InvalidOperationException("SendUsernameReminder can't be used when EmailIsUnique is false");
            }

            if (!Configuration.MultiTenant)
            {
                _log.Trace("[UserAccountService.SendUsernameReminder] applying default tenant");
                tenant = Configuration.DefaultTenant;
            }

            _log.Info("[UserAccountService.SendUsernameReminder] called: {0}, {1}", tenant, email);

            if (String.IsNullOrWhiteSpace(tenant))
            {
                _log.Error("[UserAccountService.SendUsernameReminder] failed -- null tenant");
                throw new ArgumentNullException("tenant");
            }
            if (String.IsNullOrWhiteSpace(email))
            {
                _log.Error("[UserAccountService.SendUsernameReminder] failed -- null email");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidEmail));
            }

            var account = this.GetByEmail(tenant, email);
            if (account == null) throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidEmail));

            if (!account.IsAccountVerified)
            {
                _log.Error("[UserAccountService.SendUsernameReminder] failed -- account not verified");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.AccountNotVerified));
            }

            _log.Trace("[UserAccountService.SendUsernameReminder] success");

            this.AddEvent(new UsernameReminderRequestedEvent<TAccount> { Account = account });

            UpdateInternal(account);
        }

        public virtual void ChangeUsername(Guid accountID, string newUsername)
        {
            _log.Info("[UserAccountService.ChangeUsername] called account id: {0}, new username: {1}", accountID, newUsername);

            if (Configuration.EmailIsUsername)
            {
                _log.Error("[UserAccountService.ChangeUsername] failed -- SecuritySettings.EmailIsUsername is true, use ChangeEmail API instead");
                throw new Exception("EmailIsUsername is enabled in SecuritySettings -- use ChangeEmail APIs instead.");
            }

            if (String.IsNullOrWhiteSpace(newUsername))
            {
                _log.Error("[UserAccountService.ChangeUsername] failed -- null newUsername");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidUsername));
            }

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            ValidateUsername(account, newUsername);

            _log.Trace("[UserAccountService.ChangeUsername] success");

            account.Username = newUsername;

            this.AddEvent(new UsernameChangedEvent<TAccount> { Account = account });

            Update(account);
        }

        public virtual void ChangeEmailRequest(Guid accountID, string newEmail)
        {
            _log.Info("[UserAccountService.ChangeEmailRequest] called: {0}, {1}", accountID, newEmail);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            ValidateEmail(account, newEmail);

            var oldEmail = account.Email;

            _log.Trace("[UserAccountService.ChangeEmailRequest] creating a new reset key");
            var key = SetVerificationKey(account, VerificationKeyPurpose.ChangeEmail, state: newEmail);

            if (!Configuration.RequireAccountVerification)
            {
                _log.Trace("[UserAccountService.ChangeEmailRequest] RequireAccountVerification false, changing email");
                account.IsAccountVerified = false;
                account.Email = newEmail;
                this.AddEvent(new EmailChangedEvent<TAccount> { Account = account, OldEmail = oldEmail, VerificationKey = key });
                Update(account);
            }
            else
            {
                _log.Trace("[UserAccountService.ChangeEmailRequest] RequireAccountVerification true, sending changing email");
                this.AddEvent(new EmailChangeRequestedEvent<TAccount> { Account = account, OldEmail = oldEmail, NewEmail = newEmail, VerificationKey = key });
                UpdateInternal(account);
            }

            _log.Trace("[UserAccountService.ChangeEmailRequest] success");
        }

        public virtual void VerifyEmailFromKey(string key)
        {
            TAccount account;
            VerifyEmailFromKey(key, out account);
        }

        public virtual void VerifyEmailFromKey(string key, out TAccount account)
        {
            VerifyEmailFromKey(key, null, out account);
        }

        public virtual void VerifyEmailFromKey(string key, string password)
        {
            TAccount account;
            VerifyEmailFromKey(key, password, out account);
        }

        public virtual void VerifyEmailFromKey(string key, string password, out TAccount account)
        {
            _log.Info("[UserAccountService.VerifyEmailFromKey] called");

            if (String.IsNullOrWhiteSpace(key))
            {
                _log.Error("[UserAccountService.VerifyEmailFromKey] failed -- null key");
                account = null;
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidKey));
            }

            account = this.GetByVerificationKey(key);
            if (account == null)
            {
                _log.Error("[UserAccountService.VerifyEmailFromKey] failed -- invalid key");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidKey));
            }

            _log.Info("[UserAccountService.VerifyEmailFromKey] account located: id: {0}", account.ID);

            if (account.HasPassword() && String.IsNullOrWhiteSpace(password))
            {
                _log.Error("[UserAccountService.VerifyEmailFromKey] failed -- null password");
                account = null;
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidPassword));
            }

            if (!IsVerificationKeyValid(account, VerificationKeyPurpose.ChangeEmail, key))
            {
                _log.Error("[UserAccountService.VerifyEmailFromKey] failed -- key verification failed");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidKey));
            }

            if (account.HasPassword() && !VerifyPassword(account, password))
            {
                _log.Error("[UserAccountService.VerifyEmailFromKey] failed -- authN failed");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidPassword));
            }

            if (String.IsNullOrWhiteSpace(account.VerificationStorage))
            {
                _log.Trace("[UserAccountService.VerifyEmailFromKey] failed -- verification storage empty");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidKey));
            }

            // one last check
            ValidateEmail(account, account.VerificationStorage);

            bool isNewAccount = account.IsNew();
            account.Email = account.VerificationStorage;
            account.IsAccountVerified = true;
            account.LastLogin = UtcNow;

            ClearVerificationKey(account);

            this.AddEvent(new EmailVerifiedEvent<TAccount> { Account = account, IsNewAccount = isNewAccount });

            if (Configuration.EmailIsUsername)
            {
                _log.Trace("[UserAccountService.VerifyEmailFromKey] security setting EmailIsUsername is true, so changing username: {0}, to: {1}", account.Username, account.Email);
                account.Username = account.Email;
            }

            Update(account);

            _log.Trace("[UserAccountService.VerifyEmailFromKey] success");
        }

        public virtual void SetConfirmedEmail(Guid accountID, string email)
        {
            _log.Info("[UserAccountService.SetConfirmedEmail] called: {0}, {1}", accountID, email);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            ValidateEmail(account, email);

            account.IsAccountVerified = true;
            account.Email = email;
            
            ClearVerificationKey(account);

            this.AddEvent(new EmailVerifiedEvent<TAccount> { Account = account });

            if (Configuration.EmailIsUsername)
            {
                _log.Trace("[UserAccountService.SetConfirmedEmail] security setting EmailIsUsername is true, so changing username: {0}, to: {1}", account.Username, account.Email);
                account.Username = account.Email;
            }

            Update(account);

            _log.Trace("[UserAccountService.SetConfirmedEmail] success");
        }

        public virtual void RemoveMobilePhone(Guid accountID)
        {
            _log.Info("[UserAccountService.RemoveMobilePhone] called: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            _log.Info("[UserAccountService.ClearMobilePhoneNumber] called for accountID: {0}", account.ID);

            if (account.AccountTwoFactorAuthMode == TwoFactorAuthMode.Mobile)
            {
                _log.Trace("[UserAccountService.ClearMobilePhoneNumber] disabling two factor auth");
                ConfigureTwoFactorAuthentication(account, TwoFactorAuthMode.None);
            }

            if (String.IsNullOrWhiteSpace(account.MobilePhoneNumber))
            {
                _log.Warn("[UserAccountService.ClearMobilePhoneNumber] nothing to do -- no mobile associated with account");
                return;
            }

            _log.Trace("[UserAccountService.ClearMobilePhoneNumber] success");

            ClearMobileAuthCode(account);

            account.MobilePhoneNumber = null;
            account.MobilePhoneNumberChanged = UtcNow;

            this.AddEvent(new MobilePhoneRemovedEvent<TAccount> { Account = account });

            Update(account);
        }

        public virtual void ChangeMobilePhoneRequest(Guid accountID, string newMobilePhoneNumber)
        {
            _log.Info("[UserAccountService.ChangeMobilePhoneRequest] called: {0}, {1}", accountID, newMobilePhoneNumber);

            if (String.IsNullOrWhiteSpace(newMobilePhoneNumber))
            {
                _log.Error("[UserAccountService.ChangeMobilePhoneRequest] failed -- null newMobilePhoneNumber");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidPhone));
            }

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            if (account.MobilePhoneNumber == newMobilePhoneNumber)
            {
                _log.Error("[UserAccountService.RequestChangeMobilePhoneNumber] mobile phone same as current");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.MobilePhoneMustBeDifferent));
            }

            if (MobilePhoneExistsOtherThan(account, newMobilePhoneNumber))
            {
                _log.Trace("[UserAccountValidation.ChangeMobilePhoneFromCode] failed -- number already in use");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.MobilePhoneAlreadyInUse));
            }

            if (!IsVerificationPurposeValid(account, VerificationKeyPurpose.ChangeMobile) ||
                CanResendMobileCode(account) ||
                newMobilePhoneNumber != account.VerificationStorage ||
                account.CurrentTwoFactorAuthStatus == TwoFactorAuthMode.Mobile)
            {
                ClearMobileAuthCode(account);

                SetVerificationKey(account, VerificationKeyPurpose.ChangeMobile, state: newMobilePhoneNumber);
                var code = IssueMobileCode(account);

                _log.Trace("[UserAccountService.RequestChangeMobilePhoneNumber] success");

                this.AddEvent(new MobilePhoneChangeRequestedEvent<TAccount> { Account = account, NewMobilePhoneNumber = newMobilePhoneNumber, Code = code });
            }
            else
            {
                _log.Trace("[UserAccountService.RequestChangeMobilePhoneNumber] complete, but not issuing a new code");
            }

            UpdateInternal(account);
        }

        public virtual bool ChangeMobilePhoneFromCode(Guid accountID, string code)
        {
            _log.Info("[UserAccountService.ChangeMobileFromCode] called: {0}", accountID);

            if (String.IsNullOrWhiteSpace(code))
            {
                _log.Error("[UserAccountService.ChangeMobileFromCode] failed -- null code");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.CodeRequired));
            }

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            _log.Info("[UserAccountService.ConfirmMobilePhoneNumberFromCode] called for accountID: {0}", account.ID);

            if (account.VerificationPurpose != VerificationKeyPurpose.ChangeMobile)
            {
                _log.Error("[UserAccountService.ConfirmMobilePhoneNumberFromCode] failed -- invalid verification key purpose");
                return false;
            }

            if (!VerifyMobileCode(account, code))
            {
                _log.Error("[UserAccountService.ConfirmMobilePhoneNumberFromCode] failed -- mobile code failed to verify");
                return false;
            }

            var newMobile = account.VerificationStorage;
            if (MobilePhoneExistsOtherThan(account, newMobile))
            {
                _log.Trace("[UserAccountValidation.ChangeMobilePhoneFromCode] failed -- number already in use");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.MobilePhoneAlreadyInUse));
            }

            _log.Trace("[UserAccountService.ConfirmMobilePhoneNumberFromCode] success");

            account.MobilePhoneNumber = newMobile;
            account.MobilePhoneNumberChanged = UtcNow;

            ClearVerificationKey(account);
            ClearMobileAuthCode(account);

            this.AddEvent(new MobilePhoneChangedEvent<TAccount> { Account = account });

            Update(account);

            return true;
        }

        public virtual void SetConfirmedMobilePhone(Guid accountID, string phone)
        {
            _log.Info("[UserAccountService.SetConfirmedMobilePhone] called: {0}, {1}", accountID, phone);

            if (String.IsNullOrWhiteSpace(phone))
            {
                _log.Error("[UserAccountService.SetConfirmedMobilePhone] failed -- null phone");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.MobilePhoneRequired));
            }

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            if (account.MobilePhoneNumber == phone)
            {
                _log.Error("[UserAccountService.SetConfirmedMobilePhone] mobile phone same as current");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.MobilePhoneMustBeDifferent));
            }

            if (MobilePhoneExistsOtherThan(account, phone))
            {
                _log.Trace("[UserAccountValidation.SetConfirmedMobilePhone] failed -- number already in use");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.MobilePhoneAlreadyInUse));
            }

            account.MobilePhoneNumber = phone;
            account.MobilePhoneNumberChanged = UtcNow;

            ClearVerificationKey(account);
            ClearMobileAuthCode(account);

            this.AddEvent(new MobilePhoneChangedEvent<TAccount> { Account = account });

            Update(account);
            
            _log.Trace("[UserAccountService.ConfirmMobilePhoneNumberFromCode] success");
        }

        public virtual bool IsPasswordExpired(Guid accountID)
        {
            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            return IsPasswordExpired(account);
        }

        public virtual bool IsPasswordExpired(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.IsPasswordExpired] called: {0}", account.ID);

            if (Configuration.PasswordResetFrequency <= 0)
            {
                _log.Trace("[UserAccountService.PasswordResetFrequency ] PasswordResetFrequency not set, returning false");
                return false;
            }

            if (!account.HasPassword())
            {
                _log.Trace("[UserAccountService.PasswordResetFrequency ] HashedPassword is null, returning false");
                return false;
            }

            if (account.PasswordChanged == null)
            {
                _log.Warn("[UserAccountService.PasswordResetFrequency ] PasswordChanged is null, returning false");
                return false;
            }

            var now = UtcNow;
            var last = account.PasswordChanged.Value;
            var result = last.AddDays(Configuration.PasswordResetFrequency) <= now;

            _log.Trace("[UserAccountService.PasswordResetFrequency ] result: {0}", result);

            return result;
        }

        protected virtual string SetVerificationKey(TAccount account, VerificationKeyPurpose purpose, string key = null, string state = null)
        {
            if (key == null) key = StripUglyBase64(Configuration.Crypto.GenerateSalt());

            account.VerificationKey = this.Configuration.Crypto.Hash(key);
            account.VerificationPurpose = purpose;
            account.VerificationKeySent = UtcNow;
            account.VerificationStorage = state;

            return key;
        }

        protected virtual bool IsVerificationKeyValid(TAccount account, VerificationKeyPurpose purpose, string key)
        {
            if (!IsVerificationPurposeValid(account, purpose))
            {
                return false;
            }

            var result = Configuration.Crypto.VerifyHash(key, account.VerificationKey);
            if (!result)
            {
                _log.Warn("[UserAccountService.IsVerificationKeyValid] failed -- verification key doesn't match");
                return false;
            }

            _log.Trace("[UserAccountService.IsVerificationKeyValid] success -- verification key valid");
            return true;
        }

        protected virtual bool IsVerificationPurposeValid(TAccount account, VerificationKeyPurpose purpose)
        {
            if (account.VerificationPurpose != purpose)
            {
                _log.Warn("[UserAccountService.IsVerificationPurposeValid] failed -- verification purpose invalid");
                return false;
            }

            if (IsVerificationKeyStale(account))
            {
                _log.Warn("[UserAccountService.IsVerificationPurposeValid] failed -- verification key stale");
                return false;
            }

            _log.Trace("[UserAccountService.IsVerificationPurposeValid] success -- verification purpose valid");
            return true;
        }

        public virtual bool IsVerificationKeyStale(Guid accountID)
        {
            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            return IsVerificationKeyStale(account);
        }
        
        protected virtual bool IsVerificationKeyStale(TAccount account)
        {
            if (account.VerificationKeySent == null)
            {
                return true;
            }

            if (account.VerificationKeySent < UtcNow.Subtract(Configuration.VerificationKeyLifetime))
            {
                return true;
            }

            return false;
        }

        protected virtual void ClearVerificationKey(TAccount account)
        {
            account.VerificationKey = null;
            account.VerificationPurpose = null;
            account.VerificationKeySent = null;
            account.VerificationStorage = null;
        }

        protected virtual void SetPassword(TAccount account, string password)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.SetPassword] called for accountID: {0}", account.ID);

            if (String.IsNullOrWhiteSpace(password))
            {
                _log.Error("[UserAccountService.SetPassword] failed -- no password provided");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidPassword));
            }

            _log.Trace("[UserAccountService.SetPassword] setting new password hash");

            account.HashedPassword = Configuration.Crypto.HashPassword(password, this.Configuration.PasswordHashingIterationCount);
            account.PasswordChanged = UtcNow;
            account.RequiresPasswordReset = false;
            account.FailedLoginCount = 0;

            this.AddEvent(new PasswordChangedEvent<TAccount> { Account = account, NewPassword = password });
        }

        protected virtual void ResetPassword(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.ResetPassword] called for accountID: {0}", account.ID);

            if (String.IsNullOrWhiteSpace(account.Email))
            {
                _log.Error("[UserAccountService.ResetPassword] no email to use for password reset");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.PasswordResetErrorNoEmail));
            }

            if (!account.IsAccountVerified)
            {
                // if they've not yet verified then don't allow password reset
                if (account.IsNew())
                {
                    // instead request an initial account verification
                    _log.Trace("[UserAccountService.ResetPassword] account not verified -- raising account created email event to resend initial email");
                    var key = SetVerificationKey(account, VerificationKeyPurpose.ChangeEmail, state: account.Email);
                    this.AddEvent(new AccountCreatedEvent<TAccount> { Account = account, VerificationKey = key });
                }
                else
                {
                    _log.Trace("[UserAccountService.ResetPassword] account not verified -- raising change email event to resend email verification");
                    var key = SetVerificationKey(account, VerificationKeyPurpose.ChangeEmail, state: account.Email);
                    this.AddEvent(new EmailChangeRequestedEvent<TAccount> { Account = account, NewEmail = account.Email, VerificationKey = key });
                }
            }
            else
            {
                _log.Trace("[UserAccountService.ResetPassword] creating new verification keys");
                var key = SetVerificationKey(account, VerificationKeyPurpose.ResetPassword);

                _log.Trace("[UserAccountService.ResetPassword] account verified -- raising event to send reset notification");
                this.AddEvent(new PasswordResetRequestedEvent<TAccount> { Account = account, VerificationKey = key });
            }
        }

        protected virtual string IssueMobileCode(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            string code = this.Configuration.Crypto.GenerateNumericCode(MembershipRebootConstants.UserAccount.MobileCodeLength);
            account.MobileCode = this.Configuration.Crypto.HashPassword(code, this.Configuration.PasswordHashingIterationCount);
            account.MobileCodeSent = UtcNow;

            return code;
        }

        protected virtual bool VerifyMobileCode(TAccount account, string code)
        {
            if (account == null) throw new ArgumentNullException("account");
            if (String.IsNullOrWhiteSpace(code)) return false;

            if (IsMobileCodeExpired(account))
            {
                _log.Error("[UserAccountService.VerifyMobileCode] failed -- mobile code stale");
                return false;
            }

            try
            {
                if (CheckHasTooManyRecentPasswordFailures(account))
                {
                    _log.Error("[UserAccountService.VerifyMobileCode] failed -- TooManyRecentPasswordFailures");
                    return false;
                }

                var result = this.Configuration.Crypto.VerifyHashedPassword(account.MobileCode, code);
                if (!result)
                {
                    RecordInvalidLoginAttempt(account);
                    _log.Error("[UserAccountService.VerifyMobileCode] failed -- mobile code invalid");
                    return false;
                }

                account.FailedLoginCount = 0;

                _log.Trace("[UserAccountService.VerifyMobileCode] success -- mobile code valid");
                return true;
            }
            finally
            {
                UpdateInternal(account);
            }
        }

        protected virtual void ClearMobileAuthCode(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Trace("[UserAccountService.ClearMobileAuthCode] called for account id {0}", account.ID);

            account.MobileCode = null;
            account.MobileCodeSent = null;
            if (account.CurrentTwoFactorAuthStatus == TwoFactorAuthMode.Mobile)
            {
                account.CurrentTwoFactorAuthStatus = TwoFactorAuthMode.None;
            }
            if (account.VerificationPurpose == VerificationKeyPurpose.ChangeMobile)
            {
                ClearVerificationKey(account);
            }
        }

        protected virtual bool IsMobileCodeOlderThan(TAccount account, int duration)
        {
            if (account == null) throw new ArgumentNullException("account");

            if (account.MobileCodeSent == null || String.IsNullOrWhiteSpace(account.MobileCode))
            {
                return true;
            }

            if (account.MobileCodeSent < UtcNow.AddMinutes(-duration))
            {
                return true;
            }

            return false;
        }

        protected virtual bool IsMobileCodeExpired(TAccount account)
        {
            return IsMobileCodeOlderThan(account, MembershipRebootConstants.UserAccount.MobileCodeStaleDurationMinutes);
        }

        protected virtual bool CanResendMobileCode(TAccount account)
        {
            return IsMobileCodeOlderThan(account, MembershipRebootConstants.UserAccount.MobileCodeResendDelayMinutes);
        }

        public virtual void ConfigureTwoFactorAuthentication(Guid accountID, TwoFactorAuthMode mode)
        {
            _log.Info("[UserAccountService.ConfigureTwoFactorAuthentication] called: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            ConfigureTwoFactorAuthentication(account, mode);
            Update(account);

            _log.Trace("[UserAccountService.ConfigureTwoFactorAuthentication] success");
        }

        protected virtual void ConfigureTwoFactorAuthentication(TAccount account, TwoFactorAuthMode mode)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.ConfigureTwoFactorAuthentication] called for accountID: {0}, mode: {1}", account.ID, mode);

            if (account.AccountTwoFactorAuthMode == mode)
            {
                _log.Warn("[UserAccountService.ConfigureTwoFactorAuthentication] nothing to do -- mode is same as current value");
                return;
            }

            if (mode == TwoFactorAuthMode.Mobile &&
                String.IsNullOrWhiteSpace(account.MobilePhoneNumber))
            {
                _log.Error("[UserAccountService.ConfigureTwoFactorAuthentication] failed -- mobile requested but no mobile phone for account");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.RegisterMobileForTwoFactor));
            }

            if (mode == TwoFactorAuthMode.Certificate &&
                !account.Certificates.Any())
            {
                _log.Error("[UserAccountService.ConfigureTwoFactorAuthentication] failed -- certificate requested but no certificates for account");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.AddClientCertForTwoFactor));
            }

            ClearMobileAuthCode(account);

            account.AccountTwoFactorAuthMode = mode;
            account.CurrentTwoFactorAuthStatus = TwoFactorAuthMode.None;

            if (mode == TwoFactorAuthMode.None)
            {
                RemoveTwoFactorAuthTokens(account);

                _log.Trace("[UserAccountService.ConfigureTwoFactorAuthentication] success -- two factor auth disabled");
                this.AddEvent(new TwoFactorAuthenticationDisabledEvent<TAccount> { Account = account });
            }
            else
            {
                _log.Trace("[UserAccountService.ConfigureTwoFactorAuthentication] success -- two factor auth enabled, mode: {0}", mode);
                this.AddEvent(new TwoFactorAuthenticationEnabledEvent<TAccount> { Account = account, Mode = mode });
            }
        }

        protected virtual bool RequestTwoFactorAuthCertificate(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.RequestTwoFactorAuthCertificate] called for accountID: {0}", account.ID);

            if (account.IsAccountClosed)
            {
                _log.Error("[UserAccountService.RequestTwoFactorAuthCertificate] failed -- account closed");
                return false;
            }

            if (!account.IsLoginAllowed)
            {
                _log.Error("[UserAccountService.RequestTwoFactorAuthCertificate] failed -- login not allowed");
                return false;
            }

            if (account.AccountTwoFactorAuthMode != TwoFactorAuthMode.Certificate)
            {
                _log.Error("[UserAccountService.RequestTwoFactorAuthCertificate] failed -- current auth mode is not certificate");
                return false;
            }

            if (!account.Certificates.Any())
            {
                _log.Error("[UserAccountService.RequestTwoFactorAuthCertificate] failed -- no certificates");
                return false;
            }

            _log.Trace("[UserAccountService.RequestTwoFactorAuthCertificate] success");

            account.CurrentTwoFactorAuthStatus = TwoFactorAuthMode.Certificate;

            return true;
        }

        protected virtual bool RequestTwoFactorAuthCode(TAccount account, bool force = false)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.RequestTwoFactorAuthCode] called for accountID: {0}", account.ID);

            if (account.IsAccountClosed)
            {
                _log.Error("[UserAccountService.RequestTwoFactorAuthCode] failed -- account closed");
                return false;
            }

            if (!account.IsLoginAllowed)
            {
                _log.Error("[UserAccountService.RequestTwoFactorAuthCode] failed -- login not allowed");
                return false;
            }

            if (account.AccountTwoFactorAuthMode != TwoFactorAuthMode.Mobile)
            {
                _log.Error("[UserAccountService.RequestTwoFactorAuthCode] failed -- AccountTwoFactorAuthMode not mobile");
                return false;
            }

            if (String.IsNullOrWhiteSpace(account.MobilePhoneNumber))
            {
                _log.Error("[UserAccountService.RequestTwoFactorAuthCode] failed -- empty MobilePhoneNumber");
                return false;
            }

            if (CanResendMobileCode(account) ||
                account.CurrentTwoFactorAuthStatus != TwoFactorAuthMode.Mobile)
            {
                ClearMobileAuthCode(account);

                _log.Trace("[UserAccountService.RequestTwoFactorAuthCode] new mobile code issued");
                var code = IssueMobileCode(account);
                account.CurrentTwoFactorAuthStatus = TwoFactorAuthMode.Mobile;

                _log.Trace("[UserAccountService.RequestTwoFactorAuthCode] success");

                this.AddEvent(new TwoFactorAuthenticationCodeNotificationEvent<TAccount> { Account = account, Code = code });
            }
            else
            {
                _log.Trace("[UserAccountService.RequestTwoFactorAuthCode] success, but not issuing a new code");
            }

            return true;
        }

        public virtual void SendTwoFactorAuthenticationCode(Guid accountID)
        {
            _log.Info("[UserAccountService.SendTwoFactorAuthenticationCode] called: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            RequestTwoFactorAuthCode(account, true);
            UpdateInternal(account);
        }

        public virtual void AddClaims(Guid accountID, UserClaimCollection claims)
        {
            _log.Info("[UserAccountService.AddClaims] called for accountID: {0}", accountID);
            this.UpdateClaims(accountID, claims, null);
        }

        public virtual void RemoveClaims(Guid accountID, UserClaimCollection claims)
        {
            _log.Info("[UserAccountService.RemoveClaims] called for accountID: {0}", accountID);
            this.UpdateClaims(accountID, null, claims);
        }

        public virtual void UpdateClaims(
            Guid accountID,
            UserClaimCollection additions = null,
            UserClaimCollection deletions = null)
        {
            _log.Info("[UserAccountService.UpdateClaims] called for accountID: {0}", accountID);

            if ((additions == null || !additions.Any()) &&
                (deletions == null || !deletions.Any()))
            {
                _log.Trace("[UserAccountService.UpdateClaims] no additions or deletions -- exiting");
                return;
            }

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            foreach (var addition in additions ?? UserClaimCollection.Empty)
            {
                AddClaim(account, addition);
            }
            foreach (var deletion in deletions ?? UserClaimCollection.Empty)
            {
                RemoveClaim(account, deletion.Type, deletion.Value);
            }
            Update(account);
        }

        public virtual void AddClaim(Guid accountID, string type, string value)
        {
            _log.Info("[UserAccountService.AddClaim] called for accountID: {0}", accountID);

            if (String.IsNullOrWhiteSpace(type))
            {
                _log.Error("[UserAccountService.AddClaim] failed -- null type");
                throw new ArgumentException("type");
            }

            if (String.IsNullOrWhiteSpace(value))
            {
                _log.Error("[UserAccountService.AddClaim] failed -- null value");
                throw new ArgumentException("value");
            }
            
            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID", "accountID");

            AddClaim(account, new UserClaim(type, value));
            Update(account);
        }

        private void AddClaim(TAccount account, UserClaim claim)
        {
            if (claim == null) throw new ArgumentNullException("claim");

            if (!account.HasClaim(claim.Type, claim.Value))
            {
                account.AddClaim(claim);
                this.AddEvent(new ClaimAddedEvent<TAccount> {Account = account, Claim = claim});

                _log.Trace("[UserAccountService.AddClaim] claim added");
            }
        }

        public virtual void RemoveClaim(Guid accountID, string type)
        {
            _log.Info("[UserAccountService.RemoveClaim] called for accountID: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID", "accountID");

            if (String.IsNullOrWhiteSpace(type))
            {
                _log.Error("[UserAccountService.RemoveClaim] failed -- null type");
                throw new ArgumentException("type");
            }

            var claimsToRemove =
                from claim in account.Claims
                where claim.Type == type
                select claim;
            foreach (var claim in claimsToRemove.ToArray())
            {
                account.RemoveClaim(claim);
                this.AddEvent(new ClaimRemovedEvent<TAccount> { Account = account, Claim = claim });
                _log.Trace("[UserAccountService.RemoveClaim] claim removed");
            }

            Update(account);
        }

        public virtual void RemoveClaim(Guid accountID, string type, string value)
        {
            _log.Info("[UserAccountService.RemoveClaim] called for accountID: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID", "accountID");

            RemoveClaim(account, type, value);
            Update(account);
        }

        private void RemoveClaim(TAccount account, string type, string value)
        {
            if (String.IsNullOrWhiteSpace(type))
            {
                _log.Error("[UserAccountService.RemoveClaim] failed -- null type");
                throw new ArgumentException("type");
            }

            if (String.IsNullOrWhiteSpace(value))
            {
                _log.Error("[UserAccountService.RemoveClaim] failed -- null value");
                throw new ArgumentException("value");
            }

            var claimsToRemove =
                from claim in account.Claims
                where claim.Type == type && claim.Value == value
                select claim;
            foreach (var claim in claimsToRemove.ToArray())
            {
                account.RemoveClaim(claim);
                this.AddEvent(new ClaimRemovedEvent<TAccount> {Account = account, Claim = claim});
                _log.Trace("[UserAccountService.RemoveClaim] claim removed");
            }
        }

        protected virtual LinkedAccount GetLinkedAccount(TAccount account, string provider, string id)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.GetLinkedAccount] called for account ID: {0}", account.ID);

            return account.LinkedAccounts.Where(x => x.ProviderName == provider && x.ProviderAccountID == id).SingleOrDefault();
        }

        public virtual void AddOrUpdateLinkedAccount(TAccount account, string provider, string id, IEnumerable<Claim> claims = null)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.AddOrUpdateLinkedAccount] called for accountID: {0}", account.ID);

            if (String.IsNullOrWhiteSpace(provider))
            {
                _log.Error("[UserAccountService.AddOrUpdateLinkedAccount] failed -- null provider");
                throw new ArgumentNullException("provider");
            }
            if (String.IsNullOrWhiteSpace(id))
            {
                _log.Error("[UserAccountService.AddOrUpdateLinkedAccount] failed -- null id");
                throw new ArgumentNullException("id");
            }

            var otherAcct = this.GetByLinkedAccount(account.Tenant, provider, id);
            if (otherAcct != null && otherAcct.ID != account.ID)
            {
                _log.Error("[UserAccountService.AddOrUpdateLinkedAccount] failed -- adding linked account that is already associated with another account");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.LinkedAccountAlreadyInUse));
            }

            RemoveLinkedAccountClaims(account, provider, id);

            var linked = GetLinkedAccount(account, provider, id);
            if (linked == null)
            {
                linked = new LinkedAccount();
                linked.ProviderName = provider;
                linked.ProviderAccountID = id;
                linked.LastLogin = UtcNow;
                account.AddLinkedAccount(linked);
                this.AddEvent(new LinkedAccountAddedEvent<TAccount> { Account = account, LinkedAccount = linked });

                _log.Trace("[UserAccountService.AddOrUpdateLinkedAccount] linked account added");
            }
            else
            {
                linked.LastLogin = UtcNow;
            }

            account.LastLogin = UtcNow;

            claims = claims ?? Enumerable.Empty<Claim>();
            foreach (var c in claims)
            {
                var claim = new LinkedAccountClaim();
                claim.ProviderName = linked.ProviderName;
                claim.ProviderAccountID = linked.ProviderAccountID;
                claim.Type = c.Type;
                claim.Value = c.Value;
                account.AddLinkedAccountClaim(claim);
            }

            Update(account);
        }

        public virtual void RemoveLinkedAccount(Guid accountID, string provider, string id)
        {
            _log.Info("[UserAccountService.RemoveLinkedAccount] called for account ID: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            var linked = GetLinkedAccount(account, provider, id);

            if (linked != null && account.LinkedAccounts.Count() == 1 && !account.HasPassword())
            {
                // can't remove last linked account if no password
                _log.Error("[UserAccountService.RemoveLinkedAccount] no password on account -- can't remove last provider");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.CantRemoveLastLinkedAccountIfNoPassword));
            }

            if (linked != null)
            {
                RemoveLinkedAccountClaims(account, provider, id);
                account.RemoveLinkedAccount(linked);
                this.AddEvent(new LinkedAccountRemovedEvent<TAccount> { Account = account, LinkedAccount = linked });
                _log.Trace("[UserAccountService.RemoveLinkedAccount] linked account removed");
            }

            Update(account);
        }

        public virtual void RemoveLinkedAccountClaims(Guid accountID, string provider, string id)
        {
            _log.Info("[UserAccountService.RemoveLinkedAccountClaims] called for account ID: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            RemoveLinkedAccountClaims(account, provider, id);

            Update(account);
        }

        protected virtual void RemoveLinkedAccountClaims(TAccount account, string provider, string id)
        {
            if (account == null) throw new ArgumentNullException("account");

            var claims = account.LinkedAccountClaims.Where(x => x.ProviderName == provider && x.ProviderAccountID == id).ToArray();
            foreach (var item in claims)
            {
                account.RemoveLinkedAccountClaim(item);
                _log.Trace("[UserAccountService.RemoveLinkedAccountClaims] linked account claim removed");
            }
        }

        public virtual void AddCertificate(Guid accountID, X509Certificate2 certificate)
        {
            _log.Info("[UserAccountService.AddCertificate] called for account ID: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            if (!certificate.Validate())
            {
                _log.Error("[UserAccountService.AddCertificate] failed -- cert failed to validate");
                throw new ValidationException(GetValidationMessage(MembershipRebootConstants.ValidationMessages.InvalidCertificate));
            }

            RemoveCertificate(account, certificate);
            AddCertificate(account, certificate.Thumbprint, certificate.Subject);

            Update(account);
        }

        public virtual void AddCertificate(Guid accountID, string thumbprint, string subject)
        {
            _log.Info("[UserAccountService.AddCertificate] called for account ID: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            AddCertificate(account, thumbprint, subject);
            Update(account);
        }

        protected virtual void AddCertificate(TAccount account, string thumbprint, string subject)
        {
            _log.Info("[UserAccountService.AddCertificate] called for accountID: {0}", account.ID);

            if (String.IsNullOrWhiteSpace(thumbprint))
            {
                _log.Error("[UserAccountService.AddCertificate] failed -- null thumbprint");
                throw new ArgumentNullException("thumbprint");
            }
            if (String.IsNullOrWhiteSpace(subject))
            {
                _log.Error("[UserAccountService.AddCertificate] failed -- null subject");
                throw new ArgumentNullException("subject");
            }

            var cert = new UserCertificate();
            cert.Thumbprint = thumbprint;
            cert.Subject = subject;
            account.AddCertificate(cert);

            this.AddEvent(new CertificateAddedEvent<TAccount> { Account = account, Certificate = cert });
        }

        public virtual void RemoveCertificate(Guid accountID, X509Certificate2 certificate)
        {
            _log.Info("[UserAccountService.RemoveCertificate] called for account ID: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            RemoveCertificate(account, certificate);
            Update(account);
        }
        protected virtual void RemoveCertificate(TAccount account, X509Certificate2 certificate)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.RemoveCertificate] called for accountID: {0}", account.ID);

            if (certificate == null)
            {
                _log.Error("[UserAccountService.RemoveCertificate] failed -- null certificate");
                throw new ArgumentNullException("certificate");
            }
            if (certificate.Handle == IntPtr.Zero)
            {
                _log.Error("[UserAccountService.RemoveCertificate] failed -- invalid certificate handle");
                throw new ArgumentException("Invalid certificate");
            }

            RemoveCertificate(account, certificate.Thumbprint);
        }

        public virtual void RemoveCertificate(Guid accountID, string thumbprint)
        {
            _log.Info("[UserAccountService.RemoveCertificate] called for account ID: {0}", accountID);

            var account = this.GetByID(accountID);
            if (account == null) throw new ArgumentException("Invalid AccountID");

            RemoveCertificate(account, thumbprint);
            Update(account);
        }
        protected virtual void RemoveCertificate(TAccount account, string thumbprint)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.RemoveCertificate] called for accountID: {0}", account.ID);

            if (String.IsNullOrWhiteSpace(thumbprint))
            {
                _log.Error("[UserAccountService.RemoveCertificate] failed -- no thumbprint");
                throw new ArgumentNullException("thumbprint");
            }

            var certs = account.Certificates.Where(x => x.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase)).ToArray();
            foreach (var cert in certs)
            {
                this.AddEvent(new CertificateRemovedEvent<TAccount> { Account = account, Certificate = cert });
                account.RemoveCertificate(cert);
            }
            _log.Error("[UserAccountService.RemoveCertificate] certs removed: {0}", certs.Length);

            if (!account.Certificates.Any() &&
                account.AccountTwoFactorAuthMode == TwoFactorAuthMode.Certificate)
            {
                _log.Trace("[UserAccountService.RemoveCertificate] last cert removed, disabling two factor auth");
                ConfigureTwoFactorAuthentication(account, TwoFactorAuthMode.None);
            }
        }

        protected virtual void CreateTwoFactorAuthToken(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.CreateTwoFactorAuthToken] called for accountID: {0}", account.ID);

            if (account.AccountTwoFactorAuthMode != TwoFactorAuthMode.Mobile)
            {
                _log.Error("[UserAccountService.CreateTwoFactorAuthToken] AccountTwoFactorAuthMode is not mobile");
                throw new Exception("AccountTwoFactorAuthMode is not Mobile");
            }

            var value = this.Configuration.Crypto.GenerateSalt();

            var cmd = new IssueTwoFactorAuthToken { Account = account, Token = value };
            ExecuteCommand(cmd);
            if (cmd.Success)
            {
                var item = new TwoFactorAuthToken();
                item.Token = this.Configuration.Crypto.Hash(value);
                item.Issued = UtcNow;
                account.AddTwoFactorAuthToken(item);

                this.AddEvent(new TwoFactorAuthenticationTokenCreatedEvent<TAccount> { Account = account, Token = value });

                _log.Info("[UserAccountService.CreateTwoFactorAuthToken] TwoFactorAuthToken issued");
            }
            else
            {
                _log.Info("[UserAccountService.CreateTwoFactorAuthToken] TwoFactorAuthToken not issued");
            }
        }

        protected virtual bool VerifyTwoFactorAuthToken(TAccount account, string token)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.VerifyTwoFactorAuthToken] called for accountID: {0}", account.ID);

            if (account.AccountTwoFactorAuthMode != TwoFactorAuthMode.Mobile)
            {
                _log.Error("[UserAccountService.VerifyTwoFactorAuthToken] AccountTwoFactorAuthMode is not mobile");
                return false;
            }

            if (String.IsNullOrWhiteSpace(token))
            {
                _log.Error("[UserAccountService.VerifyTwoFactorAuthToken] failed -- no token");
                return false;
            }

            //token = this.Configuration.Crypto.Hash(token);

            var expiration = UtcNow.AddDays(-MembershipRebootConstants.UserAccount.TwoFactorAuthTokenDurationDays);
            var removequery =
                from t in account.TwoFactorAuthTokens
                where
                    t.Issued < account.PasswordChanged ||
                    t.Issued < account.MobilePhoneNumberChanged ||
                    t.Issued < expiration
                select t;
            var itemsToRemove = removequery.ToArray();

            _log.Trace("[UserAccountService.VerifyTwoFactorAuthToken] number of stale tokens being removed: {0}", itemsToRemove.Length);

            foreach (var item in itemsToRemove)
            {
                account.RemoveTwoFactorAuthToken(item);
            }

            var matchquery =
                from t in account.TwoFactorAuthTokens.ToArray()
                where Configuration.Crypto.VerifyHash(token, t.Token)
                select t;

            var result = matchquery.Any();

            _log.Trace("[UserAccountService.VerifyTwoFactorAuthToken] result was token verified: {0}", result);

            return result;
        }

        protected virtual void RemoveTwoFactorAuthTokens(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            _log.Info("[UserAccountService.RemoveTwoFactorAuthTokens] called for accountID: {0}", account.ID);

            var tokens = account.TwoFactorAuthTokens.ToArray();
            foreach (var item in tokens)
            {
                account.RemoveTwoFactorAuthToken(item);
            }

            var cmd = new ClearTwoFactorAuthToken { Account = account };
            ExecuteCommand(cmd);

            _log.Trace("[UserAccountService.RemoveTwoFactorAuthTokens] tokens removed: {0}", tokens.Length);
        }

        public virtual IEnumerable<Claim> MapClaims(TAccount account)
        {
            if (account == null) throw new ArgumentNullException("account");

            var cmd = new MapClaimsFromAccount<TAccount> { Account = account };
            ExecuteCommand(cmd);
            return cmd.MappedClaims ?? Enumerable.Empty<Claim>();
        }
        
        internal protected virtual DateTime UtcNow
        {
            get
            {
                return DateTime.UtcNow;
            }
        }

        static readonly string[] UglyBase64 = { "+", "/", "=" };
        protected virtual string StripUglyBase64(string s)
        {
            if (s == null) return s;
            foreach (var ugly in UglyBase64)
            {
                s = s.Replace(ugly, "");
            }
            return s;
        }
    }

    public class UserAccountService : UserAccountService<UserAccount>
    {
        public UserAccountService(IUserAccountRepository userRepository)
            : this(new MembershipRebootConfiguration(), userRepository)
        {
        }

        public UserAccountService(MembershipRebootConfiguration configuration, IUserAccountRepository userRepository)
            : base(configuration, userRepository)
        {
        }
    }
}
