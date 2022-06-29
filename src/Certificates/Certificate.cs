using Certificates.Extensions;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Certificates
{
    public class Certificate : X509Certificate2, ISerializable, IDisposable
    {
        protected CertRequestData _certRequestData = null;
        protected string _uniqueIdentifier;
        private CertificateTypes _certificateType;

        #region Constructors

        public Certificate() : base()
        {
        }

        public Certificate(string fileName, string password, X509KeyStorageFlags keyStorageFlags) :
            base(fileName, password, keyStorageFlags)
        {
        }

        public Certificate(X509Certificate2 certificate) :
            this(certificate.RawData)
        {
            this.PrivateKey = certificate.PrivateKey;
        }

        public Certificate(byte[] pfx, string password) :
            base(pfx, password)
        {
        }

        public Certificate(string pfxBase64, string password) :
            base(Convert.FromBase64String(pfxBase64), password)
        {
        }

        public Certificate(byte[] rawCert) :
            base(rawCert)
        {
        }

        protected Certificate(SerializationInfo info, StreamingContext context) : base(info, context)
        {
            var dict = info.ToDictionary();
            if (dict.ContainsKey(nameof(CertificateId)))
                CertificateId = info.GetInt32(nameof(CertificateId));
            if (dict.ContainsKey(nameof(RevokeReasonDescription)))
                RevokeReasonDescription = info.GetString(nameof(RevokeReasonDescription));
            CertificateRevokeReason = null;
            DateRevoked = null;
            if (dict.ContainsKey(nameof(CertificateRevokeReason)))
            {
                string reason = info.GetString(nameof(CertificateRevokeReason));
                if (reason != null)
                    CertificateRevokeReason = (CertificateRevokeReason)Int32.Parse(reason);
            }
            if (dict.ContainsKey(nameof(DateRevoked)))
            {
                string date = info.GetString(nameof(DateRevoked));
                if (date != null)
                    DateRevoked = DateTime.Parse(info.GetString(nameof(DateRevoked)));
            }
        }

        #endregion Constructors

        #region Properties

        public int CertificateId { get; set; }

        public virtual string UniqueIdentifier
        {
            get
            {
                if (_uniqueIdentifier != null)
                    return _uniqueIdentifier;
                return GetCertRequestData().DeviceSerialNumber;
            }
        }

        public string CommonName
        {
            get
            {
                return GetCertRequestData().CommonName;
            }
        }

        [Obsolete]
        public string CommonNameOTP
        {
            get
            {
                if (!String.IsNullOrEmpty(UniqueIdentifier))
                    return UniqueIdentifier;

                try
                {
                    return CommonName.Substring(GetCertRequestData().CommonName.IndexOf('(') + 1, 6) + "o0"; //suffix for TaxCore applications
                }
                catch (Exception)
                {
                    return null;
                }
            }
        }

        public virtual string RequestedBy
        {
            get
            {
                return GetCertRequestData().Email;
            }
        }

        public virtual string Organization
        {
            get
            {
                return GetCertRequestData().Organization;
            }
        }

        public virtual bool IsAuthorizedPerson
        {
            get
            {
                return (!String.IsNullOrWhiteSpace(this.GivenName) && !String.IsNullOrWhiteSpace(this.SurName));
            }
        }

        private DateTime? _expiryDate;

        public virtual DateTime ExpiryDate
        {
            get
            {
                if (_expiryDate == null) return NotAfter;
                else return (DateTime)_expiryDate;
            }
            set
            {
                _expiryDate = value;
            }
        }

        public string RevokeReasonDescription { get; set; }

        public DateTime? DateRevoked { get; set; } = null;

        public CertificateRevokeReason? CertificateRevokeReason { get; set; } = null;

        public CertificateTypes CertificateType
        {
            get
            {
                if (_certificateType != CertificateTypes.Unknown)
                    return _certificateType;

                return ExtractCertificateType();
            }
            set
            {
                _certificateType = value;
            }
        }

        public int? CardId { get; set; }

        public string GivenName
        {
            get
            {
                return GetCertRequestData().GivenName;
            }
        }

        public string SurName
        {
            get
            {
                return GetCertRequestData().SurName;
            }
        }

        public string OrganizationUnit
        {
            get
            {
                return GetCertRequestData().OrganizationUnit;
            }
        }

        public string StreetAddress
        {
            get
            {
                return GetCertRequestData().StreetAddress;
            }
        }

        public string State
        {
            get
            {
                return GetCertRequestData().State;
            }
        }

        public bool IsEncryption => CertificateType == CertificateTypes.CertificateClassV36;

        public bool IsSigning => CertificateType == CertificateTypes.CertificateClassV33 || CertificateType == CertificateTypes.CertificateClassV35 || CertificateType == CertificateTypes.CertificateClassV38;

        public bool IsAuthentication => CertificateType == CertificateTypes.CertificateClassV32 || CertificateType == CertificateTypes.CertificateClassV34 || CertificateType == CertificateTypes.CertificateClassV37;

        public virtual RSA GetPrivateKeyRSA() => this.GetRSAPrivateKey();
        public virtual RSA GetPublicKeyRSA() => this.GetRSAPublicKey();

        #endregion Properties

        #region Public methods

        public string ExtractTIN()
        {
            foreach (X509Extension ext in Extensions)
            {
                if (ext.Oid.Value.StartsWith("1.3.6.1.4.1.49952.") && ext.Oid.Value.Split('.')[9] == "6")
                {
                    return Encoding.Default.GetString(ext.RawData);
                }
            }
            return string.Empty;
        }

        public string ExtractTaxCoreApiUrl()
        {
            foreach (X509Extension ext in Extensions)
            {
                if (ext.Oid.Value.StartsWith("1.3.6.1.4.1.49952.") && ext.Oid.Value.Split('.')[9] == "5")
                {
                    return Encoding.Default.GetString(ext.RawData);
                }
            }
            return string.Empty;
        }

        public void Dispose()
        {
            this.Reset();
        }

        public virtual void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            try
            {
                info.AddValue(nameof(RawData), RawData);
            }
            catch (Exception)
            {
                info.AddValue(nameof(RawData), null);
            }
            info.AddValue(nameof(CertificateId), CertificateId);
            info.AddValue(nameof(RevokeReasonDescription), RevokeReasonDescription);
            info.AddValue(nameof(DateRevoked), DateRevoked);
            info.AddValue(nameof(CertificateRevokeReason), CertificateRevokeReason);
        }

        #endregion Public methods

        #region Private methods

        private CertificateTypes ExtractCertificateType()
        {
            if (this.Handle == IntPtr.Zero)
                return CertificateTypes.Unknown;

            try
            {
                foreach (X509Extension ext in Extensions)
                {
                    if (IsEnhancedKeyUsage(ext))
                    {
                        foreach (var item in (ext as X509EnhancedKeyUsageExtension).EnhancedKeyUsages)
                        {
                            if (item.Value.StartsWith("1.3.6.1.4.1.49952."))
                            {
                                var segments = item.Value.Split('.');
                                return (CertificateTypes)Enum.Parse(typeof(CertificateTypes), segments[9] + segments[10]);
                            }
                        }
                    }
                }
            }
            catch (CryptographicException)
            {
                return CertificateTypes.Unknown;
            }

            return CertificateTypes.Unknown;
        }

        private bool IsEnhancedKeyUsage(X509Extension ext)
        {
            return (ext.Oid.FriendlyName == "Enhanced Key Usage");
        }

        private CertRequestData GetCertRequestData()
        {
            if (_certRequestData == null)
                _certRequestData = ExtractCertRequestData();
            return _certRequestData;
        }

        private CertRequestData ExtractCertRequestData()
        {
            if (Handle == IntPtr.Zero)
                return null;

            var commonName = string.Empty;
            var organizationUnit = string.Empty;
            var organization = string.Empty;
            var locality = string.Empty;
            var state = string.Empty;
            var country = string.Empty;
            var serialnumber = string.Empty;
            var domainComponent = string.Empty;
            var email = string.Empty;
            var givenName = string.Empty;
            var streetAddress = string.Empty;
            var surName = string.Empty;

            foreach (string item in Subject.Split(','))
            {
                if (item.Trim().Split('=')[0] == "CN")
                    commonName = item.Split('=')[1];

                if (item.Trim().Split('=')[0] == "OU")
                    organizationUnit = item.Split('=')[1];

                if (item.Trim().Split('=')[0] == "O")
                    organization = item.Split('=')[1];

                if (item.Trim().Split('=')[0] == "L")
                    locality = item.Split('=')[1];

                if (item.Trim().Split('=')[0] == "S")
                    state = item.Split('=')[1];

                if (item.Trim().Split('=')[0] == "C")
                    country = item.Split('=')[1];

                if (item.Trim().Split('=')[0] == "SERIALNUMBER")
                    serialnumber = item.Split('=')[1];

                if (item.Trim().Split('=')[0] == "DC")
                    domainComponent = item.Split('=')[1];

                if (item.Trim().Split('=')[0] == "E")
                    email = item.Split('=')[1];

                if (item.Trim().Split('=')[0] == "G")
                    givenName = item.Split('=')[1];

                if (item.Trim().Split('=')[0] == "STREET")
                    streetAddress = item.Split('=')[1];

                if (item.Trim().Split('=')[0] == "SN")
                    surName = item.Split('=')[1];
            }
            return new CertRequestData
            {
                CommonName = commonName,
                OrganizationUnit = organizationUnit,
                Organization = organization,
                Locality = locality,
                State = state,
                Country = country,
                DeviceSerialNumber = serialnumber,
                DomainComponent = domainComponent,
                Email = email,
                GivenName = givenName,
                StreetAddress = streetAddress,
                SurName = surName
            };
        }

        #endregion Private methods
    }
}