using System;

namespace Certificates
{
    public class CertRequestData
    {
        public string Email { get; set; }

        public string CommonName { get; set; }

        public string DeviceSerialNumber { get; set; }

        public string GivenName { get; set; }

        public string SurName { get; set; }

        public string OrganizationUnit { get; set; }

        public string Organization { get; set; }

        public string StreetAddress { get; set; }

        public string Locality { get; set; }

        public string State { get; set; }

        public string DomainComponent { get; set; }

        public string Country { get; set; }

        public string Password { get; set; }

        public string TIN { get; set; }
    }
}
