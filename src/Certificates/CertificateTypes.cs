using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Datati.Libraries.Certificates
{
    /// <summary>
    /// Types of certificates used in system
    /// </summary>
    public enum CertificateTypes
    {
        Unknown = 00,
        /// <summary>
        /// web/ssl certificate class 1
        /// </summary>
        CertificateClassV31 = 31,

        /// <summary>
        /// HTTPS auth certificate class 1 used for (V-SDC HTTPS comunnication and POS HTTPS communication)
        /// </summary>
        CertificateClassV32 = 32,

        /// <summary>
        /// Sign data certificate class 2 used for signing data on Secure Element applet
        /// </summary>
        CertificateClassV33 = 33,

        /// <summary>
        /// HTTPS auth certificate class 2 used for PKI Applet on Smart Card
        /// </summary>
        CertificateClassV34 = 34,

        /// <summary>
        /// Sign data certificate class 1, V-SDC certificate with additional options example authorized/unauthorized
        /// </summary>
        CertificateClassV35 = 35,

        /// <summary>
        /// Encrypt data class 1 (used on SE applet for encrypting POA data(TaxCore public Key) and on VSDC for InternalData encrypt/decrypt)
        /// </summary>
        CertificateClassV36 = 36,

        /// <summary>
        /// HTTPS auth certificate class 2 used for Developer
        /// </summary>
        CertificateClassV37 = 37,

        /// <summary>
        /// Sign data certificate class 2 used for signing data on virtual Developer Secure Element
        /// </summary>
        CertificateClassV38 = 38
    }
}
