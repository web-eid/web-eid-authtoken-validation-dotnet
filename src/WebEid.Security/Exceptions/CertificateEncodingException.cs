namespace WebEid.Security.Exceptions
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// 
    /// </summary>
    [Serializable]
    public class CertificateEncodingException : AuthTokenException
    {
        /// <summary>
        /// Object identifier that was not found
        /// </summary>
        public string OID { get; }

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <remarks>
        /// Constructs the instance of the class and sets the message of the exception to
        /// "X500 name RDNs empty or first element is null".
        /// </remarks>
        public CertificateEncodingException() : base("X500 name RDNs empty or first element is null")
        {
            OID = String.Empty;
        }

        /// <summary>
        /// Constructs the instance from given Object Identifier that was not found.
        /// </summary>
        /// <param name="oid">The Object Identifier that was not found.</param>
        public CertificateEncodingException(string oid) : base($"Object Identifier {oid} was not found")
        {
            OID = oid;
        }


        /// <summary>
        /// Constructs the instance from given Object Identifier, message and existing <see cref="Exception"/> object.
        /// </summary>
        /// <param name="oid">The Object Identifier that was not found.</param>
        /// <param name="msg">Message of the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public CertificateEncodingException(string oid, string msg, Exception innerException) : base(msg, innerException)
        {
            OID = oid;
        }

        /// <summary>
        /// Constructs the instance with serialized data.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> that holds the serialized object data about the exception being thrown.</param>
        /// <param name="context">The <see cref="StreamingContext"/> that contains contextual information about the source or destination.</param>
        protected CertificateEncodingException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
