
# web-eid-authtoken-validation-dotnet

![European Regional Development Fund](https://raw.githubusercontent.com/open-eid/DigiDoc4-Client/master/client/images/EL_Regionaalarengu_Fond.png)

*web-eid-authtoken-validation-dotnet* is a .NET library for issuing challenge nonces and validating Web eID JWT authentication tokens during secure authentication with electronic ID (eID) smart cards in web applications.

More information about the Web eID project is available on the project [website](https://web-eid.eu/).

# Quickstart

Complete the steps below to add support for secure authentication with eID cards to your ASP.NET Core web application back end. Instructions for the front end are available [here](https://github.com/web-eid/web-eid.js).

See full example [here](https://github.com/web-eid/web-eid-asp-dotnet-example).

## 1. Add the library to your project
To install the package, you can use the Package Manager Console. 
1.  Select the  **Tools**  >  **NuGet Package Manager**  >  **Package Manager Console**  menu command.
2.  Once the console opens, check that the  **Default project**  drop-down list shows the project into which you want to install the package. If you have a single project in the solution, it is already selected.
3. Enter the command `Install-Package WebEid.Security`. The console window shows output for the command.

When you install a package, NuGet records the dependency in either your project file or a `packages.config` file (depending on the project format).

## 2. Configure the challenge nonce store

The validation library needs a store for saving the issued challenge nonces. As it must be guaranteed that the authentication token is received from the same browser to which the corresponding challenge nonce was issued, using a session-backed challenge nonce store is the most natural choice.

Implement the session-backed challenge nonce store as follows:
```cs
using System;
using System.Runtime.Caching;
using WebEid.Security.Cache;

public class SessionBackedChallengeNonceStore : IChallengeNonceStore
{
    [ThreadStatic]
    private static HttpContext httpContext;

    private const string ChallengeNonceKey = "challenge-nonce";

    public static void SetContext(HttpContext context)
    {
        httpContext = context;
    }

    public void Put(ChallengeNonce challengeNonce)
    {
        httpContext.Session.SetString(ChallengeNonceKey, challengeNonce.Base64EncodedNonce);
    }

    public ChallengeNonce GetAndRemoveImpl()
    {
        var base64EncodedNonce = httpContext.Session.GetString(ChallengeNonceKey);
        if (!string.IsNullOrWhiteSpace(base64EncodedNonce))
        {
            httpContext.Session.Remove(ChallengeNonceKey);
            return new ChallengeNonce(base64EncodedNonce, DateTime.Now.AddMinutes(3));
        }
        return null;
    }
}
```
To access session data we need to initialize session static httpContext in controller method of ASP.NET application:
```cs
SessionBackedChallengeNonceStore.SetContext(HttpContext);
```

## 3. Configure the nonce generator

The validation library needs to generate authentication challenge nonces and store them for later validation in the challenge nonce store. Overview of challenge nonce usage is provided in the  [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1). The challenge nonce generator will be used in the REST endpoint that issues challenges; it is thread-safe and should be scoped as a singleton.

Configure the challenge nonce generator in ASP.NET Startup class as follows:

```cs
public void ConfigureServices(IServiceCollection services)
{
...
    services.AddSingleton(RNGCryptoServiceProvider.Create());
    services.AddSingleton<IChallengeNonceStore, SessionBackedChallengeNonceStore>();
    services.AddSingleton<IChallengeNonceGenerator, ChallengeNonceGenerator>();
...
}
```

## 4. Add trusted certificate authority certificates

You must explicitly specify which **intermediate** certificate authorities (CAs) are trusted to issue the eID authentication certificates. CA certificates can be loaded from either the resources or any stream source. 
First implement `CertificateLoader` class:
```cs
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

internal static class CertificateLoader
{
    public static X509Certificate[] LoadTrustedCaCertificatesFromStore()
    {
        var certPath = "Certificates";
        return new FileReader(certPath, "*.cer").ReadFiles()
            .Select(file => new X509Certificate(file))
            .ToArray();
    }
}

internal class FileReader
{
    private readonly string path;
    private readonly string searchPattern;

    public FileReader(string path, string searchPattern = null)
    {
        this.path = path;
        this.searchPattern = searchPattern;
    }

    public IEnumerable<byte[]> ReadFiles()
    {
        foreach (var file in Directory.EnumerateFiles(this.path, this.searchPattern))
        {
            yield return File.ReadAllBytes(file);
        }
    }
}
```
Then copy the trusted certificates, for example `ESTEID-SK_2015.cer` and `ESTEID2018.cer`, to `Certificates` and load the certificates as follows:

```cs
...
private X509Certificate[] TrustedCertificateAuthorities() 
{
    CertificateLoader.LoadTrustedCaCertificatesFromStore();
}
...
```

## 5. Configure the authentication token validator

Once the prerequisites have been met, the authentication token validator itself can be configured.
The mandatory parameters are the website origin (the URL serving the web application), nonce cache and trusted certificate authorities.
The authentication token validator will be used in the login processing component of your web application authentication framework; it is thread-safe and should be scoped as a singleton.

```cs
using Security.Validator;
...
public AuthTokenValidator TokenValidator()
{
return new AuthTokenValidatorBuilder()
    .WithSiteOrigin("https://example.org")
    .WithNonceCache(SingletonNonceCache)
    .WithTrustedCertificateAuthorities(TrustedCertificateAuthorities())
    .Build();
}
...
```

## 6. Add a REST endpoint for issuing challenge nonces

A REST endpoint that issues challenge nonces is required for authentication. The endpoint must support `GET` requests.

In the following example, we are using the [ASP.NET Web APIs RESTful Web Services framework](https://dotnet.microsoft.com/apps/aspnet/apis) to implement the endpoint, see also full implementation [here](https://github.com/web-eid/web-eid-asp-dotnet-example/blob/main/src/WebEid.AspNetCore.Example/Controllers/Api/AuthController.cs).

```cs
using Microsoft.AspNetCore.Mvc;
using WebEid.Security.Nonce;

[ApiController]
[Route("auth")]
public class ChallengeController : ControllerBase
{
    private readonly IChallengeNonceGenerator challengeNonceGenerator;

    public ChallengeController(IChallengeNonceGenerator challengeNonceGenerator)
    {
        this.challengeNonceGenerator = challengeNonceGenerator;
    }

    [HttpGet]
    [Route("challenge")]
    public ChallengeDto GetChallenge()
    {
        SessionBackedChallengeNonceStore.SetContext(HttpContext);
        var challenge = new ChallengeDto
        {
            Nonce = challengeNonceGenerator.GenerateAndStoreNonce(TimeSpan.FromMinutes(5)).Base64EncodedNonce
        };
        return challenge;
    }
}
```

Also, see general guidelines for implementing secure authentication services [here](https://github.com/SK-EID/smart-id-documentation/wiki/Secure-Implementation-Guide).

## 7. Implement authentication

Authentication consists of calling the `Validate()` method of the authentication token validator. The internal implementation of the validation process is described in more detail below and in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

When using standard [ASP.NET cookie authentication](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/cookie) 
- then create the Authentication Middleware services with [AddAuthentication](https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.authenticationservicecollectionextensions.addauthentication) and [AddCookie](https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.cookieextensions.addcookie) methods in the Startup.ConfigureServices method:
```cs
services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
```
- In `Startup.Configure`, call `UseAuthentication` and `UseAuthorization` to set the `HttpContext.User` property and run Authorization Middleware for requests. Call the `UseAuthentication` and `UseAuthorization` methods before calling `UseEndpoints`:
```cs
app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
    endpoints.MapRazorPages();
});
```

- Create REST endpoint that deals with authentication and creates an authentication cookie:
```cs
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using WebEid.Security.Util;
using WebEid.Security.Validator;

[Route("[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IAuthTokenValidator authTokenValidator;

    public AuthController(IAuthTokenValidator authTokenValidator, IChallengeNonceStore challengeNonceStore)
    {
        this.authTokenValidator = authTokenValidator;
        this.challengeNonceStore = challengeNonceStore;
    }

    [HttpPost]
	[ValidateAntiForgeryToken]
    [Route("login")]
    public async Task Login([FromBody] AuthenticateRequestDto authToken)
    {
        var certificate = await this.authTokenValidator.Validate(authToken.AuthToken, this.challengeNonceStore.GetAndRemove().Base64EncodedNonce);
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.GivenName, certificate.GetSubjectGivenName()),
            new Claim(ClaimTypes.Surname, certificate.GetSubjectSurname()),
            new Claim(ClaimTypes.NameIdentifier, certificate.GetSubjectIdCode())
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        var authProperties = new AuthenticationProperties
        {
            AllowRefresh = true
        };

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);
    }

    [HttpGet]
    [ValidateAntiForgeryToken]
    [Route("logout")]
    public async Task Logout()
    {
        await HttpContext.SignOutAsync(
            CookieAuthenticationDefaults.AuthenticationScheme);
    }
}
```

# Table of contents

- [Quickstart](#quickstart)
  - [1. Add the library to your project](#1-add-the-library-to-your-project)
  - [2. Add cache support](#2-add-cache-support)
  - [3. Configure the nonce generator](#3-configure-the-nonce-generator)
  - [4. Add trusted certificate authority certificates](#4-add-trusted-certificate-authority-certificates)
  - [5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)
  - [6. Add a REST endpoint for issuing challenge nonces](#6-add-a-rest-endpoint-for-issuing-challenge-nonces)
  - [7. Implement authentication](#7-implement-authentication)
- [Introduction](#introduction)
- [Authentication token validation](#authentication-token-validation)
  - [Basic usage](#basic-usage)
  - [Extended configuration](#extended-configuration)
    - [Certificates' *Authority Information Access* (AIA) extension](#certificates-authority-information-access-aia-extension)
  - [Possible validation errors](#possible-validation-errors)
- [Nonce generation](#nonce-generation)
  - [Basic usage](#basic-usage-1)
  - [Extended configuration](#extended-configuration-1)

# Introduction

The Web eID authentication token validation library for .NET contains the  implementation of the Web eID authentication token validation process in its entirety to ensure that the authentication token sent by the Web eID browser extension contains valid, consistent data that has not been modified by a third party. It also implements secure challenge nonce generation as required by the Web eID authentication protocol. It is easy to configure and integrate into your authentication service.

The authentication protocol, validation requirements and nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

# Authentication token validation

The authentication token validation process consists of three stages:

- First, the validator parses the **token header** and extracts the user certificate from the *x5c* field. Then it checks the certificate expiration, purpose and policies. Next it checks that the certificate is signed by a trusted CA and checks the certificate status with OCSP.
- Second, the validator validates the **token signature** and parses the **token body**. The signature validator validates that the signature was created using the user certificate that was provided in the header.
- Last, the validator checks the **claims from the token body**. It checks that the token hasn't expired, that the *nonce* field contains a valid challenge nonce that exists in the cache and hasn't expired, and that the *aud* field contains the site origin URL. Optionally, if configured, it also verifies the site TLS certificate fingerprint included in the *aud* field (see *[Extended configuration](#extended-configuration)* below).

The authentication token can be used only once as the corresponding nonce will be removed from the cache during nonce validation. The nonce will also be automatically evicted from the cache when its cache time-to-live expires.

## Basic usage

As described in section *[5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)*, the mandatory configuration parameters are the website origin, nonce cache and trusted certificate authorities.

**Origin** should be the URL serving the web application. Origin URL must be in the form of `"https://" <hostname> [ ":" <port> ]`  as defined in [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Location/origin) and not contain path or query components.

The **nonce cache** instance is used to look up nonce expiry time using its unique value as key. The values in the cache are populated by the nonce generator as described in section *[Nonce generation](#nonce-generation)* below. Consider using [MemoryCache](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.caching.memorycache) or similar as the caching provider if your application does not run in a cluster, [Memcached](https://memcached.org/) or [Redis](https://redis.io/) if it does. Cache configuration is described in more detail in section *[2. Add cache support](#2-add-cache-support)*.

The **trusted certificate authority certificates** are used to validate that the user certificate from the authentication token is signed by a trusted certificate authority. Intermediate CA certificates must be used instead of the root CA certificates so that revoked CA certificates can be detected. Trusted certificate authority certificates configuration is described in more detail in section *[4. Add trusted certificate authority certificates](#4-add-trusted-certificate-authority-certificates)*.

The authentication token validator configuration and construction is described in more detail in section *[5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)*. Once the validator object has been constructed, it can be used for validating authentication tokens as follows:

```cs
X509Certificate userCertificate = tokenValidator.Validate(tokenString);  
```

The `Validate()` method returns the validated user certificate object if validation is successful or throws an exception as described in section *[Possible validation errors](#possible-validation-errors)* below if validation fails. The `X509CertificateExtensions` class contains extension methods for extracting user information from the user certificate object:

```cs
using WebEid.Security.Util;
...   
userCertificate.GetSubjectCn(); // "JÕEORG\\,JAAK-KRISTJAN\\,38001085718"
userCertificate.GetSubjectIdCode(); // "PNOEE-38001085718"
userCertificate.GetSubjectCountryCode(); // "EE"
```

## Extended configuration  

The following additional configuration options are available in `AuthTokenValidatorBuilder`:

- `WithSiteCertificateSha256Fingerprint(string siteCertificateFingerprint)` – turns on origin website certificate fingerprint validation. The validator checks that the site certificate fingerprint from the authentication token matches with the provided site certificate SHA-256 fingerprint. This disables powerful man-in-the-middle attacks where attackers are able to issue falsified certificates for the origin, but also disables TLS proxy usage. Due to the technical limitations of web browsers, certificate fingerprint validation currently works only with Firefox. The provided certificate SHA-256 fingerprint should have the prefix `urn:cert:sha-256:` followed by the hexadecimal encoding of the hash value octets as specified in [URN Namespace for Certificates](https://tools.ietf.org/id/draft-seantek-certspec-01.html). Certificate fingerprint validation is disabled by default.
- `WithoutUserCertificateRevocationCheckWithOcsp()` – turns off user certificate revocation check with OCSP. The OCSP URL is extracted from the user certificate AIA extension. OCSP check is enabled by default.
- `WithOcspRequestTimeout(Duration ocspRequestTimeout)` – sets both the connection and response timeout of user certificate revocation check OCSP requests. Default is 5 seconds.
- `WithAllowedClientClockSkew(Duration allowedClockSkew)` – sets the tolerated clock skew of the client computer when verifying the token expiration. Default value is 3 minutes.
- `withDisallowedCertificatePolicies(ASN1ObjectIdentifier... policies)` – adds the given policies to the list of disallowed user certificate policies. In order for the user certificate to be considered valid, it must not contain any policies present in this list. Contains the Estonian Mobile-ID policies by default as it must not be possible to authenticate with a Mobile-ID certificate when an eID smart card is expected.
- `withNonceDisabledOcspUrls(URI... urls)` – adds the given URLs to the list of OCSP URLs for which the nonce protocol extension will be disabled. Some OCSP services don't support the nonce extension. Contains the ESTEID-2015 OCSP URL by default.

Extended configuration example:  

```cs  
AuthTokenValidator validator = new AuthTokenValidatorBuilder(logger)
    .WithSiteOrigin("https://example.org")
    .WithTrustedCertificateAuthorities(TrustedCertificateAuthorities)
    .WithoutUserCertificateRevocationCheckWithOcsp()
    .WithAllowedClientClockSkew(TimeSpan.FromMinutes(3))
    .WithDisallowedCertificatePolicies("1.2.3")
    .WithNonceDisabledOcspUrls(new Uri("http://aia.example.org/cert"))
    .Build();
```

### Certificates' *Authority Information Access* (AIA) extension

Unless a designated OCSP responder service is in use, it is required that the AIA extension that contains the certificate’s OCSP responder access location is present in the user certificate. The AIA OCSP URL will be used to check the certificate revocation status with OCSP.

Note that there may be limitations to using AIA URLs as the services behind these URLs provide different security and SLA guarantees than dedicated OCSP responder services. In case you need a SLA guarantee, use a designated OCSP responder service.

## Logging

Authentication token validation internal logging is using  [Microsoft.Extensions.Logging](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/logging). You should provide `ILogger` instance to constructor of `AuthTokenValidatorBuilder`.

```cs
var loggerFactory = LoggerFactory.Create(builder =>
{
    builder.AddConsole();
});
var logger = loggerFactory.CreateLogger("Logger name");
AuthTokenValidator validator = new AuthTokenValidatorBuilder(logger)
    ...	  
    .Build();
```

## Possible validation errors  

The `Validate()` method of `AuthTokenValidator` returns the validated user certificate object if validation is successful or throws an exception if validation fails. All exceptions that can occur during validation derive from `TokenValidationException`, the list of available exceptions is available [here](src/WebEid.Security/Exceptions). Each exception file contains a documentation comment under which conditions the exception is thrown.

## Stateful and stateless authentication

In the code examples above we use the classical stateful ASP.NET session cookie-based authentication mechanism, where a cookie that contains the user session ID is set during successful login and session data is stored at sever side. Cookie-based authentication must be protected against cross-site request forgery (CSRF) attacks and extra measures must be taken to secure the cookies by serving them only over HTTPS and setting the  _HttpOnly_,  _Secure_  and  _SameSite_  attributes.

A common alternative to stateful authentication is stateless authentication with JSON Web Tokens (JWT) or secure cookie sessions where the session data resides at the client side browser and is either signed or encrypted. Secure cookie sessions are described in  [RFC 6896](https://datatracker.ietf.org/doc/html/rfc6896)  and in the following  [article about secure cookie-based Spring Security sessions](https://www.innoq.com/en/blog/cookie-based-spring-security-session/). Usage of both an anonymous session and a cache is required to store the challenge nonce and the time it was issued before the user is authenticated. The anonymous session must be used for protection against  [forged login attacks](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Forging_login_requests)  by guaranteeing that the authentication token is received from the same browser to which the corresponding challenge nonce was issued. The cache must be used for protection against replay attacks by guaranteeing that each authentication token can be used exactly once.

# Challenge Nonce generation
The authentication protocol requires support for generating challenge nonces,  large random numbers that can be used only once, and storing them for later use during token validation. The validation library uses the *System.Security.Cryptography.RandomNumberGenerator* API as the secure random source and provides *WebEid.Security.Cache.ICache* interface for storing issued challenge nonces. 

The authentication protocol requires a REST endpoint that issues challenge nonces as described in section *[6. Add a REST endpoint for issuing challenge nonces](#6-add-a-rest-endpoint-for-issuing-challenge-nonces)*.

Nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

## Basic usage  

As described in section *[3. Configure the nonce generator](#3-configure-the-nonce-generator)*, there are two mandatory configuration parameters of the nonce generator, they are the nonce cache and the *System.Security.Cryptography.RandomNumberGenerator.RandomNumberGenerator*.

The nonce cache instance is used to store the nonce expiry time using the nonce value as key. The values in the cache are used by the token validator as described in the section [Authentication token validation > Basic usage](#basic-usage) that also contains recommendations for cache usage and configuration.

The nonce generator configuration and construction is described in more detail in section *[3. Configure the nonce generator](#3-configure-the-nonce-generator)*. Once the generator object has been constructed, it can be used for generating nonces as follows:

```cs
string nonce = nonceGenerator.GenerateAndStoreNonce(TimeSpan ttl);  
```

The `GenerateAndStoreNonce(TimeSpan ttl)` method both generates the nonce and stores it in the cache. Ttl parameter defines challenge nonce time-to-live duration. When the time-to-live passes, the nonce is considered to be expired.
