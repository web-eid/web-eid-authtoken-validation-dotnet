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

## 2. Add cache support

The validation library needs a cache for storing issued challenge nonces. 
For this purpose the generic `ICache` interface is provided. 
We use [MemoryCache](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.caching.memorycache) as implementation.
Implement the cache as follows:
```cs
using System;
using System.Runtime.Caching;
using WebEid.Security.Cache;

internal sealed class MemoryCache<T> : ICache<T>
{
    private readonly MemoryCache cacheContent = new MemoryCache("test-cache");
    private readonly CacheItemPolicy cacheItemPolicy;

    public MemoryCache() : this(ObjectCache.NoSlidingExpiration) { }

    private MemoryCache(TimeSpan cacheItemExpiration)
    {
        this.cacheItemPolicy = new CacheItemPolicy { SlidingExpiration = cacheItemExpiration };
    }

    public T GetAndRemove(string key)
    {
        return this.cacheContent.Contains(key) ? (T)this.cacheContent.Remove(key) : default;
    }

    public bool Contains(string key)
    {
        return this.cacheContent.Contains(key);
    }

    public void Put(string key, T value) => this.cacheContent.Add(key, value, this.cacheItemPolicy);

    public void Dispose() => this.cacheContent?.Dispose();
}
```
Then create singleton instance of nonce cache:
```cs
using System;
using WebEid.Security.Cache;
...
    public static ICache<DateTime> SingletonNonceCache = new MemoryCache<DateTime>();
...
```

## 3. Configure the nonce generator

The validation library needs to generate authentication challenge nonces and store them in the cache for later validation. Overview of nonce usage is provided in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1). The nonce generator will be used in the REST endpoint that issues challenges; it is thread-safe and should be scoped as a singleton.

Configure the nonce generator as follows:

```cs
using WebEid.Security.Cache;
using WebEid.Security.Nonce;
...
using (var rndGenerator = RNGCryptoServiceProvider.Create())
{
    new NonceGeneratorBuilder()
        .WithNonceCache(SingletonNonceCache)
        .WithSecureRandom(rndGenerator)
        .Build();
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
    private INonceGenerator nonceGenerator;

    public ChallengeController(INonceGenerator nonceGenerator)
    {
        this.nonceGenerator = nonceGenerator;
    }

    [HttpGet]
    [Route("challenge")]
    public ChallengeDto GetChallenge()
    {
        // a simple DTO with a single 'Nonce' field
        return new ChallengeDto { Nonce = nonceGenerator.GenerateAndStoreNonce() };
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

    public AuthController(IAuthTokenValidator authTokenValidator)
    {
        this.authTokenValidator = authTokenValidator;
    }

    [HttpPost]
    [Route("login")]
    public async Task Login([FromBody] AuthenticateRequestDto authToken)
    {
        var certificate = await this.authTokenValidator.Validate(authToken.AuthToken);
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.GivenName, certificate.GetSubjectGivenName()),
            new Claim(ClaimTypes.Surname, certificate.GetSubjectSurname())          };

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
    .WithNonceCache(NonceCache)
    .WithSecureRandom(RandomNumberGenerator)
    .WithTrustedCertificateAuthorities(TrustedCertificateAuthorities)
    .WithSiteCertificateSha256Fingerprint("urn:cert:sha-256:cert-hash-hex")
    .WithoutUserCertificateRevocationCheckWithOcsp()
    .WithAllowedClientClockSkew(TimeSpan.FromMinutes(3))
    .WithDisallowedCertificatePolicies("1.2.3")
    .WithNonceDisabledOcspUrls(new Uri("http://aia.example.org/cert"))
    .Build();
```

### Certificates' *Authority Information Access* (AIA) extension

It is assumed that the AIA extension that contains the certificates’ OCSP service location, is part of both the user and CA certificates. The AIA OCSP URL will be used to check the certificate revocation status with OCSP.

**Note that there may be legal limitations to using AIA URLs during signing** as the services behind these URLs provide different security and SLA guarantees than dedicated OCSP services. For digital signing, OCSP responder certificate validation is additionally needed. Using AIA URLs during authentication is sufficient, however.

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

# Nonce generation
The authentication protocol requires support for generating challenge nonces,  large random numbers that can be used only once, and storing them for later use during token validation. The validation library uses the *System.Security.Cryptography.RandomNumberGenerator* API as the secure random source and provides *WebEid.Security.Cache.ICache* interface for storing issued challenge nonces. 

The authentication protocol requires a REST endpoint that issues challenge nonces as described in section *[6. Add a REST endpoint for issuing challenge nonces](#6-add-a-rest-endpoint-for-issuing-challenge-nonces)*.

Nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

## Basic usage  

As described in section *[3. Configure the nonce generator](#3-configure-the-nonce-generator)*, there are two mandatory configuration parameters of the nonce generator, they are the nonce cache and the *System.Security.Cryptography.RandomNumberGenerator.RandomNumberGenerator*.

The nonce cache instance is used to store the nonce expiry time using the nonce value as key. The values in the cache are used by the token validator as described in the section [Authentication token validation > Basic usage](#basic-usage) that also contains recommendations for cache usage and configuration.

The nonce generator configuration and construction is described in more detail in section *[3. Configure the nonce generator](#3-configure-the-nonce-generator)*. Once the generator object has been constructed, it can be used for generating nonces as follows:

```cs
string nonce = nonceGenerator.GenerateAndStoreNonce();  
```

The `GenerateAndStoreNonce()` method both generates the nonce and stores it in the cache.

## Extended configuration  
The following additional configuration options are available in `NonceGeneratorBuilder`:

- `WithNonceTtl(TimeSpan duration)` – overrides the default nonce time-to-live duration. When the time-to-live passes, the nonce is considered to be expired. Default nonce time-to-live is 5 minutes.
- `WithSecureRandom(RandomNumberGenerator)` - allows to specify a custom `RandomNumberGenerator` instance.

Extended configuration example:  
```cs  
NonceGenerator generator = new NonceGeneratorBuilder()  
    .WithNonceCache(cache)
    .WithNonceTtl(TimeSpan.FromMinutes(5))
    .WithSecureRandom(customRandomNumberGenerator)  
    .Build();
```
