# web-eid-authtoken-validation-dotnet

![European Regional Development Fund](https://raw.githubusercontent.com/open-eid/DigiDoc4-Client/master/client/images/EL_Regionaalarengu_Fond.png)

*web-eid-authtoken-validation-dotnet* is a .NET library for issuing challenge nonces and validating Web eID JWT authentication tokens during secure authentication with electronic ID (eID) smart cards in web applications.

More information about the Web eID project is available on the project [website](https://web-eid.eu/).

# Quickstart

Complete the steps below to add support for secure authentication with eID cards to your ASP.NET Core web application backend. Instructions for the frontend are available [here](https://github.com/web-eid/web-eid.js).

See full example [here](https://github.com/web-eid/web-eid-asp-dotnet-example).

## 1. Add the library to your project

### When using Visual Studio

1. Configure Web eID GitLab package repository as a NuGet package source.  
   In MS Visual Studio, go to the **Tools** > **NuGet Package Manager** > **Package Manager Settings** menu command. Select **Package Sources** and add a new source. Name it _Web eID GitLab_ and set the _Source_ URL to `https://gitlab.com/api/v4/projects/35362906/packages/nuget/index.json`.

2. Install the `WebEid.Security` NuGet package.  
   You can install the package either from the GUI or the Package Manager Console.

  - From GUI:  
    Right-click the project in the Solution Explorer where you want to install the Web eID dependency. Select **Manage NuGet Packages**. Choose the _Web eID GitLab_ package source you added earlier from the _Package source_ dropdown. Then, install the `WebEid.Security` package.
     

  - From Package Manager Console:  
    Run the following command:
    ```
    Install-Package WebEid.Security
    ```

### When using `dotnet` CLI

In case you prefer using command line tools, you can add the package using the `dotnet` CLI with the following command:

```
dotnet add package WebEid.Security --source https://gitlab.com/api/v4/projects/35362906/packages/nuget/index.json
```

**Note:** When you install a package, NuGet records the dependency in either your project file or a `packages.config` file, depending on the selected package management format (`Packages.config` or `PackageReference`).

For more detailed information on different methods of installing NuGet packages, refer to [Microsoft's official documentation](https://learn.microsoft.com/en-us/nuget/consume-packages/overview-and-workflow#ways-to-install-a-nuget-package).

## 2. Configure the challenge nonce store

The validation library needs a store for saving the issued challenge nonces. As it must be guaranteed that the authentication token is received from the same browser to which the corresponding challenge nonce was issued, using a session-backed challenge nonce store is the most natural choice.

Implement the session-backed challenge nonce store as follows:
```cs
using Microsoft.AspNetCore.Http;
using System.Text.Json;
using WebEid.Security.Challenge;

public class SessionBackedChallengeNonceStore : IChallengeNonceStore
{
    private const string ChallengeNonceKey = "challenge-nonce";
    private readonly IHttpContextAccessor httpContextAccessor;

    public SessionBackedChallengeNonceStore(IHttpContextAccessor httpContextAccessor)
    {
        this.httpContextAccessor = httpContextAccessor;
    }

    public void Put(ChallengeNonce challengeNonce)
    {
        this.httpContextAccessor.HttpContext.Session.SetString(ChallengeNonceKey, JsonSerializer.Serialize(challengeNonce));
    }

    public ChallengeNonce GetAndRemoveImpl()
    {
        var httpContext = this.httpContextAccessor.HttpContext;
        var challenceNonceJson = httpContext.Session.GetString(ChallengeNonceKey);
        if (!string.IsNullOrWhiteSpace(challenceNonceJson))
        {
            httpContext.Session.Remove(ChallengeNonceKey);
            return JsonSerializer.Deserialize<ChallengeNonce>(challenceNonceJson);
        }
        return null;
    }
}
```

The `IHttpContextAccessor` dependency of `SessionBackedChallengeNonceStore` must be configured in the ASP.NET `Startup` class:
```cs
services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
```

## 3. Configure the challenge nonce generator

The validation library needs to generate authentication challenge nonces and store them for later validation in the challenge nonce store. Overview of challenge nonce usage is provided in the  [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1). The challenge nonce generator will be used in the REST endpoint that issues challenges; it is thread-safe and should be scoped as a singleton.

Configure the challenge nonce generator and its dependencies in the ASP.NET `Startup` class as follows:

```cs
public void ConfigureServices(IServiceCollection services)
{
...
    services.AddSingleton(RandomNumberGenerator.Create());
    services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
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
Then copy the trusted certificates, for example `ESTEID2018.cer`, to `Certificates` and load the certificates as follows:

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
The mandatory parameters are the website origin (the URL serving the web application), challenge nonce cache and trusted certificate authorities.
The authentication token validator will be used in the login processing component of your web application authentication framework; it is thread-safe and should be scoped as a singleton.

```cs
using Security.Validator;
...
public AuthTokenValidator TokenValidator()
{
return new AuthTokenValidatorBuilder()
    .WithSiteOrigin("https://example.org")
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

When using standard [ASP.NET cookie authentication](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/cookie),

- create the Authentication Middleware services with [`AddAuthentication`](https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.authenticationservicecollectionextensions.addauthentication) and [`AddCookie`](https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.cookieextensions.addcookie) methods in the `Startup.ConfigureServices` method:
    ```cs
    services
        .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie();
    ```
- in `Startup.Configure`, call `UseAuthentication` and `UseAuthorization` to set the `HttpContext.User` property and run Authorization Middleware for requests. Call the `UseAuthentication` and `UseAuthorization` methods before calling `UseEndpoints`:
    ```cs
    app.UseAuthentication();
    app.UseAuthorization();
    
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
        endpoints.MapRazorPages();
    });
    ```
- create a REST endpoint that deals with authentication and creates an authentication cookie:
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

- Similarly, the `MobileAuthInitController` generates a challenge nonce and returns the mobile deep-link for starting the Web eID Mobile authentication flow, and the `MobileAuthLoginController` handles the mobile login request by validating the returned authentication token and creating the authentication cookie.
    ```cs
    using System;
    using System.Text;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Options;
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using Options;
    using Security.Challenge;

    [ApiController]
    [Route("auth/mobile")]
    public class MobileAuthInitController(
        IChallengeNonceGenerator nonceGenerator,
        IOptions<WebEidMobileOptions> mobileOptions
    ) : ControllerBase
    {
        private const string WebEidMobileAuthPath = "auth";
        private const string MobileLoginPath = "/auth/mobile/login";

        [HttpPost("init")]
        public IActionResult Init()
        {
            var challenge = nonceGenerator.GenerateAndStoreNonce(TimeSpan.FromMinutes(5));
            var challengeBase64 = challenge.Base64EncodedNonce;

            var loginUri = $"{Request.Scheme}://{Request.Host}{MobileLoginPath}";

            var payload = new AuthPayload
            {
                Challenge = challengeBase64,
                LoginUri = loginUri,
                GetSigningCertificate = mobileOptions.Value.RequestSigningCert ? true : null
            };

            var json = JsonSerializer.Serialize(payload);
            var encodedPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

            var authUri = BuildAuthUri(encodedPayload);

            return Ok(new AuthUri
            {
                AuthUriValue = authUri
            });
        }
    ```

    ```cs
    using Microsoft.AspNetCore.Mvc;
    using System.Text.Json;
    using Dto;
    using Security.Challenge;
    using Security.Validator;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Security.Util;

    [ApiController]
    [Route("auth/mobile")]
    public class MobileAuthLoginController(
        IAuthTokenValidator authTokenValidator,
        IChallengeNonceStore challengeNonceStore
    ) : ControllerBase
    {
        [HttpPost("login")]
        public async Task<IActionResult> MobileLogin([FromBody] AuthenticateRequestDto dto)
        {
            if (dto?.AuthToken == null)
            {
                return BadRequest(new { error = "Missing auth_token" });
            }

            var parsedToken = dto.AuthToken;
            var certificate = await authTokenValidator.Validate(
                parsedToken,
                challengeNonceStore.GetAndRemove().Base64EncodedNonce);

            var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);

            identity.AddClaim(new Claim(ClaimTypes.GivenName, certificate.GetSubjectGivenName()));
            identity.AddClaim(new Claim(ClaimTypes.Surname, certificate.GetSubjectSurname()));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, certificate.GetSubjectIdCode()));
            identity.AddClaim(new Claim(ClaimTypes.Name, certificate.GetSubjectCn()));

            if (!string.IsNullOrEmpty(parsedToken.UnverifiedSigningCertificate))
            {
                identity.AddClaim(new Claim("signingCertificate", parsedToken.UnverifiedSigningCertificate));
            }

            if (parsedToken.SupportedSignatureAlgorithms != null)
            {
                identity.AddClaim(new Claim(
                    "supportedSignatureAlgorithms",
                    JsonSerializer.Serialize(parsedToken.SupportedSignatureAlgorithms)));
            }

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(identity),
                new AuthenticationProperties { IsPersistent = false });

            return Ok(new { redirect = "/welcome" });
        }
    }
    ```


# Table of contents

* [Introduction](#introduction)
* [Authentication token validation](#authentication-token-validation)
  * [Basic usage](#basic-usage)
  * [Extended configuration](#extended-configuration)
    * [Certificates' Authority Information Access (AIA) extension](#certificates-authority-information-access-aia-extension)
  * [Logging](#logging)
  * [Possible validation errors](#possible-validation-errors)
  * [Stateful and stateless authentication](#stateful-and-stateless-authentication)
* [Challenge nonce generation](#challenge-nonce-generation)
  * [Basic usage](#basic-usage-1)

# Introduction

The Web eID authentication token validation library for .NET contains the implementation of the Web eID authentication token validation process in its entirety to ensure that the authentication token sent by the Web eID browser extension contains valid, consistent data that has not been modified by a third party. It also implements secure challenge nonce generation as required by the Web eID authentication protocol. It is easy to configure and integrate into your authentication service.

The authentication protocol, validation requirements, authentication token format and nonce usage are described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

# Authentication token validation

The authentication token validation process consists of two stages:

- First, **user certificate validation**: the validator parses the token and extracts the user certificate from the *unverifiedCertificate* field. Then it checks the certificate expiration, purpose and policies. Next it checks that the certificate is signed by a trusted CA and checks the certificate status with OCSP.
- Second, **token signature validation**: the validator validates that the token signature was created using the provided user certificate by reconstructing the signed data `hash(origin)+hash(challenge)` and using the public key from the certificate to verify the signature in the `signature` field. If the signature verification succeeds, then the origin and challenge nonce have been implicitly and correctly verified without the need to implement any additional security checks.

The website backend must lookup the challenge nonce from its local store using an identifier specific to the browser session, to guarantee that the authentication token was received from the same browser to which the corresponding challenge nonce was issued. The website backend must guarantee that the challenge nonce lifetime is limited and that its expiration is checked, and that it can be used only once by removing it from the store during validation.

## Basic usage

As described in section *[5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)*, the mandatory configuration parameters are the website origin and trusted certificate authorities.

**Origin** must be the URL serving the web application. Origin URL must be in the form of `"https://" <hostname> [ ":" <port> ]` as defined in [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Location/origin) and not contain path or query components. Note that the `origin` URL must not end with a slash `/`.

The **trusted certificate authority certificates** are used to validate that the user certificate from the authentication token is signed by a trusted certificate authority. Intermediate CA certificates must be used instead of the root CA certificates so that revoked CA certificates can be detected. Trusted certificate authority certificates configuration is described in more detail in section *[4. Add trusted certificate authority certificates](#4-add-trusted-certificate-authority-certificates)*.

Before validation, the previously issued **challenge nonce** must be looked up from the store using an identifier specific to the browser session. The challenge nonce must be passed to the `validate()` method in the corresponding parameter. Setting up the challenge nonce store is described in more detail in section *[2. Configure the challenge nonce store](https://github.com/web-eid/web-eid-authtoken-validation-java#2-configure-the-challenge-nonce-store)*.

The authentication token validator configuration and construction is described in more detail in section *[5. Configure the authentication token validator](#5-configure-the-authentication-token-validator)*. Once the validator object has been constructed, it can be used for validating authentication tokens as follows:

```cs
string challengeNonce = challengeNonceStore.GetAndRemove().Base64EncodedNonce;
WebEidAuthToken token = tokenValidator.Parse(tokenString);
X509Certificate2 userCertificate = tokenValidator.Validate(token, challengeNonce);
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

- `WithoutUserCertificateRevocationCheckWithOcsp()` – turns off user certificate revocation check with OCSP. OCSP check is enabled by default and the OCSP responder access location URL is extracted from the user certificate AIA extension unless a designated OCSP service is activated.
- `WithDesignatedOcspServiceConfiguration(DesignatedOcspServiceConfiguration serviceConfiguration)` – activates the provided designated OCSP responder service configuration for user certificate revocation check with OCSP. The designated service is only used for checking the status of the certificates whose issuers are supported by the service, for other certificates the default AIA extension service access location will be used. See configuration examples in tests.
- `WithOcspRequestTimeout(TimeSpan ocspRequestTimeout)` – sets both the connection and response timeout of user certificate revocation check OCSP requests. Default is 5 seconds.
- `WithDisallowedCertificatePolicies(params string[] policies)` – adds the given policies to the list of disallowed user certificate policies. In order for the user certificate to be considered valid, it must not contain any policies present in this list. Contains the Estonian Mobile-ID policies by default as it must not be possible to authenticate with a Mobile-ID certificate when an eID smart card is expected.
- `WithNonceDisabledOcspUrls(params Uri[] urls)` – adds the given URLs to the list of OCSP URLs for which the nonce protocol extension will be disabled. Some OCSP services don't support the nonce extension.
- `WithAllowedOcspResponseTimeSkew(TimeSpan allowedTimeSkew)` - sets the allowed time skew for OCSP response's `thisUpdate` and `nextUpdate` times to allow discrepancies between the system clock and the OCSP responder's clock or revocation updates that are not published in real time. The default allowed time skew is 15 minutes. The relatively long default is specifically chosen to account for one particular OCSP responder that used CRLs for authoritative revocation info, these CRLs were updated every 15 minutes.
- `WithMaxOcspResponseThisUpdateAge(TimeSpan maxThisUpdateAge)` - sets the maximum age for the OCSP response's `thisUpdate` time before it is considered too old to rely on. The default maximum age is 2 minutes.
Extended configuration example:  

```cs  
AuthTokenValidator validator = new AuthTokenValidatorBuilder(logger)
    .WithSiteOrigin("https://example.org")
    .WithTrustedCertificateAuthorities(TrustedCertificateAuthorities)
    .WithoutUserCertificateRevocationCheckWithOcsp()
    .WithDisallowedCertificatePolicies("1.2.3")
    .WithNonceDisabledOcspUrls(new Uri("http://aia.example.org/cert"))
    .Build();
```

### Certificates' *Authority Information Access* (AIA) extension

Unless a designated OCSP responder service is in use, it is required that the AIA extension that contains the certificate’s OCSP responder access location is present in the user certificate. The AIA OCSP URL will be used to check the certificate revocation status with OCSP.

Note that there may be limitations to using AIA URLs as the services behind these URLs provide different security and SLA guarantees than dedicated OCSP responder services. In case you need a SLA guarantee, use a designated OCSP responder service.

## Logging

Authentication token validation internal logging uses [Microsoft.Extensions.Logging](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/logging). It is recommended that you provide an `ILogger` instance to the constructor of `AuthTokenValidatorBuilder`.

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

The `Validate()` method of `AuthTokenValidator` returns the validated user certificate object if validation is successful or throws an exception if validation fails. All exceptions that can occur during validation derive from `AuthTokenException`, the list of available exceptions is available [here](src/WebEid.Security/Exceptions). Each exception file contains a documentation comment under which conditions the exception is thrown.

## Stateful and stateless authentication

In the code examples above we use the classical stateful ASP.NET session cookie-based authentication mechanism, where a cookie that contains the user session ID is set during successful login and session data is stored at sever side. Cookie-based authentication must be protected against cross-site request forgery (CSRF) attacks and extra measures must be taken to secure the cookies by serving them only over HTTPS and setting the _HttpOnly_, _Secure_ and _SameSite_ attributes.

A common alternative to stateful authentication is stateless authentication with JSON Web Tokens (JWT) or secure cookie sessions where the session data resides at the client side browser and is either signed or encrypted. Secure cookie sessions are described in  [RFC 6896](https://datatracker.ietf.org/doc/html/rfc6896)  and in the following  [article about secure cookie-based Spring Security sessions](https://www.innoq.com/en/blog/cookie-based-spring-security-session/). Usage of both an anonymous session and a cache is required to store the challenge nonce and the time it was issued before the user is authenticated. The anonymous session must be used for protection against  [forged login attacks](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Forging_login_requests)  by guaranteeing that the authentication token is received from the same browser to which the corresponding challenge nonce was issued. The cache must be used for protection against replay attacks by guaranteeing that each authentication token can be used exactly once.

# Challenge nonce generation

The authentication protocol requires support for generating challenge nonces,  large random numbers that can be used only once, and storing them for later use during token validation. The validation library uses the *System.Security.Cryptography.RandomNumberGenerator* API as the secure random source and provides *WebEid.Security.Cache.ICache* interface for storing issued challenge nonces. 

The authentication protocol requires a REST endpoint that issues challenge nonces as described in section *[6. Add a REST endpoint for issuing challenge nonces](#6-add-a-rest-endpoint-for-issuing-challenge-nonces)*.

Nonce usage is described in more detail in the [Web eID system architecture document](https://github.com/web-eid/web-eid-system-architecture-doc#authentication-1).

## Basic usage  

As described in section _[3. Configure the nonce generator](https://github.com/web-eid/web-eid-authtoken-validation-dotnet#3-configure-the-nonce-generator)_, the only mandatory configuration parameter of the challenge nonce generator is the challenge nonce store.

The challenge nonce store is used to save the nonce value along with the nonce expiry time. It must be possible to look up the challenge nonce data structure from the store using an identifier specific to the browser session. The values from the store are used by the token validator as described in the section _[Authentication token validation > Basic usage](https://github.com/web-eid/web-eid-authtoken-validation-dotnet#basic-usage)_ that also contains recommendations for store usage and configuration.

The nonce generator configuration and construction is described in more detail in section _[3. Configure the nonce generator](https://github.com/web-eid/web-eid-authtoken-validation-dotnet#3-configure-the-nonce-generator)_. Once the generator object has been constructed, it can be used for generating nonces as follows:

```cs
ChallengeNonce challengeNonce = nonceGenerator.GenerateAndStoreNonce(timeToLive);  
```

The `GenerateAndStoreNonce(TimeSpan ttl)` method both generates the nonce and stores it in the store. The `ttl` parameter defines nonce time-to-live duration. When the time-to-live passes, the nonce is considered to be expired.
