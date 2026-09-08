#### [DiGi\.User\.WebAPI](DiGi.User.WebAPI.Overview.md 'DiGi\.User\.WebAPI\.Overview')

## DiGi\.User\.WebAPI\.Constants Namespace
### Classes

<a name='DiGi.User.WebAPI.Constants.Password'></a>

## Password Class

Provides the PBKDF2 parameters new password credentials are derived with\.

```csharp
public static class Password
```

Inheritance [System\.Object](https://learn.microsoft.com/en-us/dotnet/api/system.object 'System\.Object') → Password
### Fields

<a name='DiGi.User.WebAPI.Constants.Password.HashSize'></a>

## Password\.HashSize Field

The length in bytes of the derived key stored as the password hash\.

```csharp
public const int HashSize = 32;
```

#### Field Value
[System\.Int32](https://learn.microsoft.com/en-us/dotnet/api/system.int32 'System\.Int32')

<a name='DiGi.User.WebAPI.Constants.Password.Iterations'></a>

## Password\.Iterations Field

The number of PBKDF2\-HMAC\-SHA256 iterations a new credential is stretched over, per the OWASP password
storage guidance\.

This value applies to credentials being created. Verification uses the iteration count stored on the
            credential itself, so raising this number costs nothing to the credentials already written.

```csharp
public const int Iterations = 210000;
```

#### Field Value
[System\.Int32](https://learn.microsoft.com/en-us/dotnet/api/system.int32 'System\.Int32')

<a name='DiGi.User.WebAPI.Constants.Password.SaltSize'></a>

## Password\.SaltSize Field

The length in bytes of the random salt generated for a new credential\.

```csharp
public const int SaltSize = 16;
```

#### Field Value
[System\.Int32](https://learn.microsoft.com/en-us/dotnet/api/system.int32 'System\.Int32')

<a name='DiGi.User.WebAPI.Constants.Session'></a>

## Session Class

Holds constants describing user sessions, such as the lifetime of issued tokens\.

```csharp
public static class Session
```

Inheritance [System\.Object](https://learn.microsoft.com/en-us/dotnet/api/system.object 'System\.Object') → Session
### Fields

<a name='DiGi.User.WebAPI.Constants.Session.TokenLifetime'></a>

## Session\.TokenLifetime Field

The lifetime of a token issued by login or refresh; a session token expires naturally after this duration\.

```csharp
public static readonly TimeSpan TokenLifetime;
```

#### Field Value
[System\.TimeSpan](https://learn.microsoft.com/en-us/dotnet/api/system.timespan 'System\.TimeSpan')