#### [DiGi\.User\.WebAPI](DiGi.User.WebAPI.Overview.md 'DiGi\.User\.WebAPI\.Overview')

## DiGi\.User\.WebAPI Namespace
### Classes

<a name='DiGi.User.WebAPI.Create'></a>

## Create Class

```csharp
public static class Create
```

Inheritance [System\.Object](https://learn.microsoft.com/en-us/dotnet/api/system.object 'System\.Object') → Create
### Methods

<a name='DiGi.User.WebAPI.Create.TokenString(thisDiGi.WebAPI.Classes.SecurityKeyManager,string)'></a>

## Create\.TokenString\(this SecurityKeyManager, string\) Method

Creates a signed JWT string identifying the given email, carrying a fresh JWT identifier \(jti claim\) and expiring after the session token lifetime\.

Each call starts an independent session: the fresh jti makes the issued token individually revocable.

```csharp
public static string? TokenString(this DiGi.WebAPI.Classes.SecurityKeyManager? securityKeyManager, string? email);
```
#### Parameters

<a name='DiGi.User.WebAPI.Create.TokenString(thisDiGi.WebAPI.Classes.SecurityKeyManager,string).securityKeyManager'></a>

`securityKeyManager` [DiGi\.WebAPI\.Classes\.SecurityKeyManager](https://learn.microsoft.com/en-us/dotnet/api/digi.webapi.classes.securitykeymanager 'DiGi\.WebAPI\.Classes\.SecurityKeyManager')

The security key manager providing the active signing key\.

<a name='DiGi.User.WebAPI.Create.TokenString(thisDiGi.WebAPI.Classes.SecurityKeyManager,string).email'></a>

`email` [System\.String](https://learn.microsoft.com/en-us/dotnet/api/system.string 'System\.String')

The email of the identity the token is issued for\.

#### Returns
[System\.String](https://learn.microsoft.com/en-us/dotnet/api/system.string 'System\.String')  
The signed token string, or null when the manager, its active key or the email is missing\.

<a name='DiGi.User.WebAPI.Create.UserCredential(string,string)'></a>

## Create\.UserCredential\(string, string\) Method

Creates a [UserCredential\(string, string\)](DiGi.User.WebAPI.md#DiGi.User.WebAPI.Create.UserCredential(string,string) 'DiGi\.User\.WebAPI\.Create\.UserCredential\(string, string\)') for a password, deriving it with PBKDF2\-HMAC\-SHA256 over a freshly
generated random salt\.

The salt is random per call, so creating a credential twice for the same password yields two different
            hashes and neither reveals that the passwords match.

The credential is not stored by this method. Pass the result to
            `UserPostgreSQLConverter.SetUserCredentialAsync` to write it against an existing user.

```csharp
public static DiGi.User.Classes.UserCredential? UserCredential(string? email, string? password);
```
#### Parameters

<a name='DiGi.User.WebAPI.Create.UserCredential(string,string).email'></a>

`email` [System\.String](https://learn.microsoft.com/en-us/dotnet/api/system.string 'System\.String')

The email address of the user the credential belongs to\.

<a name='DiGi.User.WebAPI.Create.UserCredential(string,string).password'></a>

`password` [System\.String](https://learn.microsoft.com/en-us/dotnet/api/system.string 'System\.String')

The plain text password to derive the credential from\.

#### Returns
[DiGi\.User\.Classes\.UserCredential](https://learn.microsoft.com/en-us/dotnet/api/digi.user.classes.usercredential 'DiGi\.User\.Classes\.UserCredential')  
The derived [UserCredential\(string, string\)](DiGi.User.WebAPI.md#DiGi.User.WebAPI.Create.UserCredential(string,string) 'DiGi\.User\.WebAPI\.Create\.UserCredential\(string, string\)'), or null when the email or the password is blank\.

<a name='DiGi.User.WebAPI.Modify'></a>

## Modify Class

```csharp
public static class Modify
```

Inheritance [System\.Object](https://learn.microsoft.com/en-us/dotnet/api/system.object 'System\.Object') → Modify
### Methods

<a name='DiGi.User.WebAPI.Modify.InitializeAsync(thisMicrosoft.Extensions.DependencyInjection.IServiceCollection)'></a>

## Modify\.InitializeAsync\(this IServiceCollection\) Method

Initializes the authentication and authorization services for the Web API, including security key management,
token revocation and the PostgreSQL converters the controllers read users from\.

```csharp
public static System.Threading.Tasks.Task InitializeAsync(this Microsoft.Extensions.DependencyInjection.IServiceCollection serviceCollection);
```
#### Parameters

<a name='DiGi.User.WebAPI.Modify.InitializeAsync(thisMicrosoft.Extensions.DependencyInjection.IServiceCollection).serviceCollection'></a>

`serviceCollection` [Microsoft\.Extensions\.DependencyInjection\.IServiceCollection](https://learn.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection 'Microsoft\.Extensions\.DependencyInjection\.IServiceCollection')

The [Microsoft\.Extensions\.DependencyInjection\.IServiceCollection](https://learn.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection 'Microsoft\.Extensions\.DependencyInjection\.IServiceCollection') to add services to\.

#### Returns
[System\.Threading\.Tasks\.Task](https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.task 'System\.Threading\.Tasks\.Task')  
A [System\.Threading\.Tasks\.Task](https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.task 'System\.Threading\.Tasks\.Task') representing the asynchronous operation\.

<a name='DiGi.User.WebAPI.Query'></a>

## Query Class

```csharp
public static class Query
```

Inheritance [System\.Object](https://learn.microsoft.com/en-us/dotnet/api/system.object 'System\.Object') → Query
### Methods

<a name='DiGi.User.WebAPI.Query.IsPasswordValid(thisDiGi.User.Classes.UserCredential,string)'></a>

## Query\.IsPasswordValid\(this UserCredential, string\) Method

Determines whether a password matches a stored credential, deriving it with the iteration count recorded on
the credential and comparing the result in constant time\.

Every branch that is not an exact match denies: a null credential, a blank password, a credential
            missing its hash or salt, a non-positive iteration count, and malformed Base64 all return false.

A null credential is still verified against a fixed dummy salt before the answer is returned, so the
            time an unknown email takes to be rejected does not reveal that the account does not exist.

```csharp
public static bool IsPasswordValid(this DiGi.User.Classes.UserCredential? userCredential, string? password);
```
#### Parameters

<a name='DiGi.User.WebAPI.Query.IsPasswordValid(thisDiGi.User.Classes.UserCredential,string).userCredential'></a>

`userCredential` [DiGi\.User\.Classes\.UserCredential](https://learn.microsoft.com/en-us/dotnet/api/digi.user.classes.usercredential 'DiGi\.User\.Classes\.UserCredential')

The stored credential to verify against, or null when the user has none\.

<a name='DiGi.User.WebAPI.Query.IsPasswordValid(thisDiGi.User.Classes.UserCredential,string).password'></a>

`password` [System\.String](https://learn.microsoft.com/en-us/dotnet/api/system.string 'System\.String')

The plain text password presented by the caller\.

#### Returns
[System\.Boolean](https://learn.microsoft.com/en-us/dotnet/api/system.boolean 'System\.Boolean')  
True when the password derives to the stored hash; otherwise, false\.