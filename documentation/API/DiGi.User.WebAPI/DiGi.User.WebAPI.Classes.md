#### [DiGi\.User\.WebAPI](DiGi.User.WebAPI.Overview.md 'DiGi\.User\.WebAPI\.Overview')

## DiGi\.User\.WebAPI\.Classes Namespace
### Classes

<a name='DiGi.User.WebAPI.Classes.UserController'></a>

## UserController Class

Controller responsible for handling user\-related operations, including authentication, session lifecycle and access to protected data\.

```csharp
public class UserController : DiGi.WebAPI.Classes.WebAPIController
```

Inheritance [System\.Object](https://learn.microsoft.com/en-us/dotnet/api/system.object 'System\.Object') → [Microsoft\.AspNetCore\.Mvc\.ControllerBase](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.controllerbase 'Microsoft\.AspNetCore\.Mvc\.ControllerBase') → [DiGi\.Core\.Interfaces\.IObject](https://learn.microsoft.com/en-us/dotnet/api/digi.core.interfaces.iobject 'DiGi\.Core\.Interfaces\.IObject') → [DiGi\.WebAPI\.Classes\.WebAPIController](https://learn.microsoft.com/en-us/dotnet/api/digi.webapi.classes.webapicontroller 'DiGi\.WebAPI\.Classes\.WebAPIController') → UserController
### Constructors

<a name='DiGi.User.WebAPI.Classes.UserController.UserController(DiGi.WebAPI.Classes.SecurityKeyManager,DiGi.WebAPI.Classes.TokenRevocationStore)'></a>

## UserController\(SecurityKeyManager, TokenRevocationStore\) Constructor

Initializes a new instance of the [UserController](DiGi.User.WebAPI.Classes.md#DiGi.User.WebAPI.Classes.UserController 'DiGi\.User\.WebAPI\.Classes\.UserController') class\.

```csharp
public UserController(DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager, DiGi.WebAPI.Classes.TokenRevocationStore tokenRevocationStore);
```
#### Parameters

<a name='DiGi.User.WebAPI.Classes.UserController.UserController(DiGi.WebAPI.Classes.SecurityKeyManager,DiGi.WebAPI.Classes.TokenRevocationStore).securityKeyManager'></a>

`securityKeyManager` [DiGi\.WebAPI\.Classes\.SecurityKeyManager](https://learn.microsoft.com/en-us/dotnet/api/digi.webapi.classes.securitykeymanager 'DiGi\.WebAPI\.Classes\.SecurityKeyManager')

The security key manager used for managing cryptographic keys\.

<a name='DiGi.User.WebAPI.Classes.UserController.UserController(DiGi.WebAPI.Classes.SecurityKeyManager,DiGi.WebAPI.Classes.TokenRevocationStore).tokenRevocationStore'></a>

`tokenRevocationStore` [DiGi\.WebAPI\.Classes\.TokenRevocationStore](https://learn.microsoft.com/en-us/dotnet/api/digi.webapi.classes.tokenrevocationstore 'DiGi\.WebAPI\.Classes\.TokenRevocationStore')

The token revocation store used for terminating sessions\.
### Methods

<a name='DiGi.User.WebAPI.Classes.UserController.GetProtectedData()'></a>

## UserController\.GetProtectedData\(\) Method

Retrieves secure data that requires authorization\.

```csharp
public Microsoft.AspNetCore.Mvc.IActionResult GetProtectedData();
```

#### Returns
[Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult')  
An [Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult') containing the protected data or an authorization error\.

<a name='DiGi.User.WebAPI.Classes.UserController.GetSession()'></a>

## UserController\.GetSession\(\) Method

Introspects the current session, returning the identity and token metadata of the presented token\.

```csharp
public Microsoft.AspNetCore.Mvc.IActionResult GetSession();
```

#### Returns
[Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult')  
An [Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult') containing the session information, or an authorization error\.

<a name='DiGi.User.WebAPI.Classes.UserController.Login(DiGi.User.Classes.UserLogin)'></a>

## UserController\.Login\(UserLogin\) Method

Authenticates a user and generates a JWT security token carrying a fresh session identifier \(jti claim\)\.

```csharp
public Microsoft.AspNetCore.Mvc.IActionResult Login(DiGi.User.Classes.UserLogin userLogin);
```
#### Parameters

<a name='DiGi.User.WebAPI.Classes.UserController.Login(DiGi.User.Classes.UserLogin).userLogin'></a>

`userLogin` [DiGi\.User\.Classes\.UserLogin](https://learn.microsoft.com/en-us/dotnet/api/digi.user.classes.userlogin 'DiGi\.User\.Classes\.UserLogin')

The login credentials of the user\.

#### Returns
[Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult')  
An [Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult') containing the generated token upon success, or an unauthorized result\.

<a name='DiGi.User.WebAPI.Classes.UserController.Logout()'></a>

## UserController\.Logout\(\) Method

Terminates the current session by revoking the presented token until its natural expiration; every subsequent request carrying it is rejected\.

```csharp
public Microsoft.AspNetCore.Mvc.IActionResult Logout();
```

#### Returns
[Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult')  
An [Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult') confirming the revocation, a bad request when the token cannot be revoked, or an authorization error\.

<a name='DiGi.User.WebAPI.Classes.UserController.ReadPresentedToken()'></a>

## UserController\.ReadPresentedToken\(\) Method

Reads the bearer token from the Authorization header, already validated by the authentication middleware for any authorized action\.

```csharp
private System.IdentityModel.Tokens.Jwt.JwtSecurityToken? ReadPresentedToken();
```

#### Returns
[System\.IdentityModel\.Tokens\.Jwt\.JwtSecurityToken](https://learn.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.jwt.jwtsecuritytoken 'System\.IdentityModel\.Tokens\.Jwt\.JwtSecurityToken')  
The presented [System\.IdentityModel\.Tokens\.Jwt\.JwtSecurityToken](https://learn.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.jwt.jwtsecuritytoken 'System\.IdentityModel\.Tokens\.Jwt\.JwtSecurityToken'), or null when the header does not carry a bearer token\.

<a name='DiGi.User.WebAPI.Classes.UserController.Refresh()'></a>

## UserController\.Refresh\(\) Method

Issues a new token for the identity of the presented token, starting an independent session; the presented token remains valid until its own expiration\.

```csharp
public Microsoft.AspNetCore.Mvc.IActionResult Refresh();
```

#### Returns
[Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult')  
An [Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult') containing the new token, or an authorization error\.