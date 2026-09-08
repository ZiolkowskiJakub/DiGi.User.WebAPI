#### [DiGi\.User\.WebAPI](DiGi.User.WebAPI.Overview.md 'DiGi\.User\.WebAPI\.Overview')

## DiGi\.User\.WebAPI\.Classes Namespace
### Classes

<a name='DiGi.User.WebAPI.Classes.UserController'></a>

## UserController Class

Controller responsible for handling user\-related operations, including authentication, session lifecycle and access to protected data\.

```csharp
public class UserController : DiGi.WebAPI.Classes.WebAPIController
```

Inheritance [System\.Object](https://learn.microsoft.com/en-us/dotnet/api/system.object 'System\.Object') → [Microsoft\.AspNetCore\.Mvc\.ControllerBase](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.controllerbase 'Microsoft\.AspNetCore\.Mvc\.ControllerBase') → [DiGi\.WebAPI\.Classes\.WebAPIController](https://learn.microsoft.com/en-us/dotnet/api/digi.webapi.classes.webapicontroller 'DiGi\.WebAPI\.Classes\.WebAPIController') → UserController
### Constructors

<a name='DiGi.User.WebAPI.Classes.UserController.UserController(DiGi.WebAPI.Classes.SecurityKeyManager,DiGi.WebAPI.Classes.TokenRevocationStore,DiGi.User.PostgreSQL.Classes.UserPostgreSQLConverter)'></a>

## UserController\(SecurityKeyManager, TokenRevocationStore, UserPostgreSQLConverter\) Constructor

Initializes a new instance of the [UserController](DiGi.User.WebAPI.Classes.md#DiGi.User.WebAPI.Classes.UserController 'DiGi\.User\.WebAPI\.Classes\.UserController') class\.

This is deliberately the only public constructor: a second one makes the controller ambiguous to the
            activator and every endpoint answers 500 at request time, with the build still green.

```csharp
public UserController(DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager, DiGi.WebAPI.Classes.TokenRevocationStore tokenRevocationStore, DiGi.User.PostgreSQL.Classes.UserPostgreSQLConverter userPostgreSQLConverter);
```
#### Parameters

<a name='DiGi.User.WebAPI.Classes.UserController.UserController(DiGi.WebAPI.Classes.SecurityKeyManager,DiGi.WebAPI.Classes.TokenRevocationStore,DiGi.User.PostgreSQL.Classes.UserPostgreSQLConverter).securityKeyManager'></a>

`securityKeyManager` [DiGi\.WebAPI\.Classes\.SecurityKeyManager](https://learn.microsoft.com/en-us/dotnet/api/digi.webapi.classes.securitykeymanager 'DiGi\.WebAPI\.Classes\.SecurityKeyManager')

The security key manager used for managing cryptographic keys\.

<a name='DiGi.User.WebAPI.Classes.UserController.UserController(DiGi.WebAPI.Classes.SecurityKeyManager,DiGi.WebAPI.Classes.TokenRevocationStore,DiGi.User.PostgreSQL.Classes.UserPostgreSQLConverter).tokenRevocationStore'></a>

`tokenRevocationStore` [DiGi\.WebAPI\.Classes\.TokenRevocationStore](https://learn.microsoft.com/en-us/dotnet/api/digi.webapi.classes.tokenrevocationstore 'DiGi\.WebAPI\.Classes\.TokenRevocationStore')

The token revocation store used for terminating sessions\.

<a name='DiGi.User.WebAPI.Classes.UserController.UserController(DiGi.WebAPI.Classes.SecurityKeyManager,DiGi.WebAPI.Classes.TokenRevocationStore,DiGi.User.PostgreSQL.Classes.UserPostgreSQLConverter).userPostgreSQLConverter'></a>

`userPostgreSQLConverter` [DiGi\.User\.PostgreSQL\.Classes\.UserPostgreSQLConverter](https://learn.microsoft.com/en-us/dotnet/api/digi.user.postgresql.classes.userpostgresqlconverter 'DiGi\.User\.PostgreSQL\.Classes\.UserPostgreSQLConverter')

The converter used to read users and their credentials from PostgreSQL\.
### Methods

<a name='DiGi.User.WebAPI.Classes.UserController.GetProtectedDataAsync(System.Threading.CancellationToken)'></a>

## UserController\.GetProtectedDataAsync\(CancellationToken\) Method

Retrieves the stored record of the authenticated user\.

The record is read for the email carried by the presented token, so a caller can only ever read itself.
            The credential columns are not part of the [DiGi\.User\.Classes\.User](https://learn.microsoft.com/en-us/dotnet/api/digi.user.classes.user 'DiGi\.User\.Classes\.User') payload and are never returned.

```csharp
public System.Threading.Tasks.Task<Microsoft.AspNetCore.Mvc.IActionResult> GetProtectedDataAsync(System.Threading.CancellationToken cancellationToken=default(System.Threading.CancellationToken));
```
#### Parameters

<a name='DiGi.User.WebAPI.Classes.UserController.GetProtectedDataAsync(System.Threading.CancellationToken).cancellationToken'></a>

`cancellationToken` [System\.Threading\.CancellationToken](https://learn.microsoft.com/en-us/dotnet/api/system.threading.cancellationtoken 'System\.Threading\.CancellationToken')

A cancellation token that can be used by other objects or threads to receive notice of cancellation\.

#### Returns
[System\.Threading\.Tasks\.Task&lt;](https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.task-1 'System\.Threading\.Tasks\.Task\`1')[Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult')[&gt;](https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.task-1 'System\.Threading\.Tasks\.Task\`1')  
An [Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult') containing the stored user, a not found result, or an authorization error\.

<a name='DiGi.User.WebAPI.Classes.UserController.GetSession()'></a>

## UserController\.GetSession\(\) Method

Introspects the current session, returning the identity and token metadata of the presented token\.

```csharp
public Microsoft.AspNetCore.Mvc.IActionResult GetSession();
```

#### Returns
[Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult')  
An [Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult') containing the session information, or an authorization error\.

<a name='DiGi.User.WebAPI.Classes.UserController.LoginAsync(DiGi.User.Classes.UserLogin,System.Threading.CancellationToken)'></a>

## UserController\.LoginAsync\(UserLogin, CancellationToken\) Method

Authenticates a user against the credential stored in PostgreSQL and generates a JWT security token carrying a
fresh session identifier \(jti claim\)\.

Every outcome that is not an exact password match answers 401, and all of them take the same time: an
            unknown email, an account whose credential was never set, and a wrong password are indistinguishable to the
            caller. The server log distinguishes them.

```csharp
public System.Threading.Tasks.Task<Microsoft.AspNetCore.Mvc.IActionResult> LoginAsync(DiGi.User.Classes.UserLogin userLogin, System.Threading.CancellationToken cancellationToken=default(System.Threading.CancellationToken));
```
#### Parameters

<a name='DiGi.User.WebAPI.Classes.UserController.LoginAsync(DiGi.User.Classes.UserLogin,System.Threading.CancellationToken).userLogin'></a>

`userLogin` [DiGi\.User\.Classes\.UserLogin](https://learn.microsoft.com/en-us/dotnet/api/digi.user.classes.userlogin 'DiGi\.User\.Classes\.UserLogin')

The login credentials of the user\.

<a name='DiGi.User.WebAPI.Classes.UserController.LoginAsync(DiGi.User.Classes.UserLogin,System.Threading.CancellationToken).cancellationToken'></a>

`cancellationToken` [System\.Threading\.CancellationToken](https://learn.microsoft.com/en-us/dotnet/api/system.threading.cancellationtoken 'System\.Threading\.CancellationToken')

A cancellation token that can be used by other objects or threads to receive notice of cancellation\.

#### Returns
[System\.Threading\.Tasks\.Task&lt;](https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.task-1 'System\.Threading\.Tasks\.Task\`1')[Microsoft\.AspNetCore\.Mvc\.IActionResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.iactionresult 'Microsoft\.AspNetCore\.Mvc\.IActionResult')[&gt;](https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.task-1 'System\.Threading\.Tasks\.Task\`1')  
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