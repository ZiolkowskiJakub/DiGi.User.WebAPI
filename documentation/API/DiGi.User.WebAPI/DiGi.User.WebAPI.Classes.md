#### [DiGi\.User\.WebAPI](DiGi.User.WebAPI.Overview.md 'DiGi\.User\.WebAPI\.Overview')

## DiGi\.User\.WebAPI\.Classes Namespace
### Classes

<a name='DiGi.User.WebAPI.Classes.UserController'></a>

## UserController Class

Controller responsible for handling user\-related operations, including authentication and access to protected data\.

```csharp
public class UserController : DiGi.WebAPI.Classes.WebAPIController
```

Inheritance [System\.Object](https://learn.microsoft.com/en-us/dotnet/api/system.object 'System\.Object') → [Microsoft\.AspNetCore\.Mvc\.ControllerBase](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.controllerbase 'Microsoft\.AspNetCore\.Mvc\.ControllerBase') → [DiGi\.Core\.Interfaces\.IObject](https://learn.microsoft.com/en-us/dotnet/api/digi.core.interfaces.iobject 'DiGi\.Core\.Interfaces\.IObject') → [DiGi\.WebAPI\.Classes\.WebAPIController](https://learn.microsoft.com/en-us/dotnet/api/digi.webapi.classes.webapicontroller 'DiGi\.WebAPI\.Classes\.WebAPIController') → UserController
### Constructors

<a name='DiGi.User.WebAPI.Classes.UserController.UserController(DiGi.WebAPI.Classes.SecurityKeyManager)'></a>

## UserController\(SecurityKeyManager\) Constructor

Initializes a new instance of the [UserController](DiGi.User.WebAPI.Classes.md#DiGi.User.WebAPI.Classes.UserController 'DiGi\.User\.WebAPI\.Classes\.UserController') class\.

```csharp
public UserController(DiGi.WebAPI.Classes.SecurityKeyManager securityKeyManager);
```
#### Parameters

<a name='DiGi.User.WebAPI.Classes.UserController.UserController(DiGi.WebAPI.Classes.SecurityKeyManager).securityKeyManager'></a>

`securityKeyManager` [DiGi\.WebAPI\.Classes\.SecurityKeyManager](https://learn.microsoft.com/en-us/dotnet/api/digi.webapi.classes.securitykeymanager 'DiGi\.WebAPI\.Classes\.SecurityKeyManager')

The security key manager used for managing cryptographic keys\.
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

<a name='DiGi.User.WebAPI.Classes.UserController.Login(DiGi.User.Classes.UserLogin)'></a>

## UserController\.Login\(UserLogin\) Method

Authenticates a user and generates a JWT security token\.

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