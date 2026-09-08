#### [DiGi\.User\.WebAPI](DiGi.User.WebAPI.Overview.md 'DiGi\.User\.WebAPI\.Overview')

## DiGi\.User\.WebAPI\.Constants Namespace
### Classes

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