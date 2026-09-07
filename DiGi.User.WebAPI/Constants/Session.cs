using System;

namespace DiGi.User.WebAPI.Constants
{
    /// <summary>
    /// Holds constants describing user sessions, such as the lifetime of issued tokens.
    /// </summary>
    public static class Session
    {
        /// <summary>
        /// The lifetime of a token issued by login or refresh; a session token expires naturally after this duration.
        /// </summary>
        public static readonly TimeSpan TokenLifetime = TimeSpan.FromHours(1);
    }
}
