using Autodesk.Forge;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ForgeSample.Controllers.API
{

    [ApiController]
    public class TwoLeggedOAuthController : ControllerBase
    {
        private static dynamic InternalToken { get; set; }
        public static dynamic PublicToken { get; set; }

        /// <summary>
        /// Get access token with public (viewables:read) scope
        /// </summary>
        [HttpGet]
        [Route("api/forge/oauth/2leggedtoken")]
        public async Task<dynamic> GetPublicAsync()
        {
            try
            {
                if (PublicToken == null || PublicToken.ExpiresAt < DateTime.UtcNow)
                {
                    PublicToken = await Get2LeggedTokenAsync(new Scope[] { Scope.ViewablesRead });
                    PublicToken.ExpiresAt = DateTime.UtcNow.AddSeconds(PublicToken.expires_in);
                }
                return Newtonsoft.Json.JsonConvert.SerializeObject(PublicToken);

            }
            catch(Exception exp)
            {
                Exception a = exp;
                return PublicToken;
            }
            
        }
        public static async Task<dynamic> GetInternalAsync()
        {
            if (InternalToken == null || InternalToken.ExpiresAt < DateTime.UtcNow)
            {
                InternalToken = await Get2LeggedTokenAsync(new Scope[] { 
                    Scope.BucketCreate, 
                    Scope.BucketRead, 
                    Scope.BucketDelete, 
                    Scope.DataRead, 
                    Scope.DataWrite, 
                    Scope.DataCreate, 
                    Scope.CodeAll });
                InternalToken.ExpiresAt = DateTime.UtcNow.AddSeconds(InternalToken.expires_in);
            }

            return InternalToken;
        }

        private static async Task<dynamic> Get2LeggedTokenAsync(Scope[] scopes)
        {
            TwoLeggedApi oauth = new TwoLeggedApi();
            string grantType = "client_credentials";
            dynamic bearer = await oauth.AuthenticateAsync(Environment.GetEnvironmentVariable("FORGE_CLIENT_ID"), Environment.GetEnvironmentVariable("FORGE_CLIENT_SECRET"), grantType, scopes);
            return bearer;
        }
    }
}
