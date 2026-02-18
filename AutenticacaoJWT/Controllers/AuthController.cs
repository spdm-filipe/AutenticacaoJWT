using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace AutenticacaoJWT.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : Controller
    {
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost]
        public IActionResult Authenticate([FromBody] Credential credential)
        {
            if (credential.UserName == "admin" && credential.Password == "password")
            {
                var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, "admin"),
                        new Claim(ClaimTypes.Email, "admin@website.com"),
                        new Claim("Departamento", "RH"),
                        new Claim("admin", "true")
                    };
                var expiresAt = DateTime.UtcNow.AddMinutes(30);

                return base.Ok(new
                {
                    access_token = CreateToken(claims, expiresAt),
                    expires_at = expiresAt
                });
            }

            ModelState.AddModelError("Unauthorized", "Usuário ou senha inválidos");

            var problemDetails = new ValidationProblemDetails(ModelState)
            {
                Status = StatusCodes.Status401Unauthorized,
                Title = "Unauthorized",
                Detail = "Usuário ou senha inválidos"
            };

            return Unauthorized(problemDetails);
        }

        private string CreateToken(List<Claim> claims, DateTime expiresAt)
        {
            var claimsDic = new Dictionary<string, object>();
            if (claims is not null && claims.Count > 0)
            {
                foreach (var claim in claims)
                {
                    claimsDic.Add(claim.Type, claim.Value);
                }
            }

            var key = System.Text.Encoding.ASCII.GetBytes(_configuration["SecretKey"] ?? string.Empty);
           
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expiresAt,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature),
                NotBefore = DateTime.UtcNow
            };
            var tokenHandler = new JsonWebTokenHandler(); 
           return tokenHandler.CreateToken(tokenDescriptor);
        }
    }
}
