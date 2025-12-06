using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using ResiApp.Context;
using ResiApp.Models;
using ResiApp.Security;
using ResiApp.Utils;

namespace ResiApp.Services
{
    public class AuthorizationService : IAuthorizationService
    {
        private readonly ResiAppDBContext db = new ResiAppDBContext();
        private readonly IPasswordEncripter _passordEncripter = new PasswordEncripter();

        public AuthResults Auth(string user, string password, out Usuario usuario)
        {
            usuario = db.Usuarios.Where(x => x.Correo.Equals(user)).FirstOrDefault();

            if (usuario == null)
                return AuthResults.NotExists;

            password = _passordEncripter.Encript(password, new List<byte[]>()
                .AddHash(usuario.HashKey)
                .AddHash(usuario.HashIV)
                );
            if (password != usuario.Contrasena)
                return AuthResults.PasswordNotMatch;

            return AuthResults.Success;
        }
    }
}