using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using ResiApp.Models;
using ResiApp.Context;
using ResiApp.Security;
using ResiApp.Services;
using Newtonsoft.Json;
using System.Web.Security;
using ResiApp.Utils;
using System.Collections.Generic;
using System.Net;
using System.Data.Entity;

namespace ResiApp.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly ResiAppDBContext _db;
        private readonly IPasswordEncripter _passwordEncripter;
        private readonly IAuthorizationService _authService;

        public AccountController(ResiAppDBContext db, IPasswordEncripter passwordEncripter, IAuthorizationService authService)
        {
            _db = db;
            _passwordEncripter = passwordEncripter;
            _authService = authService;
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Index()
        {
            var usuarios = _db.Usuarios.Include(u => u.Rol);
            return View(await usuarios.ToListAsync());
        }

        [AllowAnonymous]
        public ActionResult Login()
        {
            return View(new Login());
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(Login model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            Usuario usuario = new Usuario();
            var result = _authService.Auth(model.Email, model.Password, out usuario);
            switch (result)
            {
                case AuthResults.Success:
                    CookieUpdate(usuario);
                    if (SessionHelper.Rol == "Administrador")
                        return RedirectToAction("Index", "Home");
                    else
                        return RedirectToAction("UserView", "Home");

                case AuthResults.PasswordNotMatch:
                    ModelState.AddModelError("", "La contraseña es incorrecta.");
                    return View(model);

                case AuthResults.NotExists:
                    ModelState.AddModelError("", "El usuario no existe.");
                    return View(model);

                default:
                    ModelState.AddModelError("", "Error de autenticación.");
                    return View(model);
            }
        }

        private void CookieUpdate(Usuario usuario)
        {
            try
            {
                var ticket = new FormsAuthenticationTicket(
                    2,
                    usuario.Correo,
                    DateTime.Now,
                    DateTime.Now.AddMinutes(FormsAuthentication.Timeout.TotalMinutes),
                    false,
                    usuario.Rol.DescripcionRol
                );

                var encryptedTicket = FormsAuthentication.Encrypt(ticket);
                var authCookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);
                Response.Cookies.Add(authCookie);

                SessionHelper.NombreCompleto = usuario.Nombres + " " + usuario.Apellidos;
                SessionHelper.UserName = usuario.Correo;
                SessionHelper.Rol = usuario.Rol.DescripcionRol;
                SessionHelper.UserId = usuario.IdUsuario;
            }
            catch (Exception ex)
            {
                throw new Exception("Error al crear la cookie de autenticación: " + ex.Message);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            Session.RemoveAll();
            Session.Clear();
            FormsAuthentication.SignOut();
            return RedirectToAction("Inicio", "Home");
        }

        [AuthorizeRole("Administrador")]
        public ActionResult Register()
        {
            ViewBag.Rol = _db.Rol.Select(r => new SelectListItem { Value = r.IdRol.ToString(), Text = r.DescripcionRol }).ToList();
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(Usuario model)
        {
            if (ModelState.IsValid)
            {
                var hash = new List<byte[]>();
                model.Contrasena = _passwordEncripter.Encript(model.Contrasena, out hash);
                model.HashKey = hash[0];
                model.HashIV = hash[1];
                model.UsuarioCreacion = SessionHelper.UserId.Value;

                _db.Usuarios.Add(model);
                await _db.SaveChangesAsync();

                TempData["SuccessMessage"] = "Usuario creado correctamente";
                return RedirectToAction("Index");
            }
            ViewBag.Rol = _db.Rol.Select(r => new SelectListItem { Value = r.IdRol.ToString(), Text = r.DescripcionRol }).ToList();
            return View(model);
        }

        public async Task<ActionResult> Edit(int? id)
        {
            if ((SessionHelper.Rol != "Administrador") && (id != SessionHelper.UserId.Value))
            {
                return RedirectToAction("Unauthorized", "Error");
            }

            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Usuario usuario = await _db.Usuarios.FindAsync(id);
            if (usuario == null)
            {
                return HttpNotFound();
            }
            ViewBag.Rol = await _db.Rol.Select(r => new SelectListItem { Value = r.IdRol.ToString(), Text = r.DescripcionRol }).ToListAsync();
            return View(usuario);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(Usuario model)
        {
            if (ModelState.IsValid)
            {
                if (!string.IsNullOrEmpty(model.NuevaContrasena))
                {
                    if (model.HashKey == null && model.HashIV == null)
                    {
                        var hash = new List<byte[]>();
                        model.Contrasena = _passwordEncripter.Encript(model.NuevaContrasena, out hash);
                        model.HashKey = hash[0];
                        model.HashIV = hash[1];
                    }
                    else
                    {
                        model.Contrasena = _passwordEncripter.Encript(model.NuevaContrasena, new List<byte[]>()
                          .AddHash(model.HashKey)
                          .AddHash(model.HashIV));
                    }
                }
                model.FechaModificacion = DateTime.Now;
                model.UsuarioModificacion = SessionHelper.UserId;

                _db.Entry(model).State = EntityState.Modified;
                await _db.SaveChangesAsync();

                TempData["SuccessMessage"] = "Usuario actualizado correctamente";
                return RedirectToAction("Index");
            }

            ViewBag.Rol = _db.Rol.Select(r => new SelectListItem { Value = r.IdRol.ToString(), Text = r.DescripcionRol }).ToList();
            return View(model);
        }

        [AuthorizeRole("Administrador")]
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Usuario usuario = _db.Usuarios.Find(id);
            if (usuario == null)
            {
                return HttpNotFound();
            }
            return View(usuario);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(int id)
        {
            Usuario usuario = _db.Usuarios.Find(id);
            _db.Usuarios.Remove(usuario);
            await _db.SaveChangesAsync();
            TempData["SuccessMessage"] = "Usuario eliminado correctamente";
            return RedirectToAction("Index");
        }

        // ════════════════════════════════════════════════════════════════
        //  RECUPERACIÓN DE CONTRASEÑA
        // ════════════════════════════════════════════════════════════════

        [HttpGet]
        [AllowAnonymous]
        public ActionResult ForgotPassword() => View();

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ForgotPassword(string correo, string telefono)
        {
            if (string.IsNullOrWhiteSpace(correo) || string.IsNullOrWhiteSpace(telefono))
            {
                ViewBag.Error = "Por favor ingresa todos los campos.";
                return View();
            }

            var usuario = _db.Usuarios
                             .FirstOrDefault(u => u.Correo == correo
                                               && u.Telefono == telefono);

            if (usuario == null)
            {
                ViewBag.Error = "El correo o número de celular no coinciden con ningún usuario registrado.";
                return View();
            }

            Session["RecuperacionUsuarioId"] = usuario.IdUsuario;
            return RedirectToAction("ResetPassword");
        }

        [HttpGet]
        [AllowAnonymous]
        public ActionResult ResetPassword()
        {
            if (Session["RecuperacionUsuarioId"] == null)
                return RedirectToAction("ForgotPassword");

            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ResetPassword(string nuevaContrasena, string confirmarContrasena)
        {
            if (Session["RecuperacionUsuarioId"] == null)
                return RedirectToAction("ForgotPassword");

            if (string.IsNullOrWhiteSpace(nuevaContrasena) || string.IsNullOrWhiteSpace(confirmarContrasena))
            {
                ViewBag.Error = "Por favor ingresa todos los campos.";
                return View();
            }

            if (nuevaContrasena != confirmarContrasena)
            {
                ViewBag.Error = "Las contraseñas no coinciden.";
                return View();
            }

            if (nuevaContrasena.Length < 6)
            {
                ViewBag.Error = "La contraseña debe tener al menos 6 caracteres.";
                return View();
            }

            int usuarioId = (int)Session["RecuperacionUsuarioId"];
            var usuario = _db.Usuarios.Find(usuarioId);

            if (usuario == null)
            {
                ViewBag.Error = "Usuario no encontrado.";
                return RedirectToAction("ForgotPassword");
            }

            var hashes = new List<byte[]>();
            usuario.Contrasena = _passwordEncripter.Encript(nuevaContrasena, out hashes);
            usuario.HashKey = hashes[0];
            usuario.HashIV = hashes[1];
            usuario.FechaModificacion = DateTime.Now;
            usuario.UsuarioModificacion = usuario.IdUsuario;

            _db.SaveChanges();

            Session.Remove("RecuperacionUsuarioId");

            TempData["SuccessMessage"] = "¡Contraseña actualizada correctamente! Ya puedes iniciar sesión.";
            return RedirectToAction("Login");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}