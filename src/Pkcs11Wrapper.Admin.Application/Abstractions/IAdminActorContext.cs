using System.Security.Claims;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Abstractions;

public interface IAdminActorContext
{
    AdminActorInfo GetCurrent();
}
