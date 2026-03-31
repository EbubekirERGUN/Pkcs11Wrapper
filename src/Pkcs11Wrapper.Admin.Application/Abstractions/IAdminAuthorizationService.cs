using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Abstractions;

public interface IAdminAuthorizationService
{
    void DemandViewer();

    void DemandOperator();

    void DemandAdmin();
}
