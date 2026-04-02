# syntax=docker/dockerfile:1.7

FROM mcr.microsoft.com/dotnet/sdk:10.0-noble AS restore
WORKDIR /src

COPY ["global.json", "Directory.Build.props", "./"]
COPY ["docs/nuget/README.nuget.md", "docs/nuget/"]
COPY ["src/Pkcs11Wrapper.Admin.Web/Pkcs11Wrapper.Admin.Web.csproj", "src/Pkcs11Wrapper.Admin.Web/"]
COPY ["src/Pkcs11Wrapper.Admin.Application/Pkcs11Wrapper.Admin.Application.csproj", "src/Pkcs11Wrapper.Admin.Application/"]
COPY ["src/Pkcs11Wrapper.Admin.Infrastructure/Pkcs11Wrapper.Admin.Infrastructure.csproj", "src/Pkcs11Wrapper.Admin.Infrastructure/"]
COPY ["src/Pkcs11Wrapper/Pkcs11Wrapper.csproj", "src/Pkcs11Wrapper/"]
COPY ["src/Pkcs11Wrapper.Native/Pkcs11Wrapper.Native.csproj", "src/Pkcs11Wrapper.Native/"]
RUN dotnet restore "src/Pkcs11Wrapper.Admin.Web/Pkcs11Wrapper.Admin.Web.csproj"

FROM restore AS publish
COPY src ./src
COPY ["docs/nuget/README.nuget.md", "docs/nuget/"]
RUN dotnet publish "src/Pkcs11Wrapper.Admin.Web/Pkcs11Wrapper.Admin.Web.csproj" \
    --configuration Release \
    --output /app/publish \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble AS final
ARG APP_UID=64198
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends softhsm2 \
    && rm -rf /var/lib/apt/lists/*
ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_EnableDiagnostics=0 \
    AdminStorage__DataRoot=/var/lib/pkcs11wrapper-admin \
    AdminRuntime__DisableHttpsRedirection=true \
    HOME=/var/lib/pkcs11wrapper-admin/home \
    TMPDIR=/var/lib/pkcs11wrapper-admin/tmp \
    SOFTHSM2_CONF=/opt/pkcs11/softhsm/softhsm2.conf
WORKDIR /app
COPY --from=publish /app/publish ./
RUN mkdir -p /var/lib/pkcs11wrapper-admin/home /var/lib/pkcs11wrapper-admin/keys /var/lib/pkcs11wrapper-admin/tmp /opt/pkcs11/lib /opt/pkcs11/softhsm/tokens \
    && ln -sf /usr/lib/softhsm/libsofthsm2.so /opt/pkcs11/lib/libsofthsm2.so \
    && chown -R ${APP_UID}:0 /app /var/lib/pkcs11wrapper-admin /opt/pkcs11 \
    && chmod -R g=u /app /var/lib/pkcs11wrapper-admin /opt/pkcs11
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["dotnet", "Pkcs11Wrapper.Admin.Web.dll", "--container-healthcheck", "http://127.0.0.1:8080/health/ready"]
VOLUME ["/var/lib/pkcs11wrapper-admin", "/opt/pkcs11/softhsm"]
EXPOSE 8080
USER ${APP_UID}
ENTRYPOINT ["dotnet", "Pkcs11Wrapper.Admin.Web.dll"]
