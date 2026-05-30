# In the future, we should use chiseled images.
FROM mcr.microsoft.com/dotnet/aspnet:8.0-jammy

WORKDIR /app

COPY ria_public_key.gpg /usr/share/keyrings/ria-repository.gpg

# Add RIA repository to install the official libdigidocpp-csharp package. As each RUN commits the layer to image,
# need to chain commands and clean up in the end to keep the image small.
RUN echo "deb [signed-by=/usr/share/keyrings/ria-repository.gpg] https://installer.id.ee/media/ubuntu/ jammy main" > /etc/apt/sources.list.d/ria-repository.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends libdigidocpp-csharp && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists

COPY ./WebEid.AspNetCore.Example/bin/Release/net8.0/publish/ .

COPY ./WebEid.AspNetCore.Example/Certificates/Dev/self-signed-server-certificate.pfx /https/self-signed-server-certificate.pfx

ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS="https://+:443"
ENV ASPNETCORE_Kestrel__Certificates__Default__Path=/https/self-signed-server-certificate.pfx

EXPOSE 443

ENTRYPOINT ["dotnet", "WebEid.AspNetCore.Example.dll"]
