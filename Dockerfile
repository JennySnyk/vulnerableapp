# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["VulnerabilityScannerTestApp/VulnerabilityScannerTestApp.csproj", "VulnerabilityScannerTestApp/"]
RUN dotnet restore "VulnerabilityScannerTestApp/VulnerabilityScannerTestApp.csproj"
COPY . .

WORKDIR /src/VulnerabilityScannerTestApp
RUN dotnet build "VulnerabilityScannerTestApp.csproj" -c Release -o /app

FROM build AS publish
RUN dotnet publish "VulnerabilityScannerTestApp.csproj" -c Release -o /app

FROM base AS final

WORKDIR /app
COPY --from=publish /app .
COPY entrypoint.sh entrypoint.sh
ENTRYPOINT ["/bin/bash", "entrypoint.sh"]