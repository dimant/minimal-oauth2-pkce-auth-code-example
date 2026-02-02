# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY ResourceServer/ResourceServer.csproj ResourceServer/
RUN dotnet restore ResourceServer/ResourceServer.csproj

COPY ResourceServer/ ResourceServer/
RUN dotnet build ResourceServer/ResourceServer.csproj -c Release -o /app/build

RUN dotnet publish ResourceServer/ResourceServer.csproj -c Release -o /app/publish

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app
COPY --from=build /app/publish .

ENTRYPOINT ["dotnet", "ResourceServer.dll"]
