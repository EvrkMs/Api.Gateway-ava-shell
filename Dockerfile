FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["Api.Gateway/Api.Gateway.csproj", "Api.Gateway/"]
RUN dotnet restore "Api.Gateway/Api.Gateway.csproj"
COPY . .
WORKDIR "/src/Api.Gateway"
RUN dotnet publish "Api.Gateway.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Api.Gateway.dll"]
