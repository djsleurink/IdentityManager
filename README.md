[![Nuget](https://img.shields.io/nuget/v/djsleurink.IdentityManager)](https://www.nuget.org/packages/djsleurink.IdentityManager)

# Identity Manager for ASP.NET Core / Blazor Server 
## Simple yet effective
This package adds basic CRUD actions for Identity Management  which can be used during development for ASP.NET Core/Blazor Server projects using the identity framework provided by Microsoft.

It does what it says, with the least setup/hassle possible.

I made it because i needed the functionality for my personal apps. I based it off of Carl Franklin's https://github.com/carlfranklin/IdentityManagerLibrary
I Just wanted to make it more reuseable for myself.

## Prerequitites
- TargetFramework >= .NET 8.0
- Have identity management setup using Microsoft.AspNetCore.Identity

## Setup
1. Setting up the IdentityManager
2. Adding CRUD pages

### 1. Setting up the IdentityManager
Do the following in you main ASP.NET Core / Blazor Server project:

- Add the package using NuGet package manager `djsleurink.IdentityManager` or using CLI:`dotnet add package djsleurink.IdentityManager`
- Register the identity manager: 
	 - `using IdentityManager;`	
	- `builder.Services.AddIdentityManager<[your IdentityUser model], [your IdentityRole model]>();`

### 2. Adding CRUD pages
- In App.Razor add the following inside the router tag
	-  `AdditionalAssemblies="new[] { typeof(IdentityManager.DependencyInjection).Assembly}"`
- In your NavMenu include the following: 
	 -	`<IdentityManagerNavigationLinks></IdentityManagerNavigationLinks>`



## Done

The CRUD pages can be reached via:
- identitymanager/users 
	- identitymanager/createuser
	- identitymanager/edituser/{id}
- identitymanager/roles
	-  identitymanager/createrole

A management class will be accessible that you can use, it is registered with the ServiceCollection as the IIdentityManager, this will let you use the CRUD actions in your code directly.
