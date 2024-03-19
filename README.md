# FindMeAccess

FindMeAccess is a tool useful for finding gaps in Azure/M365 MFA requirements for different resources, client ids, and user agents. The tool is mostly based off [Spray365's](https://github.com/MarkoH17/Spray365) auditing logic. The goal is to provide a streamlined way to quickly check gaps in coverage, as well as obtain tokens.

```
FindMeAccess v1.0

usage: findmeaccess.py [-h] [-u user] [-p password] [--threads THREADS] [--ua_all] [--user_agent USER_AGENT] [-c clientid] [-r resource] [--get_token] [--list_resources] [--list_clients] [--list_ua]
                       [--proxy proxy]

options:
  -h, --help            show this help message and exit
  -u user               User to check
  -p password           Password for account
  --threads THREADS     Number of threads to run (Default: 10 threads)
  --ua_all              Check all users agents (Default: False)
  --user_agent USER_AGENT
                        User Agent to use
  -c clientid           clientid to use
  -r resource           resource to use
  --get_token           Grab a Token (use with clientid and resource flags)
  --list_resources      List all resources
  --list_clients        List all client ids
  --list_ua             List all user agents
  --proxy proxy         HTTP proxy to use - ie http://127.0.0.1:8080
```

## Installation
```
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```
## Basic Usage

For an initial run you just need to provide a username and password. The tool will first try all combinations of resources, client ids, but will only try using one user agent (Windows 10 Chrome). 

You can choose to pass the password via command line with `-p` or just provide the username and be prompted for a password

```
python findmeaccess.py -u username@domain.com
```

For safety reasons, the tool will initially perform a test authentication and if successful, will continue. Otherwise the tool will exit. This helps prevent unintended lockouts via incorrect passwords, as well as just keeping the tool efficient and preventing attempts incorrect usernames, incorrect tenants, etc.

If you want to audit all endpoints with all built-in user agents you can pass the `--ua_all` flag. Currently there are various user agents built-in which target various operating systems (Android, iOS, Linux, Mac, Windows) and various browsers (Chrome, Firefox, Safari).

There are multiple helper functions which can list all the built-in resources, client ids, and user agents.

```
python findmeaccess.py --list_resources

FindMeAccess v1.0

Azure Graph API        : https://graph.windows.net
Azure Management API   : https://management.azure.com
Azure Data Catalog     : https://datacatalog.azure.com
Azure Key Vault        : https://vault.azure.net
Cloud Webapp Proxy     : https://proxy.cloudwebappproxy.net/registerapp
Database               : https://database.windows.net
Microsoft Graph API    : https://graph.microsoft.com
msmamservice           : https://msmamservice.api.application
Office Management      : https://manage.office.com
Office Apps            : https://officeapps.live.com
OneNote                : https://onenote.com
Outlook                : https://outlook.office365.com
Outlook SDF            : https://outlook-sdf.office.com
Sara                   : https://api.diagnostics.office.com
Skype For Business     : https://api.skypeforbusiness.com
Spaces Api             : https://api.spaces.skype.com
Webshell Suite         : https://webshell.suite.office.com
Windows Management API : https://management.core.windows.net
Yammer                 : https://api.yammer.com
```

```
python findmeaccess.py --list_clients

FindMeAccess v1.0

Accounts Control UI                      : a40d7d7d-59aa-447e-a655-679a4107e548
M365 Compliance Drive Client             : be1918be-3fe3-4be9-b32b-b542fc27f02e
Microsoft Authenticator App              : 4813382a-8fa7-425e-ab75-3b753aab3abb
Microsoft Azure CLI                      : 04b07795-8ddb-461a-bbee-02f9e1bf7b46
Microsoft Azure PowerShell               : 1950a258-227b-4e31-a9cf-717495945fc2
Microsoft Bing Search for Microsoft Edge : 2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8
Microsoft Bing Search                    : cf36b471-5b44-428c-9ce7-313bf84528de
Microsoft Defender for Mobile            : dd47d17a-3194-4d86-bfd5-c6ae6f5651e3
Microsoft Defender Platform              : cab96880-db5b-4e15-90a7-f3f1d62ffe39
Microsoft Edge Enterprise New Tab Page   : d7b530a4-7680-4c23-a8bf-c52c121d2e87
Microsoft Edge                           : e9c51622-460d-4d3d-952d-966a5b1da34c
Microsoft Edge2                          : ecd6b820-32c2-49b6-98a6-444530e5a77a
Microsoft Edge3                          : f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34
Microsoft Flow                           : 57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0
Microsoft Intune Company Portal          : 9ba1a5c7-f17a-4de9-a1f1-6178c8d51223
Microsoft Office                         : d3590ed6-52b3-4102-aeff-aad2292ab01c
Microsoft Planner                        : 66375f6b-983f-4c2c-9701-d680650f588f
Microsoft Power BI                       : c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12
Microsoft Stream Mobile Native           : 844cca35-0656-46ce-b636-13f48b0eecbd
Microsoft Teams - Device Admin Agent     : 87749df4-7ccf-48f8-aa87-704bad0e0e16
Microsoft Teams                          : 1fec8e78-bce4-4aaf-ab1b-5451cc387264
Microsoft To-Do client                   : 22098786-6e16-43cc-a27d-191a01a1e3b5
Microsoft Tunnel                         : eb539595-3fe1-474e-9c1d-feb3625d1be5
Microsoft Whiteboard Client              : 57336123-6e14-4acc-8dcf-287b6088aa28
Office 365 Management                    : 00b41c95-dab0-4487-9791-b9d2c32c80f2
Office UWP PWA                           : 0ec893e0-5785-4de6-99da-4ed124e5296c
OneDrive iOS App                         : af124e86-4e96-495a-b70a-90f90ab96707
OneDrive SyncEngine                      : ab9b8c07-8f02-4f72-87fa-80105867a763
OneDrive                                 : b26aadf8-566f-4478-926f-589f601d9c74
Outlook Lite                             : e9b154d0-7658-433b-bb25-6b8e0a8a7c59
Outlook Mobile                           : 27922004-5251-4030-b22d-91ecd9a37ea4
PowerApps                                : 4e291c71-d680-4d0e-9640-0a3358e31177
SharePoint Android                       : f05ff7c9-f75a-4acd-a3b5-f4b6a870245d
SharePoint                               : d326c1ce-6cc6-4de2-bebc-4591e5e13ef0
Visual Studio                            : 872cd9fa-d31f-45e0-9eab-6e460a02d1f1
Windows Search                           : 26a7ee05-5602-4d76-a7ba-eae8b7b67941
Yammer iPhone                            : a569458c-7f2b-45cb-bab9-b7dee514d112
```

```
python findmeaccess.py --list_ua

FindMeAccess v1.0

Android Chrome    : Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.178 Mobile Safari/537.36
iPhone Safari     : Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1
Mac Firefox       : Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0
Chrome OS         : Mozilla/5.0 (X11; CrOS x86_64 15633.69.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.212 Safari/537.36
Linux Firefox     : Mozilla/5.0 (X11; Linux i686; rv:94.0) Gecko/20100101 Firefox/94.0
Windows 10 Chrome : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
Windows 7 IE11    : Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
Windows 10 IE11   : Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko
Windows 10 Edge   : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.128
Windows Phone     : Mozilla/5.0 (Windows Mobile 10; Android 10.0; Microsoft; Lumia 950XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36 Edge/40.15254.603
```

Custom user agents can be passed with the `--user_agent` flag.

```
python findmeaccess.py -u username@domain.com --user_agent "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.178 Mobile Safari/537.36"
```


Specific resources can also be targeted with the `-r` flag via the resource name or resource URL. The `--ua_all` flag can also be passed for trying all built-in user agents.

```
python findmeaccess.py -u username@domain.com -r "Azure Graph API" --ua_all
python findmeaccess.py -u username@domain.com -r "https://graph.windows.net"
```

## Getting a Token
If you do find gaps in MFA you can get tokens using the `--get_token` flag, along with specifying a resource `-r` and client id `-c`. The resource or client id values can be their named values in the tool or actual values. 


```
python findmeaccess.py -u username@domain.com --get_token -e "Microsoft Graph API" -c "Microsoft Azure PowerShell"
python findmeaccess.py -u username@domain.com --get_token -r "https://graph.microsoft.com" -c "1950a258-227b-4e31-a9cf-717495945fc2"
```

## Credits
https://github.com/secureworks/family-of-client-ids-research

https://github.com/MarkoH17/Spray365