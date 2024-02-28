import argparse
import sys
import requests
import urllib3
import concurrent.futures
from termcolor import colored
import json
from tabulate import tabulate
import getpass


# endpoint resources 
resources = {
    "Azure Graph API": "https://graph.windows.net",
    "Azure Management API": "https://management.azure.com",
    "Azure Data Catalog": "https://datacatalog.azure.com",
    "Azure Key Vault": "https://vault.azure.net",
    "Cloud Webapp Proxy": "https://proxy.cloudwebappproxy.net/registerapp",
    "Database": "https://database.windows.net",
    "Microsoft Graph API": "https://graph.microsoft.com",
    "msmamservice": "https://msmamservice.api.application",
    "Office Management": "https://manage.office.com",
    "Office Apps": "https://officeapps.live.com",
    "OneNote": "https://onenote.com",
    "Outlook": "https://outlook.office365.com",
    "Outlook SDF": "https://outlook-sdf.office.com",
    "Sara": "https://api.diagnostics.office.com",
    "Skype For Business": "https://api.skypeforbusiness.com",
    "Spaces Api": "https://api.spaces.skype.com",
    "Webshell Suite": "https://webshell.suite.office.com",
    "Windows Management API": "https://management.core.windows.net",
    "Yammer": "https://api.yammer.com"
}

# used for final display
final_results = {}

# https://github.com/secureworks/family-of-client-ids-research/blob/main/known-foci-clients.csv
client_ids = {
   "Accounts Control UI" : "a40d7d7d-59aa-447e-a655-679a4107e548",
   "M365 Compliance Drive Client" : "be1918be-3fe3-4be9-b32b-b542fc27f02e",
   "Microsoft Authenticator App" : "4813382a-8fa7-425e-ab75-3b753aab3abb",
   "Microsoft Azure CLI" : "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
   "Microsoft Azure PowerShell" : "1950a258-227b-4e31-a9cf-717495945fc2",
   "Microsoft Bing Search for Microsoft Edge" : "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8",
   "Microsoft Bing Search" : "cf36b471-5b44-428c-9ce7-313bf84528de",
   "Microsoft Defender for Mobile" : "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3",
   "Microsoft Defender Platform" : "cab96880-db5b-4e15-90a7-f3f1d62ffe39",
   "Microsoft Edge Enterprise New Tab Page" : "d7b530a4-7680-4c23-a8bf-c52c121d2e87",
   "Microsoft Edge" : "e9c51622-460d-4d3d-952d-966a5b1da34c",
   "Microsoft Edge2" : "ecd6b820-32c2-49b6-98a6-444530e5a77a",
   "Microsoft Edge3" : "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34",
   "Microsoft Flow" : "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0",
   "Microsoft Intune Company Portal" : "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
   "Microsoft Office" : "d3590ed6-52b3-4102-aeff-aad2292ab01c",
   "Microsoft Planner" : "66375f6b-983f-4c2c-9701-d680650f588f",
   "Microsoft Power BI" : "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12",
   "Microsoft Stream Mobile Native" : "844cca35-0656-46ce-b636-13f48b0eecbd",
   "Microsoft Teams - Device Admin Agent" : "87749df4-7ccf-48f8-aa87-704bad0e0e16",
   "Microsoft Teams" : "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
   "Microsoft To-Do client" : "22098786-6e16-43cc-a27d-191a01a1e3b5",
   "Microsoft Tunnel" : "eb539595-3fe1-474e-9c1d-feb3625d1be5",
   "Microsoft Whiteboard Client" : "57336123-6e14-4acc-8dcf-287b6088aa28",
   "Office 365 Management" : "00b41c95-dab0-4487-9791-b9d2c32c80f2",
   "Office UWP PWA" : "0ec893e0-5785-4de6-99da-4ed124e5296c",
   "OneDrive iOS App" : "af124e86-4e96-495a-b70a-90f90ab96707",
   "OneDrive SyncEngine" : "ab9b8c07-8f02-4f72-87fa-80105867a763",
   "OneDrive" : "b26aadf8-566f-4478-926f-589f601d9c74",
   "Outlook Lite" : "e9b154d0-7658-433b-bb25-6b8e0a8a7c59",
   "Outlook Mobile" : "27922004-5251-4030-b22d-91ecd9a37ea4",
   "PowerApps" : "4e291c71-d680-4d0e-9640-0a3358e31177",
   "SharePoint Android" : "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d",
   "SharePoint" : "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0",
   "Visual Studio" : "872cd9fa-d31f-45e0-9eab-6e460a02d1f1",
   "Windows Search" : "26a7ee05-5602-4d76-a7ba-eae8b7b67941",
   "Yammer iPhone" : "a569458c-7f2b-45cb-bab9-b7dee514d112",
}

# https://www.whatismybrowser.com/guides/the-latest-user-agent/
user_agents = {
  "Android Chrome": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.178 Mobile Safari/537.36",
  "iPhone Safari": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
  "Mac Firefox": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
  "Chrome OS": "Mozilla/5.0 (X11; CrOS x86_64 15633.69.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.212 Safari/537.36",
  "Linux Firefox": "Mozilla/5.0 (X11; Linux i686; rv:94.0) Gecko/20100101 Firefox/94.0",
  "Windows 10 Chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
  "Windows 7 IE11": "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
  "Windows 10 IE11": "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
  "Windows 10 Edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.128",
  "Windows Phone" : "Mozilla/5.0 (Windows Mobile 10; Android 10.0; Microsoft; Lumia 950XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36 Edge/40.15254.603"
}

# pretty print dictionaries
def print_aligned(dictionary):
    max_key_length = max(len(key) for key in dictionary.keys())
    for key, value in dictionary.items():
      print(f"{key.ljust(max_key_length)} : {value}")

# main authentication function
def authenticate(username, password, resource, client_id, user_agent, proxy, get_token=False):
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    url = "https://login.microsoft.com/common/oauth2/token" 

    parameters = {
        'resource': resource[1],
        'client_id': client_id[1],
        'client_info': '1',
        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': 'openid'
    }

    headers = {
        'User-Agent': user_agent[1],
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.post(url, data=parameters, headers=headers, proxies=proxy, verify=False)
    
    if response.status_code == 200:
        success_string = colored("Success! No MFA","green", attrs=['bold'])
        print(f"[+] {resource[0]} - {client_id[0]} - {user_agent[0]} - {success_string}")
        if get_token:
           json_text = json.loads(response.text)
           print(json.dumps(json_text, indent=2))
        else:
          return resource, client_id, user_agent

    else:
        # Standard invalid password
        if "AADSTS50126" in response.text:
            raise ValueError(colored(f"[!] Error validating credentials for {username}","red", attrs=['bold']))
        
        # Invalid Tenant Response
        elif "AADSTS50128" in response.text or "AADSTS50059" in response.text:
            raise ValueError(colored(f"[!] Tenant for account {username} doesn't exist.","red", attrs=['bold']))
        
        # Invalid Username
        elif "AADSTS50034" in response.text:
            raise ValueError(colored(f"[!] The account {username} doesn't exist.","red", attrs=['bold']))
        
        # Microsoft MFA 
        elif "AADSTS50079" in response.text or "AADSTS50076" in response.text:
            message_string = colored("Microsoft MFA Required or blocked by conditional access","yellow", attrs=['bold'])
            print(f"[-] {resource[0]} - {client_id[0]} - {user_agent[0]} - {message_string}")
        
        # Conditional Access 
        elif "AADSTS53003" in response.text:
            message_string = colored("Blocked by conditional access policy","yellow", attrs=['bold'])
            print(f"[-] {resource[0]} - {client_id[0]} - {user_agent[0]} - {message_string} ")
        
        # Third party MFA
        elif "AADSTS50158" in response.text:
            message_string = colored("Third-party MFA required","yellow", attrs=['bold'])
            print(f"[-] {resource[0]} - {client_id[0]} - {user_agent[0]} - {message_string} ")

        # Locked out account or hitting smart lockout
        elif "AADSTS50053" in response.text:
            raise ValueError(colored(f"[!] The account {username} appears to be locked.","red", attrs=['bold']))
        
        # Disabled account
        elif "AADSTS50057" in response.text:
            raise ValueError(colored(f"[!] The account {username} appears to be disabled.","red", attrs=['bold']))
        
        # Clientid isn't valid for resource
        elif "AADSTS65002" in response.text:
            message_string = colored("Client_id not authorized for resource","yellow", attrs=['bold'])
            print(f"[-] {resource[0]} - {client_id[0]} - {message_string} ")

        # Suspicious activity
        elif "AADSTS53004" in response.text:
            message_string = colored("Suspicious activity","yellow", attrs=['bold'])
            print(f"[-] {resource[0]} - {client_id[0]} - {message_string} ")
        
        # Empty password
        elif "AADSTS900144" in response.text:
           raise ValueError(colored(f"[!] No password provided for {username}","red", attrs=['bold']))
        
        # User password is expired
        elif "AADSTS50055" in response.text:
            raise ValueError(colored(f"[!] Password for {username} expired!","red", attrs=['bold']))
        
        # Invalid resource resource
        elif "AADSTS500011" in response.text:
            raise ValueError(colored(f"[!] resource resource {resource[1]} is invalid","red", attrs=['bold']))
        
        # Invalid clientid
        elif "AADSTS700016" in response.text:
            raise ValueError(colored(f"[!] Clientid {client_id[1]} is invalid","red", attrs=['bold']))

        # default unknown
        else:
            response_data = json.loads(response)
            error_description = response_data.get('error_description')
            raise ValueError(colored(f"[!] Unknown error encountered: {error_description}","red", attrs=['bold']))

        return

# do a test authentication to validate creds and to prevent a bunch of attempts on accounts that throw errors
def do_test_auth(username, password, proxy):
    print("[*] Performing test authentication")
    ua_key = "Windows 10 Chrome"
    ua_value = user_agents[ua_key]
    user_agent = (ua_key, ua_value)
    resource_key = "Azure Graph API"
    resource_value = resources[resource_key]
    resource = (resource_key, resource_value)
    client_key = "Outlook Mobile"
    client_value = client_ids[client_key]
    client_id = (client_key, client_value)
    authenticate(username, password, resource, client_id, user_agent, proxy)

# function to get tokens
def get_token(username, password, custom_resource, custom_client_id, custom_user_agent, proxy):
    print("[*] Getting token")
    if custom_user_agent is None:
      print("[-] No User Agent specified, using Windows 10 Chrome")
      ua_key = "Windows 10 Chrome"
      ua_value = user_agents[ua_key]
      user_agent = (ua_key, ua_value)
    else:
      user_agent = ("Custom", custom_user_agent)

    if custom_resource is None:
       print("[-] No resource resource specified. Use '-e' argument")
       sys.exit()

    # check if resource provided is a key in resources dict
    if custom_resource in resources:
      resource_value = resources[custom_resource]
      resource = (custom_resource, resource_value)

    # check if resource provided is a value in resources dict
    elif custom_resource in resources.values():
       for key, value in resources.items(): 
          if value == custom_resource:
             resource = (key, custom_resource)
    
    # otherwise just add the Custom tag
    else:
       resource = ("Custom", custom_resource)

    if custom_client_id is None:
       print("[-] No client id specified. Use '-c' argument")
       sys.exit()

    if custom_client_id in client_ids:
      client_id_value = client_ids[custom_client_id]
      client_id = (custom_client_id, client_id_value)
    
    else:
       client_id = ("Custom", custom_client_id)

    try:
      authenticate(username, password, resource, client_id, user_agent, proxy, True)
    except ValueError as e:
       print(e)

# Create a function to handle each combination of parameters
def handle_combination(combination):
    username, password, resource, client_id, user_agent, proxy = combination
    return authenticate(username, password, resource, client_id, user_agent, proxy)
    
# mass check resources, client ids, and user agents
def check_resources(username, password, all_user_agents, threads, custom_user_agent, custom_resource, proxy):
  print("[*] Starting checks")
  results = []
  resources_to_check = {}
  if custom_resource is not None:
    
    # check if resource provided is a key in resources dict
    if custom_resource in resources:
        resource_value = resources[custom_resource]
        resources_to_check[custom_resource] = resource_value

    # check if resource provided is a value in resources dict
    elif custom_resource in resources.values():
       for key, value in resources.items(): 
          if value == custom_resource:
             resources_to_check[key] = custom_resource
    
    # otherwise just add the Custom tag         
    else:
        resources_to_check["Custom"] = custom_resource
  else:
     resources_to_check = resources

  # generate final results dict
  for resource in resources_to_check:
     final_results[resource] = {'Accessible': False, 'Accessible Client IDs': 0}

  if all_user_agents:
    combinations = [(username, password, resource, client_id, user_agent, proxy)
                for resource in resources_to_check.items()
                for client_id in client_ids.items()
                for user_agent in user_agents.items()]
  else:
      if custom_user_agent is not None:
          ua_value = custom_user_agent
          ua_key = "Custom"
          user_agent = (ua_key, ua_value)
      else:
          ua_key = "Windows 10 Chrome"
          ua_value = user_agents[ua_key]
          user_agent = (ua_key, ua_value)
      
      combinations = [(username, password, resource, client_id, user_agent, proxy)
                for resource in resources_to_check.items()
                for client_id in client_ids.items()]
  try:
    error_raised = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
      try:
        for result in executor.map(handle_combination, combinations):
          results.append(result)
      except ValueError as e:
        # just want to print one time
        if not error_raised:
          error_raised = True
          print(e) 
        sys.exit()

    return results
  
  except KeyboardInterrupt:
    print(colored("[!] Ctrl+C detected, exiting...", "yellow"))
    sys.exit()

# self-explanatory
def write_results(username, results):
  #filter out None results
  filtered_results = [x for x in results if x is not None]
  filename = username + "-accessible.txt"
  with open(filename, "a+") as f:
    for result in filtered_results:
      f.write(', '.join(map(str, result)) + '\n')

  print(f"\n[+] Results written to {filename}\n")

# print out final table
def print_table(results):
  #filter out None results
  filtered_results = [x for x in results if x is not None]

  for result in filtered_results:
    resource_name = result[0][0]
    if resource_name in final_results:
      final_results[resource_name]['Accessible'] = True
      final_results[resource_name]['Accessible Client IDs'] += 1
        
  table_data = []
  for resource, e in final_results.items():
    accessible = e['Accessible']
    if accessible:
        accessible = colored(accessible, 'green',attrs=['bold'])
    else:
       accessible = colored(accessible, 'red',attrs=['bold'])
    table_data.append([resource, accessible, e['Accessible Client IDs']])

  print("\n\n"+tabulate(table_data, headers=[colored("Resource", attrs=['bold']), colored("Accessible w/o MFA",attrs=['bold']), colored("Accessible Client IDs",attrs=['bold'])], tablefmt="grid"))

def main():
    banner = "\nFindMeAccess v1.0\n"
    print(banner)

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-u', metavar="user", help="User to check", type=str)
    parser.add_argument('-p', metavar="password", help="Password for account", type=str)      
    parser.add_argument('--threads', help="Number of threads to run (Default: 10 threads)", type=int,default=10)
    parser.add_argument('--ua_all', help="Check all users agents (Default: False)", action='store_true', default=False)
    parser.add_argument('--user_agent', help="User Agent to use", type=str)
    parser.add_argument('-c', metavar="clientid", help="clientid to use", type=str)
    parser.add_argument('-r', metavar="resource", help="resource to use", type=str)
    parser.add_argument('--get_token', help="Grab a Token (use with clientid and resource flags)", action='store_true')
    parser.add_argument('--list_resources', help="List all resources", action='store_true')  
    parser.add_argument('--list_clients', help="List all client ids", action='store_true')  
    parser.add_argument('--list_ua', help="List all user agents", action='store_true')
    parser.add_argument('--proxy', metavar="proxy", help="HTTP proxy to use - ie http://127.0.0.1:8080", type=str)

    args = parser.parse_args()
    if len(sys.argv) == 1:
      parser.print_help()
    
    if args.list_resources:
       print_aligned(resources)
    
    elif args.list_clients:
       print_aligned(client_ids)

    elif args.list_ua:
       print_aligned(user_agents)

    else:
       
      if not args.u:
        print("[-] No username specified with '-u' option")
        sys.exit()
      
      if not args.p:
        password = getpass.getpass()
      else:
        password = args.p
      
      if args.proxy:
        proxies = {
           "http": args.proxy, 
           "https": args.proxy
           }
      else:
        proxies = {}

      if args.get_token:
          get_token(args.u, password, args.r, args.c, args.user_agent, proxies)
    
      else:

        try:
          do_test_auth(args.u, password, proxies)
          print("[+] Test authentication successful!")

        except Exception as e:
          print(e)
          print("[!] Exception caught, exiting...")
          sys.exit()

        try:
          results = check_resources(args.u, password, args.ua_all, args.threads, args.user_agent, args.r, proxies)
          if not args.ua_all:
            print_table(results)
          write_results(args.u, results)

        except Exception as e:
            print(e)
            print("[!] Exception caught, exiting...")
            sys.exit()
    
if __name__ == "__main__":
    main()