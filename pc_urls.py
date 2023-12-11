'''
This is the Private Cloud Address list.  It will need updated over time.
'''
import os
from dotenv import load_dotenv

load_dotenv()
pc_domain = os.getenv('PC_DOMAIN')

PCADDRESSLIST = [
    f"console.{pc_domain}",
    f"auth.{pc_domain}",
    f"disp.{pc_domain}",
    f"disp-ext.{pc_domain}",
    f"disp-update.{pc_domain}",
    f"fmc.{pc_domain}"
    ]
