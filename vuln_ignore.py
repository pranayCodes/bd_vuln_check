#!/usr/bin/env python3

"""
vuln_ignore.py

This python script is used to mark vulnerabilities in a "New" status on the BOM, by double checking (best pass effort) on the basis of the library being used. This script will work only for CentOS/ RedHat packages on a BOM.

The aim of this script is to mark vulnerabilities as ignored, and give a RHSA reference wherever possible in the comments.

Usage:
    vuln_ignore.py (--instance INSTANCE) (--token TOKEN) (--project=PROJECT) (--version VERSION)

Arguments:
    --instance=INSTANCE            Black Duck instance URL (without protocol)

    --token=TOKEN              API token generated from the BD instance

    --project=PROJECT              Project UUID

    --version=VERSION              Version UUID

"""

import requests
import json
from requests_jwt import JWTAuth
import re
from docopt import docopt
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def __init__(self, args):

    self.args = args

def print_msg_box(msg, indent=1, width=None, title=None):
    """Print message-box with optional title."""
    lines = msg.split('\n')
    space = " " * indent
    if not width:
        width = max(map(len, lines))
    box = f'╔{"═" * (width + indent * 2)}╗\n'  # upper_border
    if title:
        box += f'║{space}{title:<{width}}{space}║\n'  # title
        box += f'║{space}{"-" * len(title):<{width}}{space}║\n'  # underscore
    box += ''.join([f'║{space}{line:<{width}}{space}║\n' for line in lines])
    box += f'╚{"═" * (width + indent * 2)}╝'  # lower_border
    print(box)

def authenticate(args):
    response = requests.post('https://{}/api/tokens/authenticate'.format(args['--instance']), headers={'Authorization': 'token '+args['--token']}, verify=False)    
    return response.json().get('bearerToken')

def update_hub_vuln(args, bearer_token, component_id, version_id, origin_id, cve_id, message):
    project_version = 'https://{}/api/projects/{}/versions/{}/'.format(args['--instance'],args['--project'],args['--version'])
    origin_vuln = 'components/{}/versions/{}/origins/{}/vulnerabilities/{}/remediation/'.format(component_id, version_id, origin_id, cve_id)
    url = project_version + origin_vuln
    ignore = False
    
    comment = ' / '

    if message[0] == 'Not affected':
        ignore = True
        payload = "{\"comment\" : \""+comment.join(message)+"\",\"remediationStatus\" : \"IGNORED\"}"
    else:
        payload = "{\"comment\" : \""+comment.join(message)+"\",\"remediationStatus\" : \"NEW\"}"
    
    headers = {
    'Content-Type': 'application/vnd.blackducksoftware.bill-of-materials-6+json',
    'Accept': 'application/vnd.blackducksoftware.bill-of-materials-6+json',
    'Authorization': 'Bearer '+bearer_token
    }
    
    resp = requests.request("PUT",url,data=payload,headers=headers,verify=False)
    
    if resp.status_code == 202:
        ret = "Processed"
    else:
        ret = "Could not process"

    return ret

def get_el_version(componentVersionOriginId):

    #identify if component is from el7/ el8 release
    el_version = re.findall(r'el[0-9]',componentVersionOriginId)

    if 'el7' in el_version:
        return 'Red Hat Enterprise Linux 7'
    elif 'el8' in el_version:
        return 'Red Hat Enterprise Linux 8'
    elif 'el6' in el_version:
        return 'Red Hat Enterprise Linux 6'

def get_rhsa_opinion(cve_id, componentVersionOriginId):
    #return print_msg_box(cve_id + "  -->  " + componentVersionOriginId)
    
    redhat_errata = 'https://access.redhat.com/security/cve/'+ cve_id + '.json'

    redhat_api = 'https://access.redhat.com/hydra/rest/securitydata/cve/' + cve_id + '.json'
    redhat_resp = requests.get(redhat_api, headers={}, verify=False).json()
    fix_state = ''

    el_version = get_el_version(componentVersionOriginId)
    
    if "affected_release" in redhat_resp.keys():
        for item in redhat_resp['affected_release']:
            if item['product_name'] == el_version:
                pkg_name = item['package'].split('-')[0]
                if pkg_name in componentVersionOriginId:
                    fix_state = 'Released'
                    break
    
    if "package_state" in redhat_resp.keys():
        for item in redhat_resp['package_state']:
            if item['product_name'] == el_version:
                pkg_name = re.split(r'(-|/)',componentVersionOriginId)[0]
                if pkg_name in item['package_name'] or item['package_name'] in pkg_name:
                    fix_state = item['fix_state']
                    break
                else:
                    fix_state = 'Uncertain'
            else:
                fix_state = "Not Listed"
    else: 
        fix_state = "Not Listed"

    return (fix_state, redhat_errata) 

def find_components(args, bearer_token):
    count = 0
    api_url='https://{}/api/projects/{}/versions/{}/vulnerable-bom-components/?limit=2000'.format(args['--instance'],args['--project'],args['--version'])
    resp = requests.get(api_url, headers={'Authorization': 'Bearer '+ bearer_token}, verify=False)
    items = resp.json()

    for r in items['items']:
        if r['vulnerabilityWithRemediation']['source'] == "NVD" and r['vulnerabilityWithRemediation']['remediationStatus'] == "NEW" and r["componentVersionOriginName"] in ["centos","redhat"]:
            #print(r['componentVersionOriginId'] + ',' + r['vulnerabilityWithRemediation']['vulnerabilityName'])
            count +=1
            cve_id = r['vulnerabilityWithRemediation']['vulnerabilityName']
            componentVersionOriginId = r['componentVersionOriginId']
            for i in r['_meta']['links']:
                if i['rel'] == 'vulnerabilities':
                    component_id=i['href'].split('/')[4:6][1]
                    version_id=i['href'].split('/')[7:9][0]
                    origin_id=i['href'].split('/')[9:10][0]

                    message = get_rhsa_opinion(cve_id, componentVersionOriginId)
                    state = update_hub_vuln(args, bearer_token, component_id, version_id, origin_id, cve_id, message)
                    
                    print(componentVersionOriginId," --> ",state)

    return count

def run(args):
    """ Main Method """
    
    bearer_token = authenticate(args)

    if bearer_token != None:
        print_msg_box('Authentication: {} '.format("Successful") + 
        '\nFound Project: {}'.format(args['--project'] +
        '\nFound Version: {}'.format(args['--version'])))
        print("\n\nProcessing BOM Components....\n\n")
        count = find_components(args, bearer_token)

    print_msg_box("Components Processed = {}".format(count)+"\n\nProcess Complete!")

if __name__ == '__main__':

    args = docopt(__doc__)
    run(args)
