#!/usr/bin/env python3
# File: firemon_assessment_export.py
# Description: Script to export rules failures against a specific assessment and device to CSV

import sys
# Adding FireMon package path
sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.8/site-packages')
try:
    import requests
    import zipfile
    import os
    import xml.etree.ElementTree as ET
    import re
    import csv
    from getpass import getpass
except ImportError:
    try:
        sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.9/site-packages')
        import requests
        import zipfile
        import os
        import xml.etree.ElementTree as ET
        import re
        import csv
        from getpass import getpass
    except ImportError:
        try:
            sys.path.append('/usr/lib/firemon/devpackfw/lib/python3.10/site-packages')
            import requests
            import zipfile
            import os
            import xml.etree.ElementTree as ET
            import re
            import csv
            from getpass import getpass
        except ImportError:
            import requests
            import zipfile
            import os
            import xml.etree.ElementTree as ET
            import re
            import csv
            from getpass import getpass

import argparse
import json
import sys
import logging
from urllib.parse import quote

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_auth_session(base_url, username, password, verify_ssl=True):
    """
    Create an authenticated session with FireMon API
    
    Args:
        base_url (str): Base URL for FireMon API
        username (str): Username for authentication
        password (str): Password for authentication
        verify_ssl (bool): Whether to verify SSL certificates
        
    Returns:
        requests.Session: Authenticated session
    """
    # Build base API URL
    api_url = f"{base_url}/securitymanager/api"
    
    # Create session
    session = requests.Session()
    session.auth = (username, password)
    session.headers = {'Content-Type': 'application/json', 'accept': 'application/json'}
    
    # Authenticate
    logon_data = {
        "username": username,
        "password": password
    }
    json_logon_data = json.dumps(logon_data)
    
    try:
        logger.info(f"Authenticating to {api_url}/authentication/validate")
        verify_auth = session.post(
            f'{api_url}/authentication/validate', 
            data=json_logon_data, 
            verify=verify_ssl
        )
        
        if verify_auth.status_code != 200:
            logger.error(f"Authentication failed with status code: {verify_auth.status_code}")
            logger.error(f"Response: {verify_auth.text}")
            return None
        
        auth_data = verify_auth.json()
        auth_status = auth_data.get('authStatus')
        
        if auth_status != 'AUTHORIZED':
            logger.error(f"Authentication failed: {auth_status}")
            return None
        
        logger.info(f"Successfully authenticated as {username}")
        return session
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during authentication: {e}")
        return None

def get_failed_rules(base_url, session, device_id, assessment_uuid, verify_ssl=True, page=0, page_size=100):
    """
    Get list of rules with failed controls for specific device and assessment
    
    Args:
        base_url (str): Base URL for FireMon API
        session (requests.Session): Authenticated session
        device_id (int): Device ID
        assessment_uuid (str): Assessment UUID
        verify_ssl (bool): Whether to verify SSL certificates
        page (int): Page number for pagination
        page_size (int): Page size for pagination
        
    Returns:
        list: List of rules with failed controls
    """
    # Query to find rules with failed controls - using the correct format
    query = f"domain{{id=1}} and device{{id={device_id}}} and assessment{{id='{assessment_uuid}'}} and control{{status='FAIL'}}"
    encoded_query = quote(query)
    
    url = f"{base_url}/securitymanager/api/siql/secrule/paged-search?q={encoded_query}&page={page}&pageSize={page_size}"
    
    logger.info(f"Requesting rules from: {url}")
    
    try:
        all_results = []
        
        # Initial request
        response = session.get(url, verify=verify_ssl)
        
        if response.status_code != 200:
            logger.error(f"Failed to get rules. Status code: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return []
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            logger.error("Failed to parse response as JSON")
            logger.error(f"Response content: {response.text}")
            return []
        
        total_results = data.get("total", 0)
        all_results.extend(data.get("results", []))
        
        # If there are more pages, get them
        if total_results > page_size:
            total_pages = (total_results + page_size - 1) // page_size
            logger.info(f"Found {total_results} results, retrieving {total_pages} pages")
            
            for page_num in range(1, total_pages):
                page_url = f"{base_url}/securitymanager/api/siql/secrule/paged-search?q={encoded_query}&page={page_num}&pageSize={page_size}"
                logger.debug(f"Getting page {page_num} from {page_url}")
                page_response = session.get(page_url, verify=verify_ssl)
                
                if page_response.status_code != 200:
                    logger.error(f"Failed to get page {page_num}. Status code: {page_response.status_code}")
                    continue
                
                page_data = page_response.json()
                all_results.extend(page_data.get("results", []))
        
        logger.info(f"Found {len(all_results)} rules with failed controls")
        return all_results
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting failed rules: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response status code: {e.response.status_code}")
            logger.error(f"Response content: {e.response.text}")
        return []

def get_rule_control_violations(base_url, session, device_id, assessment_uuid, rule_uid, verify_ssl=True, page=0, page_size=100):
    """
    Get control violations for a specific rule
    
    Args:
        base_url (str): Base URL for FireMon API
        session (requests.Session): Authenticated session
        device_id (int): Device ID
        assessment_uuid (str): Assessment UUID
        rule_uid (str): Rule UID
        verify_ssl (bool): Whether to verify SSL certificates
        page (int): Page number for pagination
        page_size (int): Page size for pagination
        
    Returns:
        list: List of control violations for the rule
    """
    # Query to find control violations for a specific rule
    query = f"device {{ id = {device_id} }} AND assessment {{ id = '{assessment_uuid}' }} AND control {{ status = 'FAIL' }} AND rule {{ uid = '{rule_uid}' }}"
    encoded_query = quote(query)
    
    url = f"{base_url}/securitymanager/api/siql/control/paged-search?q={encoded_query}&page={page}&pageSize={page_size}&sortdir=asc&sort=name&sort=-enddate&sort=devicename"
    
    try:
        all_results = []
        
        # Initial request
        response = session.get(url, verify=verify_ssl)
        
        if response.status_code != 200:
            logger.error(f"Failed to get control violations. Status code: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return []
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            logger.error("Failed to parse response as JSON")
            logger.error(f"Response content: {response.text}")
            return []
        
        total_results = data.get("total", 0)
        all_results.extend(data.get("results", []))
        
        # If there are more pages, get them
        if total_results > page_size:
            total_pages = (total_results + page_size - 1) // page_size
            
            for page_num in range(1, total_pages):
                page_url = f"{base_url}/securitymanager/api/siql/control/paged-search?q={encoded_query}&page={page_num}&pageSize={page_size}&sortdir=asc&sort=name&sort=-enddate&sort=devicename"
                page_response = session.get(page_url, verify=verify_ssl)
                
                if page_response.status_code != 200:
                    logger.error(f"Failed to get control violations page {page_num}. Status code: {page_response.status_code}")
                    continue
                
                page_data = page_response.json()
                all_results.extend(page_data.get("results", []))
        
        return all_results
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting control violations for rule {rule_uid}: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response status code: {e.response.status_code}")
            logger.error(f"Response content: {e.response.text}")
        return []

def format_network_objects(objects):
    """
    Format network objects into a readable string with IP addresses
    
    Args:
        objects (list): List of network objects
        
    Returns:
        str: Formatted string of network objects with IP addresses
    """
    if not objects:
        return ""
    
    result = []
    for obj in objects:
        display_name = obj.get("displayName", "")
        
        # Get IP addresses if available
        addresses = obj.get("addresses", [])
        address_str = ""
        if addresses:
            address_values = []
            for addr in addresses:
                if addr.get("address"):
                    address_values.append(addr.get("address"))
            if address_values:
                address_str = f" ({', '.join(address_values)})"
        
        result.append(f"{display_name}{address_str}")
    
    return ", ".join(result)

def format_service_objects(objects):
    """
    Format service objects into a readable string with protocol/port
    
    Args:
        objects (list): List of service objects
        
    Returns:
        str: Formatted string of service objects with protocol/port
    """
    if not objects:
        return ""
    
    result = []
    for obj in objects:
        display_name = obj.get("displayName", "")
        
        # Get service details if available
        services = obj.get("services", [])
        service_str = ""
        if services:
            service_values = []
            for svc in services:
                if svc.get("formattedValue"):
                    service_values.append(svc.get("formattedValue"))
                elif svc.get("protocol") is not None and svc.get("startPort") is not None:
                    protocol = "tcp" if svc.get("protocol") == 6 else "udp" if svc.get("protocol") == 17 else str(svc.get("protocol"))
                    ports = str(svc.get("startPort"))
                    if svc.get("endPort") and svc.get("endPort") != svc.get("startPort"):
                        ports += f"-{svc.get('endPort')}"
                    service_values.append(f"{protocol}/{ports}")
            if service_values:
                service_str = f" ({', '.join(service_values)})"
        
        result.append(f"{display_name}{service_str}")
    
    return ", ".join(result)

def export_to_csv(rules_with_controls, output_file):
    """
    Export rules with control violations to CSV
    
    Args:
        rules_with_controls (list): List of rules with control violations
        output_file (str): Output CSV file path
    """
    # Define CSV headers - removed "Rule Section"
    headers = [
        "Rule Name", 
        "Rule Number", 
        "Cumulative Rule Severity",
        "Policy Name",
        "Sources",
        "Destinations",
        "Services",
        "Users",
        "Apps",
        "Profiles",
        "URL Matchers",
        "Action",
        "Control Name",
        "Control Description",
        "Control Severity",
        "Control Code"
    ]
    
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            for rule in rules_with_controls:
                rule_data = rule.get("rule", {})
                controls = rule.get("controls", [])
                
                # Basic rule information - removed rule_section
                rule_name = rule_data.get("ruleName", "")
                rule_number = rule_data.get("ruleNumber", "")
                rule_severity = rule_data.get("cumulativeRuleSeverity", "")
                policy_name = rule_data.get("policy", {}).get("displayName", "")
                
                # Network objects with detailed information
                sources = format_network_objects(rule_data.get("sources", []))
                destinations = format_network_objects(rule_data.get("destinations", []))
                services = format_service_objects(rule_data.get("services", []))
                users = format_network_objects(rule_data.get("users", []))
                apps = format_network_objects(rule_data.get("apps", []))
                profiles = format_network_objects(rule_data.get("profiles", []))
                url_matchers = format_network_objects(rule_data.get("urlMatchers", []))
                
                # Action
                action = rule_data.get("ruleAction", "")
                
                # Write each control as a separate row
                if controls:
                    for control in controls:
                        control_name = control.get("name", "")
                        control_description = control.get("description", "")
                        control_severity = control.get("severity", "")
                        control_code = control.get("code", "")
                        
                        row = [
                            rule_name,
                            rule_number,
                            rule_severity,
                            policy_name,
                            sources,
                            destinations,
                            services,
                            users,
                            apps,
                            profiles,
                            url_matchers,
                            action,
                            control_name,
                            control_description,
                            control_severity,
                            control_code
                        ]
                        
                        writer.writerow(row)
                else:
                    # If no controls, write a row with just rule information
                    row = [
                        rule_name,
                        rule_number,
                        rule_severity,
                        policy_name,
                        sources,
                        destinations,
                        services,
                        users,
                        apps,
                        profiles,
                        url_matchers,
                        action,
                        "", "", "", ""  # Empty control information
                    ]
                    
                    writer.writerow(row)
        
        logger.info(f"Successfully exported data to {output_file}")
    
    except Exception as e:
        logger.error(f"Error exporting to CSV: {e}")

def main():
    parser = argparse.ArgumentParser(description='Export FireMon assessment rule failures to CSV')
    parser.add_argument('-u', '--url', required=True, help='FireMon base URL (e.g., https://demo01.firemon.xyz)')
    parser.add_argument('-n', '--username', required=True, help='FireMon username')
    parser.add_argument('-p', '--password', required=True, help='FireMon password')
    parser.add_argument('-d', '--device-id', required=True, type=int, help='Device ID')
    parser.add_argument('-a', '--assessment', required=True, help='Assessment UUID')
    parser.add_argument('-o', '--output', required=True, help='Output CSV file path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose debug output')
    parser.add_argument('--no-verify', action='store_true', help='Disable SSL certificate verification')
    
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # SSL verification setting
    verify_ssl = not args.no_verify
    if not verify_ssl:
        logger.warning("SSL certificate verification is disabled")
        # Suppress InsecureRequestWarning
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Get authenticated session
    session = get_auth_session(args.url, args.username, args.password, verify_ssl)
    if not session:
        logger.error("Failed to create authenticated session. Exiting.")
        sys.exit(1)
    
    # Get rules with failed controls
    failed_rules = get_failed_rules(args.url, session, args.device_id, args.assessment, verify_ssl)
    if not failed_rules:
        logger.warning("No rules with failed controls found. Exiting.")
        sys.exit(0)
    
    # Get control violations for each rule and combine the data
    rules_with_controls = []
    
    for rule in failed_rules:
        rule_uid = rule.get("matchId")
        if rule_uid:
            logger.info(f"Getting control violations for rule: {rule.get('ruleName', rule_uid)}")
            control_violations = get_rule_control_violations(
                args.url, session, args.device_id, args.assessment, rule_uid, verify_ssl
            )
            
            rules_with_controls.append({
                "rule": rule,
                "controls": control_violations
            })
    
    # Export to CSV
    export_to_csv(rules_with_controls, args.output)

if __name__ == "__main__":
    main()