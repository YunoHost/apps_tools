"""
Checks against NIST and EUVD databases for vulnerabilities impacting Yunohost app catalog

* Install dependencies: pip install -r requirements.txt
* Execution time: depends on API rate limitation, so count ~between 2 and 7 seconds per app
* Environment variables: NIST_API_KEY (optional)

"""
# Bundled imports
import argparse
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib3.util import Retry

# External modules
import requests                                             #pip install requests
from requests.adapters import HTTPAdapter                   #pip install requests
import tomlkit                                              #pip install tomlkit
import toml                                                 #pip install toml
import tqdm                                                 #pip install tqdm
from git import Repo                                        #pip install GitPython


# External local file
sys.path.insert(0, str(Path(__file__).parent.parent))       # Add 'apps_tools' parent folder to sys.path to allow its access by the script
import appslib.get_apps_repo as get_apps_repo               #../appslib/get_apps_repo.py
from appslib.utils import get_catalog, get_security, set_apps_path         #../appslib/utils.py

## Global vars
TOOLS_DIR = Path(__file__).resolve().parent.parent          #/path/to/apps_tools (for github token)
YNH_APPS = 'https://raw.githubusercontent.com/YunoHost/apps/refs/heads/main/apps.toml' #URL for YNH last apps catalog
YNH_APPS_SECURITY = 'https://raw.githubusercontent.com/YunoHost/apps/refs/heads/main/security.toml' #URL for YNH last security.toml
GITHUB_API_BASE = 'https://api.github.com/repos/'
NIST_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0/'
NIST_API_KEY = os.environ.get('NIST_API_KEY', '')           #pass API key as env variable. API key is optional but speeds up API access rate by 6x, cf. https://nvd.nist.gov/developers/request-an-api-key
EUVD_API_BASE = 'https://euvdservices.enisa.europa.eu/api/search'
SEVERITY_TARGET = ['medium', 'high', 'critical']            # can be 'none', 'low', 'medium', 'high' or 'critical'


def adjust_from_date(expected_from_date: datetime, to_date: str) -> datetime:
    """
    NIST expects ISO_8601 date with a maximum of 120 days between from_date
    and to_date

    Args:
        expected_from_date (datetime): expected date that will be checked and changed if the gap with to_date is more than 120 days
        to_date (str)
    """

    from_date_obj = expected_from_date
    to_date_obj = datetime.fromisoformat(to_date)

    delta = to_date_obj - from_date_obj
    days_between = delta.days
    if days_between > 120:
        gap = days_between - 119 #the period queried will be of 119 days, as some errors have been sometimes encountered with a value of 120...
        from_date_obj = from_date_obj + timedelta(days=gap)

    return from_date_obj


def api_get(url: str, params: dict = {}, headers: dict = {}) -> dict | None:
    """
    API call, retries and error management
    Inspired by https://github.com/joshbressers/cve-analysis/blob/ed00173d3f09608593b51cf3ca11208f1952eab4/get-euvd-json-date.py#L18-L45 (under GPL 3.0)

    Args:
        url (str): chosen API's base URL
        params (dict): dictionnary of allowed parameters (cf. chosen API's documentation)
        headers (dict): dictionnary of HTTP headers' values (cf. https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers)
    """

    # Define a retry strategy
    retry_strategy = Retry(
        total=10,                                    #Maximum number of retries
        backoff_factor=6,                            #Delay between retries
        status_forcelist=[429, 500, 502, 503, 504],  #HTTP status codes to retry on
    )

    # Create an HTTP adapter with the retry strategy and mount it to session
    adapter = HTTPAdapter(max_retries=retry_strategy)

    # Create a new session object
    session = requests.Session()
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    # Make request call
    try:
        response = session.get(url, params=params, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            error_msg = 'API ' + str(response.status_code) + ' error on \'' + url + '\': ' + response.headers['message']
            logging.critical(error_msg)
            print(error_msg)
            logging.debug(response.text)
            logging.debug(response.headers)
            return None

    except requests.exceptions.RequestException as e:
        error_msg = 'API ' + str(e) + ' error on \'' + url + '\''
        logging.critical(error_msg)
        print(error_msg)
        return None


def call_nist(app_name: str, cpe: str, from_date: str, to_date: str) -> list:
    """
    Retrieve vulnerabilites from the US NIST database (historical actor),
    filter them and return a list of dictionnaries in the format of YNH's
    security.toml.

    Args:
        app_name (str): YNH app id
        cpe (str): NIST CPE with 'virtualMatchString' format (e.g.: 'cpe:2.3:a:nextcloud:nextcloud')
        from_date (str): ISO_8601 start period date
        to_date (str): ISO_8601 end period date

    Gap between from_date and to_date should not exceed 120 days.

    API Rate limit:
    - 5 requests/rolling 30 second window without API key
    - 50 requests/rolling   30 second window with API key
    It is still recommended that your application sleeps for several seconds
    between requests so that legitimate requests are not denied,
    and all requests are responded to in sequence.

    API key: https://nvd.nist.gov/developers/request-an-api-key
    API properties: https://nvd.nist.gov/developers/vulnerabilities
    """

    # Define missing variables
    start_index = 0

    # Define HTTP headers & API rate limiting
    headers = { 'User-Agent': 'curl/7.54.1' }
    if NIST_API_KEY:
        headers.update({ 'apiKey': NIST_API_KEY })
        api_rate_limit = 1
    else:
        api_rate_limit = 6

    # Call API & loop through pagination
    nist_vulnerabilities = []
    while True:

        # Define query parameters
        params = {
                    'virtualMatchString': cpe,
                    'pubStartDate':       from_date,
                    'pubEndDate':         to_date,
                    'startIndex':         start_index,
               }

        # Slow down as per API rate limiting
        time.sleep(api_rate_limit)

        # Make request call
        response = api_get(NIST_API_BASE, params, headers)
        if response is None:
            exit() #api_get() already manages retries so there is an issue, no need to continue
        nist_vulnerabilities.extend(response['vulnerabilities'])

        # Manage pagination for while loop
        start_index = start_index + response['resultsPerPage']
        total_results = response['totalResults']
        if start_index >= total_results:
            break

    # Parse response
    nist_vulnerabilities_formatted = []
    for nist_vulnerability in nist_vulnerabilities:
        cve = nist_vulnerability['cve']

        # ID
        vuln_id = cve['id'] #e.g. 'CVE-2023-37401'

        # Publication date
        pub_date = cve['published'].split('T', 1)[0] #%Y-%m-%d format

        # Modification date (initially publication date, and then later if edited further)
        # @TODO update vulnerability entries in security.toml if new info or consider only newly published CVEs ?
        # ~ modif_date = cve['lastModified'].split('T', 1)[0] #%Y-%m-%d format

        # Status
        status = cve['vulnStatus'] #cf. statuses list: https://nvd.nist.gov/vuln/vulnerability-status#divNvdStatus

        # Description
        description_lang = ['en', 'fr'] #Priorize English description, but also accept French one.
        description = ''
        for desc in cve['descriptions']:
            if desc['lang'] in description_lang:
                description = desc['value']
                break

        # Severity
        metric_versions = ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV20']
        severity_text = ''
        for version in metric_versions: #Use latest available metrics only
            if cve['metrics'].get(version) == None:
                continue
            else:
                severity_text = cve['metrics'][version][0]['cvssData']['baseSeverity'].lower()
                break

        # Filter out vulnerability reports not yet analyzed (i.e. that may not have CPE nor CVSS) and outside of severity target
        if status != 'Analyzed' and severity_text not in SEVERITY_TARGET:
			continue

		# More infos link
		nist_link = 'https://nvd.nist.gov/vuln/detail/' + vuln_id
		references = cve['references']
		urls = [nist_link]
		for ref in references:
			if 'url' in ref:
				urls.append(ref['url'])

		#Versions impacted
		started_with_version = ''
		fixed_in_version = ''
		configurations = cve['configurations']
		for config in configurations:
			for node in config['nodes']:
				cpe_matches = node['cpeMatch']
				for cpe_match in cpe_matches:
					cpe_criteria = cpe_match['criteria'].split(':')
					del cpe_criteria[5:len(cpe_criteria)] #keep only 5 first elements of CPE
					cpe_criteria = ':'.join(cpe_criteria) #e.g. cpe:2.3:a:lynxtechnology:twonky_server
					if cpe_criteria == cpe:
						if 'versionStartIncluding' in cpe_match:
							started_with_version = cpe_match['versionStartIncluding']
						if 'versionEndExcluding' in cpe_match:
							fixed_in_version = cpe_match['versionEndExcluding']

		# Generate YNH_APPS_SECURITY entry
		ynh_app_vulnerability = generate_vulnerability_dict(
															app_name,
															vuln_id,
															pub_date,
															description,
															severity_text,
															urls,
															started_with_version,
															fixed_in_version,
															'danger',
															'nist'
															)

		nist_vulnerabilities_formatted.append(ynh_app_vulnerability)

    return nist_vulnerabilities_formatted


def call_euvd(app_name: str, app_cpe: str | None, from_date: str, to_date: str) -> list:
    """
    Retrieve vulnerabilites from the European Union Vulnerabilites Database
    (initiated in 2025) filtered by severity and return a list of dictionnaries
    in the format of YNH's security.toml.

    Args:
        app_name (str): YNH app id
        app_cpe (str): NIST CPE with 'virtualMatchString' format (e.g.: 'cpe:2.3:a:nextcloud:nextcloud')
        from_date (str): start period date (%Y-%m-%d)
        to_date (str): end period date (%Y-%m-%d)

    API properties: https://euvd.enisa.europa.eu/apidoc
    """

    # Define missing variables
    vendor = ''
    product = app_name
    if app_cpe:
        cpe_compounds = app_cpe.split(':') #cf. https://en.wikipedia.org/wiki/Common_Platform_Enumeration#Scheme_format
        cpe_version = cpe_compounds[1]
        if cpe_version == '2.3':
            vendor = cpe_compounds[3]
            product = cpe_compounds[4]
    page = 0
    api_rate_limit = 1 #there is theoretically no API rate limit on EUVD for now, but let's be patient to avoid errors.

    # Define HTTP headers
    headers = { 'User-Agent': 'curl/7.54.1' }

    # Call API & loop through pagination
    euvd_vulnerabilities = []
    while True:

        # Define query parameters
        params = {
                'fromScore':    convert_severity(SEVERITY_TARGET[0].lower(), 'low_bound'),
                'toScore':      convert_severity(SEVERITY_TARGET[len(SEVERITY_TARGET) - 1].lower(), 'high_bound'),
               #'fromEpss':     '', #0-1 (probability), if EPSS is used later
               #'toEpss':       '', #0-1 (probability), if EPSS is used later
                'fromDate':     from_date,
                'toDate':       to_date,
                'vendor':       vendor,
                'product':      product,
                'page':         page,
                'size':         100
           }

        # Slow down as per API rate limiting
        time.sleep(api_rate_limit)

        # Make request call
        response = api_get(EUVD_API_BASE, params, headers)
        if response is None:
            exit() #api_get() already manages retries so there is an issue, no need to continue
        euvd_vulnerabilities.extend(response['items'])

        # Manage pagination for while loop
        total_entries = response['total']
        if len(euvd_vulnerabilities) >= total_entries:
            break
        page += 1

    euvd_vulnerabilities_formatted = []
    for euvd_vulnerability in euvd_vulnerabilities:

        # Prefer CVE as ID for consistency with NIST, but use EUVD ID if there is no.
        if 'CVE-' in euvd_vulnerability['aliases']:
            aliases = euvd_vulnerability['aliases']
            pattern = r"CVE-\d{4}-\d*"
            found = re.findall(pattern, aliases)
            vuln_id = found[0] #e.g. 'CVE-2023-37401'
        else:
            vuln_id = euvd_vulnerability['id'] #e.g. 'EUVD-2025-202425'

        # Publication date
        pub_date = euvd_vulnerability['datePublished']  #e.g. 'Dec 10, 2025, 3:31:24 PM'
        pub_date = datetime.strptime(pub_date, '%b %d, %Y, %I:%M:%S %p').strftime('%Y-%m-%d') #%Y-%m-%d

        # Modification date
        # @TODO update vulnerability entries in security.toml if new info or consider only newly published CVEs ?
        # ~ modif_date = euvd_vulnerability['dateUpdated'] #e.g. 'Dec 18, 2025, 1:00:21 AM'
        # ~ modif_date = datetime.strptime(modif_date, '%b %d, %Y, %I:%M:%S %p').strftime('%Y-%m-%d') #%Y-%m-%d

        # Description
        description = euvd_vulnerability['description']

        # Severity
        severity_score = euvd_vulnerability['baseScore']
        severity_text = convert_severity(severity_score, 'text')
        #exploitability = euvd_vulnerability['epss'] #if EPSS is used later

        # More infos link
        euvd_link = 'https://euvd.enisa.europa.eu/vulnerability/' + euvd_vulnerability['id']
        references = euvd_vulnerability['references'].split('\n')
        references.insert(0, euvd_link)

        #Versions impacted
        started_with_version = ''
        fixed_in_version = ''
        products_versions = euvd_vulnerability['enisaIdProduct']
        for prod in products_versions: #if there are several 'prod' value with matching product names and information about product versions (e.g. https://euvd.enisa.europa.eu/vulnerability/EUVD-2025-202425), then only the last entry will be saved.
            if 'name' in prod['product'] and prod['product']['name'] == product:
                to_version_operators = ['≤', '<=', '<']
                for op in to_version_operators:
                    if op in prod['product_version']: #e.g. "0 ≤0.13.3", or "< 0.13.3", or other variations
                        split_versions = prod['product_version'].split(op)
                        if len(split_versions) == 2 and split_versions[0]:
                            started_with_version = split_versions[0].strip()
                            if op == '<': #'0 ≤ 0.13.3' means all versions up to 0.13.3 are vulnerable, but '0 < 0.13.3' means all versions excluding 0.13.3 are vulnerables (i.e. indicates a fixed version)
                                fixed_in_version = split_versions[1].strip()
                            break
                        else:
                            if not split_versions[0].strip():
                                del split_versions[0] #remove empty value so that only one value remains in the list
                            if op == '<':
                                fixed_in_version = split_versions[0].strip()
                            else:
                                started_with_version = split_versions[0].strip()
                            break

                    else: #no operator, probably just a version number, e.g. '0.13.3'
                        started_with_version = prod['product_version'].strip()

        # Generate YNH_APPS_SECURITY entry
        ynh_app_vulnerability = generate_vulnerability_dict(
                                                            app_name,
                                                            vuln_id,
                                                            pub_date,
                                                            description,
                                                            severity_text,
                                                            references,
                                                            started_with_version,
                                                            fixed_in_version,
                                                            'danger',
                                                            'euvd'
                                                            )
        euvd_vulnerabilities_formatted.append(ynh_app_vulnerability)

    return euvd_vulnerabilities_formatted


# ~ def call_first():
    # ~ """
        # ~ Get exploitability (EPSS) score for CVEs

        # ~ API rate limitation: 1000 requests/minute
        # ~ https://api.first.org/
    # ~ """
    # @TODO ? Could help to narrow vulnerability filtering:
    #   * Filter out low-risk vulnerabilities with high CVSS but low EPSS
    #   * Prioritize high-risk vulnerabilities with moderate CVSS but high EPSS
    #
    # EPSS score is already provided in EUVD DB responses, but not in NIST responses.


def check_app_security(cache_path: Path, app_name: str, app_url: str, from_date_source: dict, current_number: int, total_number: int) -> list:
    """
    For a given app, loads manifest, calls databases, and returns a list of app
        vulnerabilities in the format required for 'security.toml'.

    Args:
        app_name (str): app name without '_ynh' suffix
        app_url (str): URL of the github repo of the YNH package
        from_date_source (dict): dict containing the dates of the last vulnerabilities added security.toml
            for each source database
    """

    # Load app manifest from cache
    logging.info('(' + str(current_number) + '/' + str(total_number) + ') Loading "' + app_name + '_ynh"\'s manifest...')
    try:
        manifest_toml = cache_path / app_name / 'manifest.toml'
        if manifest_toml.exists():
            app_manifest = tomlkit.load(manifest_toml.open('r', encoding='utf-8'))
        else:
            logging.warning('No manifest.toml file found in ' + app_name + '\'s repository.')
            return []
    except Exception as e:
        logging.error('Error while loading' + app_name + '\'s manifest: {e}')
        return []

    # Find CPE
    if 'cpe' in app_manifest['upstream'] and re.match(r'^cpe:2.3:[a-z]:[a-z0-9]*:[a-z0-9]*$', app_manifest['upstream']['cpe']): # valid expected CPE format = 'cpe:2.3:a:nextcloud:nextcloud'
        app_cpe = app_manifest['upstream']['cpe']
    else:
        app_cpe = None
        logging.info('No valid CPE declared for ' + app_name + '.')

    # Call databases via API
    logging.info('Retrieving new vulnerabilities in ' + app_name + '...')
    app_vulnerabilities = []
    to_date = datetime.now().isoformat() #ISO 8601

    nist_response = []
    if app_cpe:
        from_date = adjust_from_date(from_date_source['nist'], to_date).isoformat() #ISO 8601
        logging.debug('Querying NIST NVD database...')
        nist_response = call_nist(app_name, app_cpe, from_date, to_date)
    app_vulnerabilities.extend(nist_response)

    euvd_response = []
    to_date = to_date.split('T')[0] #%Y-%m-%d
    from_date = from_date_source['euvd'].strftime('%Y-%m-%d') #%Y-%m-%d
    logging.debug('Querying EUVD database...')
    euvd_response = call_euvd(app_name, app_cpe, from_date, to_date)
    if euvd_response:
        if app_cpe:
            app_vulnerabilities.extend(euvd_response)
        else:
            # Not appending results to app_vulnerabilties because if no app_cpe, search by product (proxied as app_name)
            #   without vendor on EUVD DB does not match exact word. Thus searching for 'element' would bring results such as
            #   'Elementor', 'Photoshop Elements', ... i.e. potentially a lot of false positives if app_name is a common word.
            logging.warning('Found results at EUVD for ' + app_name + ' although it has no declared CPE' +
              ' so they could be false positives. Please check for this app CPE at https://nvd.nist.gov/products/cpe/search' +
              ' and add it to the app manifest, so that results are taken into account during the next run.')
            # @TODO? Looking for CPE programatically is difficult due to the lack of identifying info about the app & vendor.
            #    Using only app_id in a keyword search at NIST CPE API will most likely bring many false postive in many cases.
            #    Cf. https://nvd.nist.gov/developers/products

    return app_vulnerabilities #at this point there could be duplicates (typically in case it retrieved the same vulnerability both from NIST & EUVD databases)


def convert_severity(value: str | int | float, return_format: str) -> str | int | float:
    """
    Convert severity from value to text or vice-versa.

    Args:
        value (str,int,float): severity value in text or number
        return_format (str): can be 'low_bound', 'high_bound' or 'text'
    """

    # CVSS v3.x and v4.0 ratings, cf. https://nvd.nist.gov/vuln-metrics/cvss
    severity_thresholds = {
                            'none':      { 'from': 0,   'to':  0   },
                            'low' :      { 'from': 0.1, 'to':  3.9 },
                            'medium':    { 'from': 4,   'to':  6.9 },
                            'high':      { 'from': 7,   'to':  8.9 },
                            'critical':  { 'from': 9,   'to': 10   }
                          }

    def get_severity_text(severity_score):
        for severity_text, thresholds in severity_thresholds.items():
            if thresholds['from'] <= severity_score <= thresholds['to']:
                return severity_text
        logging.debug('Error: Supplied severity float value does not fit in CVSS classification\'s bounds.')
        return ''

    def get_severity_score(severity_text, bound):
        if bound == 'low_bound':
            severity_score = severity_thresholds[severity_text]['from']
        else:
            severity_score = severity_thresholds[severity_text]['to']
        return severity_score

    if return_format in ['low_bound', 'high_bound']:
        if value in severity_thresholds.keys(): #text value
            severity_score = get_severity_score(value, return_format)
            return severity_score
        elif isinstance(value, (int,float)):
            severity_text = get_severity_text(value)
            severity_score = get_severity_score(severity_text, return_format)
            return severity_score
        else:
            logging.debug('Error: Supplied text value does not match known classification.')

    if return_format == 'text':
        if isinstance(value, (int,float)):
            severity_text = get_severity_text(value)
            return severity_text
        else:
            logging.debug('Error: Numeric value expected.')

    return '' #error case


def generate_vulnerability_dict(
                                app_id: str,
                                vuln_id: str,
                                date: str,
                                description: str,
                                severity: str | int | float,
                                more_infos: list,
                                started_with_version: str | int | float,
                                fixed_in_version: str | int | float,
                                level: str,
                                source: str
                                ) -> dict:
    """
    Create an entry matching "security.toml"'s data structure, e.g.:

    [apps]
        [apps.gogs]
            [apps.gogs.cve-2025-00000]
            date = "2025-12-16"
            title = "Gogs / HIGH - CVE-2025-00000 - Vulnerability description blah blah blah"
            more_infos = [
                "https://nvd.nist.gov/vuln/detail/CVE-2025-00000",
                "https://github.com/owner/app/issues/55"
            ]
            started_with_version = ""
            fixed_in_version = ""
            level = "danger"
            source = "nist"
    """

    if len(description) > 80:
        description = description[0:80] + '...'

    title = ( app_id.title() + ' / ' +
              severity.upper() + ' - ' +
              vuln_id + ' - ' +
              description )

    vulnerability = {
                      'date': date,
                      'title': title,
                      'more_infos': more_infos,
                      'started_with_version': started_with_version,
                      'fixed_in_version': fixed_in_version,
                      'level': level, # @TODO: How do we set risk gradation? Is there any point to listing low risk vulneratiblities? Do we want to take into account EPSS classification?
                      'source': source
                    }

    return vulnerability


def github_token() -> str | None:
    """
    Borrowed from https://github.com/YunoHost/apps_tools/blob/083361f4fd13b1faf36fcbc2ebd55db64562fc1e/update_app_levels/update_app_levels.py#L33
    """
    github_token_path = TOOLS_DIR / ".github_token"
    if github_token_path.exists():
        return github_token_path.open("r", encoding="utf-8").read().strip()
    return None


def last_security_report_date(source: str, security: dict) -> datetime:
    """
    Return the latest date in the security list for a given source to serve as
    the initial date for a new check

    Args:
        source (str): 'nist', 'euvd' or 'other'
        security (dict): data loaded from security.toml (dictionnary of lists of one dictionnary)
    """
    latest_date = datetime.strptime('2025-01-01', '%Y-%m-%d') #arbitrary value used as start date if nothing is found in the list

    for app in security.values():
        for report in app.values():
            if report['source'] == source: #assuming descending order of the list (latest to oldest), it takes the first matching value
                latest_date = datetime.strptime(report['date'], '%Y-%m-%d') #date obj
                return latest_date
    return latest_date


def indent_tomlkit_nested_tables(item: tomlkit.items.Table, current_level: int = 1, max_level: int = 100, spaces: int = 4 ) -> None:
    """
    Recursively indent tables with increasing spaces based on nesting level.

    Args:
        item (tomlkit.items.Table): values of the first level of the tomlkit document
        current_level (int): current nesting level (1 means indentation starts straight at the level of 'value')
        max_level (int): level after which indentation should not increase further
        spaces (int): indentation size in number of space characters
    """
    if current_level > max_level:
        logging.warning('Cannot indent TOML output properly: start level > max level.')

    indent_size = current_level * spaces
    if isinstance(item, tomlkit.items.Table):
        item.indent(indent_size)
        for value in item.values():
            if isinstance(value, tomlkit.items.Table):
                if current_level < max_level:
                    indent_tomlkit_nested_tables(value, current_level + 1) #recursively increase indent level
                else:
                    value.indent(max_level * spaces) #keep last indent level


def make_pull_request(pr_title: str, pr_body: str, pr_head: str) -> None:
    """
    Borrowed from https://github.com/YunoHost/apps_tools/blob/main/update_app_levels/update_app_levels.py#L169,
     with a few changes in the functions args and in the first 11 lines.

     Args:
        pr_title (str): title for the pull request
        pr_body (str): body text for the pull request
        pr_head (str): head branch name for the pull request
    """
    remote_app_repos = YNH_APPS.split('/')
    remote_app_repos = remote_app_repos[2] + '/' + remote_app_repos[3]

    pr_data = {
        "title": pr_title,
        "body": pr_body,
        "head": pr_head,
        "base": "main",
    }

    with requests.Session() as s:
        s.headers.update({"Authorization": f"token {_github_token()}"})
        response = s.post(
            f"https://api.github.com/repos/{remote_app_repos}/pulls", json=pr_data
        )

        if response.status_code == 422:
            response = s.get(
                f"https://api.github.com/repos/{remote_app_repos}/pulls",
                data={"head": "update_app_levels"},
            )
            response.raise_for_status()
            pr_number = response.json()[0]["number"]

            # head can't be updated
            del pr_data["head"]
            response = s.patch(
                f"https://api.github.com/repos/{remote_app_repos}/pulls/{pr_number}",
                json=pr_data,
            )
            response.raise_for_status()
            existing_url = response.json()["html_url"]
            logging.warning(
                f"An existing Pull Request has been updated at {existing_url} !"
            )
        else:
            response.raise_for_status()

            new_url = response.json()["html_url"]
            logging.info(f"Opened a Pull Request at {new_url} !")


def show_minutes_or_seconds(seconds: int) -> str:

    minutes = round(seconds / 60)
    if minutes > 1:
        time_estimate = str(minutes) + ' minutes'
    else:
        time_estimate = str(round(seconds)) + ' seconds'
    return time_estimate


def main() -> None:
    """
    Wrapper function that retrieves new vulnerabilities for YNH apps from NIST & EUVD databases to upgrade security.toml

    Args: (argparse ones)

    """
    # First measure to determine script execution's length
    start_time = time.time()

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--apps', help='Selected app names delimited by commas (without the "_ynh" suffix) that can be found in the YNH app catalog. Defaults to all catalog apps.', type=str, default='all')
    parser.add_argument('-f', '--from_date', help='Beginning of the search period, e.g. 2025-12-21 (should be less than 120 days from today for NIST). Defaults to the date of the last report in security.toml.', type=str)
    parser.add_argument('-j', '--log_dir', help='Path where to create the log (e.g."path/to/update-vuln.log"). Defaults to current folder.', type=str)
    parser.add_argument('-s', '--show', help='Print the updated security.toml to stdout (default action)', action=argparse.BooleanOptionalAction)
    parser.add_argument('-w', '--write', help='Write the updated security.toml in the script folder', action=argparse.BooleanOptionalAction)
    parser.add_argument('--pr', help='Create a pull request with the updated security.toml (it implies --write)', action=argparse.BooleanOptionalAction)
    parser.add_argument('-v', '--verbose', action=argparse.BooleanOptionalAction)
    get_apps_repo.add_args(parser)
    args = parser.parse_args()

    # Check for mandatory arguments:
    if not args.apps_dir or not Path(args.apps_dir).exists():
        error_msg = 'The APPS_DIR folder cannot be found. Please specify a valid path. Exiting...'
        logging.critical(error_msg)
        exit()

    if not args.apps_cache or not Path(args.apps_cache).exists():
        error_msg = 'The APPS_CACHE folder cannot be found. Please specify a valid path. Exiting...'
        logging.critical(error_msg)
        exit()

    # Enable logging
    if args.log_dir and Path(args.log_dir).parent.is_dir():
        log_dir_path_string = args.log_dir
    else:
        log_dir_path_string = 'update_vuln_db.log' #in the dir where the script is called from (i.e. not necessarily __file__)

    logging.basicConfig(filename=f"{log_dir_path_string}", filemode='w', level=logging.DEBUG)
    logging.getLogger().setLevel(logging.INFO)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    all_vulnerabilities = {}

    # Define cache dir
    cache_path = get_apps_repo.cache_path(args)
    set_apps_path(args.apps_dir)

    # Open YNH app catalog from cache
    logging.info('Loading YNH apps\' catalog...')
    catalog = get_catalog(False) #including non_working_apps

    # Estimate script time of execution (cf. documentation of call_nist())
    selected_apps = [str(app) for app in args.apps.split(',')] #convert delimited string of selected apps into a list
    if 'all' in selected_apps:
        apps_number = len(catalog.keys())
    else:
        apps_number = len(selected_apps)

    # Check there is not mistake in selected apps name
    if not 'all' in selected_apps and not set(selected_apps).issubset(list(catalog.keys())):
        error_msg = 'One or more of the selected apps are not in the catalog. Exiting...'
        logging.critical(error_msg)
        print(error_msg)
        exit()

    logging.info('Starting to check for new vulnerabilities for ' + str(apps_number) + ' apps.')

    if NIST_API_KEY:
        total_time_sec = (1 + 1 + 1) * apps_number # = NIST API + EUVD API + margin based on test
    else:
        total_time_sec = (6 + 1 + 1) * apps_number # = NIST API + EUVD API + margin based on test

    time_estimate = show_minutes_or_seconds(total_time_sec)
    logging.info('Estimated time of execution for this script is ~' + time_estimate + '.')

    # Open initial security.toml from cache
    logging.info('Loading current YNH apps\' vulnerabilities list...')
    security = get_security()
    apps_security = security['apps']

    # Find date of last saved entries from online databases
    if args.from_date:
        from_date_obj = datetime.strptime(args.from_date, '%Y-%m-%d')
        from_date_source = {
                             'nist': from_date_obj,
                             'euvd': from_date_obj,
                           }
    else:
        from_date_source = {
                             'nist': last_security_report_date('nist', apps_security),
                             'euvd': last_security_report_date('euvd', apps_security),
                           }

    # Instantiate a progress bar
    with tqdm.tqdm(total=apps_number, ascii=" ·#") as progress_bar:

        # Lookup vulnerabilities in the online databases
        retrieved_vulnerabilities = {}
        apps_counter = 0
        new_unique_vuln_counter = 0
        for app_name, props in catalog.items():
            # @TODO? Add multiprocessing to this loop - cf. https://github.com/YunoHost/yunohost/blob/dev/src/app_catalog.py#L253-L272

            # Lookup only for app names passed as function argument
            if 'all' in selected_apps or app_name in selected_apps:
                apps_counter += 1
                logging.info('-------------------------------------------------')
                app_url = props['url']
                api_results = check_app_security(cache_path, app_name, app_url, from_date_source, apps_counter, apps_number)
                if api_results:
                    retrieved_vulnerabilities[app_name] = api_results
                progress_bar.update(1) #that's really the loop that's takes 99.7% of exec time, so let it account for 100% on the progress bar
        logging.info('-------------------------------------------------')

        # Add them to the current local databse and generate PR changelog
        pr_changelog = ''
        for app_name, app_retrieved_vulnerabilities in retrieved_vulnerabilities.items():

            # Sort already so that they appear in correct order in the changelog
            app_retrieved_vulnerabilities = sorted(app_retrieved_vulnerabilities, key=lambda vuln: vuln['date'], reverse=True) #by date prop value

            if not app_name in apps_security:
                security['apps'].update({ app_name: {}}) #update the main dict
            app_sec_updated = security['apps'][app_name]

            has_already_printed_vuln = False
            for app_vuln in app_retrieved_vulnerabilities:
                date = app_vuln['date']
                url = app_vuln['more_infos'][0] #NIST or EUVD link
                vuln_id = app_vuln['title'].split(' - ')[1]
                vuln_id_lowercaps = vuln_id.lower()

                # Save new vulnerability only if its ID is not already in current security.toml (key name, e.g. [apps.gogs.cve-2024-56731])
                if vuln_id_lowercaps not in app_sec_updated.keys():
                    new_unique_vuln_counter += 1

                    if not has_already_printed_vuln:
                        pr_changelog += '### ' + app_name + "\n"
                    has_already_printed_vuln = True

                    vuln_status = 'FIXED' if app_vuln['fixed_in_version'] else 'NOT FIXED'
                    pr_changelog += '- [' + vuln_id + '](' + url + ') - ' + date + ' - ' + vuln_status + '\n' #e.g. "- [CVE-2025-00000](https://nvd.nist.gov/vuln/detail/CVE-2025-00000) - 2025-12-16"

                    # Define vulnerability for the TOML file. As per TOML specs,
                    #   keys must be unique, and keys should preferably be displayed
                    #   in order: https://toml.io/en/v1.1.0#table
                    app_vuln = { vuln_id_lowercaps: app_vuln } #e.g. 'cve-2025-00000'.
                    # ~ app_vuln = { date + '_' + vuln_id.lower(): app_vuln } #e.g. '2025-12-16_cve-2025-00000'.

                    app_sec_updated.update(app_vuln)
            security['apps'][app_name].update(app_sec_updated)

        # Finalize changelog
        start_time_formatted = datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
        if new_unique_vuln_counter:
            pr_changelog = ('## New vulnerabilities (' + str(new_unique_vuln_counter) + ')\n' +
                            'Looked up for ' + str(apps_number) + ' apps on ' +
                            start_time_formatted + '.\n' +
                            pr_changelog)
        else:
            pr_changelog = ('No new vulnerability found!\n' +
                            'Looked up for ' + str(apps_number) + ' apps on ' +
                             start_time_formatted + '.\n')

        # Build TOML document (cf. https://tomlkit.readthedocs.io/en/latest/api/)
        logging.info('Generating the new security.toml file...')
        security_new_toml = tomlkit.document()

        security_new_toml.add(tomlkit.comment('========================================================='))
        security_new_toml.add(tomlkit.comment(' This file has been generated with https://github.com/YunoHost/apps_tools/update_vulnerabilities_database/update_vulnerabilities_database.py.'))
        security_new_toml.add(tomlkit.comment(' You can manually add entries to it and they will be taken into account at next generation of the file. If so, please make sure you:'))
        security_new_toml.add(tomlkit.comment(' - use the same template than the existing entries'))
        security_new_toml.add(tomlkit.comment(' - use "source" = "other" as source property'))
        security_new_toml.add(tomlkit.comment('========================================================='))
        security_new_toml.add(tomlkit.nl())

        for category_name, softwares in security.items():
            cat = tomlkit.table(False) #do not make it a super-table or tomlkit will not dump its header
            cat.add(tomlkit.nl())

            for software_name, reports in softwares.items():
                sw = tomlkit.table(False) #do not make it a super-table or tomlkit will not dump its header
                sw.add(tomlkit.nl())

                # Sort all reports from newest to oldest (new reports are now mixed with previous ones)
                if len(reports) > 1:
                    reports_sorted = { k: v for k, v in sorted(reports.items(), key=lambda report: (report[1]['date'], report[0]), reverse=True) } #sort by date and then among equal dates by key name (= CVE ID)
                else:
                    reports_sorted = reports

                for i, (report_name, report_data) in enumerate(reports_sorted.items()):
                    rep = tomlkit.table(False) #do not make it a super-table or tomlkit will not dump its header

                    for key, val in report_data.items():
                        if key == 'more_infos' and isinstance(val, list):
                            val_filtered = list(filter(None, val)) #remove any empty elements from the list
                            links = tomlkit.array().multiline(True) #this is the "more_infos" array containing URLs - display one URL per line
                            for url in val_filtered:
                                links.add_line(url)
                            rep.add(key, links)
                        else:
                            rep.add(key, val)

                    # Add new line at the end of the block, except for the last report of the given app (or there will be 2 new lines)
                    if (i + 1) < len(reports):
                        rep.add(tomlkit.nl())

                    sw.append(report_name, rep)
                cat.append(software_name, sw)
            security_new_toml.append(category_name, cat)

        # Indent TOML document
        for value in security_new_toml.values():
            indent_tomlkit_nested_tables(value, current_level=0, max_level=2, spaces=4)

        # Dump TOML
        security_new_toml = tomlkit.dumps(security_new_toml)

        # Output data as per chosen action
        if args.pr:
            # PR to Github
            repo_path = get_apps_repo.from_args(args)
            apps_repo = Repo(repo_path)
            apps_toml_path = repo_path / "security.toml"

            pr_head = 'update_vulnerabilities_database'
            new_branch = apps_repo.create_head(pr_head, apps_repo.refs.main)
            apps_repo.head.reference = new_branch
            apps_toml_path.open("w", encoding="utf-8").write(security_new_toml)

            logging.info("Committing and pushing the new catalog...")
            pr_title = 'Update vulnerabilities\' database'
            apps_repo.index.add("security.toml")
            apps_repo.index.commit(pr_title)
            apps_repo.git.push("--set-upstream", "origin", new_branch)

            make_pull_request(pr_title, pr_changelog, pr_head)
            success_msg = 'Success: Pull request created.'

        elif args.write:
            local_save_path = Path(str(Path(__file__).parent) + '/security.toml')
            local_save_path.open('w', encoding='utf-8').write(security_new_toml)
            success_msg = 'Success: security.toml written to ' + str(local_save_path) + '.'

        else: #show
            logging.info('\n' + security_new_toml)
            success_msg = 'Success: security.toml printed.'

        # That's all, folks!
        logging.info(success_msg)
        print(success_msg)
        time_estimate = show_minutes_or_seconds(time.time() - start_time)
        logging.info('Execution time: ' + str(time_estimate))
        logging.info('-------------------------------------------------')
        logging.info('\n' + pr_changelog)


if __name__ == '__main__':
    main()
