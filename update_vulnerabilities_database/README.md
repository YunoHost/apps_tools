## Description

This script generates an updated [`security.toml`](https://github.com/YunoHost/apps/blob/main/security.toml) file by reaching the API of 2 major vulnerabilities databases:
- NIST NVD (US): https://nvd.nist.gov/vuln/search#/nvd/home?resultType=records
- EUVD (EU): https://euvd.enisa.europa.eu/

The data in the source `security.toml` is kept in the updated version.

## Usage

1. Clone apps_tools repo: `git clone https://github.com/YunoHost/apps_tools.git`
2. Clone apps repo: `git clone https://github.com/YunoHost/apps`
3. Install app caches (it will take 10 to 30mn downloading): `python3 app_caches.py -j8 -l path/to/apps/repo -c apps_cache/`
	1. `path/to/apps/repo` being the path to which the apps repo is cloned.
	2. `apps_cache` being the path where you want the cache to be installed/updated.
4. Go to script directory (or somewhere else actually) and create a Python Virtual environment: `python3 -m venv .venv`
5. Activate the Python virtual environment: `source .venv/bin/activate`
6. Install script's dependencies: `pip install requests toml tomlkit tqdm GitPython`
7. Run the script, e.g.:
	1. for only a few apps: `python3 update_vulnerabilities_database.py -c path/to/apps_cache -l path/to/apps -w`
	2. for all apps of the catalog: `python3 update_vulnerabilities_database.py -c path/to/apps_cache -l path/to/apps -w -a discourse,nextcloud`
8. With such arguments, it will create a `security.toml` in the script's folder, and a log file in the directory from where was called. That can be customized with specific arguments.

### Arguments

Only `APPS_DIR` (`-l`), APPS_CACHE (`-c`) and one of the actions (`-s`, `-w` or `--pr`) are mandatory.
```
usage: update_vulnerabilities_database.py [-h] [-a APPS] [-f FROM_DATE] [-j LOG_DIR] [-s | --show | --no-show] [-w | --write | --no-write] [--pr | --no-pr] [-v | --verbose | --no-verbose] [-l APPS_DIR | -r APPS_REPO] [-c APPS_CACHE]

options:
  -h, --help            show this help message and exit
  -a APPS, --apps APPS  Selected app names delimited by commas (without the "_ynh" suffix) that can be found in the YNH app catalog. Defaults to all catalog apps.
  -f FROM_DATE, --from_date FROM_DATE
                        Beginning of the search period, e.g. 2025-12-21 (should be less than 120 days from today for NIST). Defaults to the date of the last report in security.toml.
  -j LOG_DIR, --log_dir LOG_DIR
                        Path where to create the log (e.g."path/to/update-vuln.log"). Defaults to current folder.
  -s, --show, --no-show
                        Print the updated security.toml to stdout (default action)
  -w, --write, --no-write
                        Write the updated security.toml in the current folder
  --pr, --no-pr         Create a pull request with the updated security.toml (it implies --write)
  -v, --verbose, --no-verbose
  -l APPS_DIR, --apps-dir APPS_DIR
                        Path to a local 'apps' repository
  -r APPS_REPO, --apps-repo APPS_REPO
                        Git url to clone the remote 'apps' repository
  -c APPS_CACHE, --apps-cache APPS_CACHE
                        Path to the apps cache directory (default=<apps repo>/.apps_cache)
```

### Performance
It takes currently ~8s per app to run the script. 
If run for the full catalog (642 apps as of today), it takes 55mn - 5,1 second per app on average to run due to the fact that some apps do not have a CPE (because it doesn't exist or it was not declared in the app's manifest) - so the lookup is skipped for them.
Using a [NIST NVD API key](https://nvd.nist.gov/developers/request-an-api-key) is saving an additional 5s per app (to be passed to the script as environment variable `NIST_API_KEY` . 

## TO-DOs
- [ ] Test the `--pr` feature and fix potentially related bugs.
- [ ] if is a new app is added the catalog, next run of the script will fetch its vulnerabilities only from last date the script was run (could be the day before or... i.e. not showing recent vulnerabilties at app addition to the database.
	- There could be a separate action triggered by the event "new app in catalog", running the query from base date again just for the new app, by using the -f parameter which allows to chosing the start date of the period.
- [ ] Better define danger level.
	- Define what are possible answers to `level` property in `security.toml` and what they should mean for maintainers and admins: 
        - "dangerous" vulnerability ? --> automatically append a "Security warning" mention to `doc/PRE_INSTALL.md` and maybe the apps catalog as well.  
        - no fix or fix available in another version ? --> notify maintainers about it so they can watch for related news or update the pacakge.
	- Include EPSS classification (probability of exploitation) and or CISA Known Exploited Vulnerability for more accuracy?
		- At NIST NVD DB, for one vulnerability report there can be multiple evaluations giving a broad range of CVSS scores for the same app:
			- different versions of CVSS (currently essentially v3.1 or/and v4.0)
			- different assessors
		Depending on the chosen parameters, [this CVE](https://nvd.nist.gov/vuln/detail/CVE-2025-14649) has for instance a severity ranging from Medium, High and Critical.
	- Mixing CVSS and EPSS and CISA-KEV could help: 
		- Filtering out low-risk vulnerabilities with high CVSS but low EPSS (if a critical vulnerability needs physical access to the machine, there would be no emergency in YNH context)
		- Prioritizing high-risk vulnerabilities with moderate CVSS but high EPSS or in CISA KEV catalog
        - [More infos](https://riskbasedprioritization.github.io/risk/Rbp_schemes/#cvss-base-score-ratings-with-exploitation-focus)
	- EPSS data is produced by First and is available via a [free API](https://api.first.org/) or via the EUVD reports as well.
    - CISA Known Exploited Vulnerabilities (KEV) catalog is a regularly updated CSV/JSON file which can be found [at this page](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) with its associated schema.
- [ ] Make parrallel queries to speed up the process: https://github.com/YunoHost/yunohost/blob/dev/src/app_catalog.py#L253-L272
	- It would very likely require an API key from NIST NVD DB.
- [ ] Check for modified dates ? For now search relies on vulnerabilities's publication dates. But it could also be made so that it checks for modifications dates and updates existing records in `security.toml` as there might more more infos URLs, a change in classification, or new info regarding a potential fixed version. For now all this follow-up is to be done manually - which nevertheless is not that bad - maintainers should ideally check the links directly and then report in security.toml that they applied the patch to the package.
- [ ] Looking for missing CPE programmatically? NIST has an other API to lookup for CPE, however that will be difficult to implement with the YunoHost `app_id` as entry key as depending on the apps there may be many answers that need to be sorted manually. Indeed some apps can have a name which is a rather common word which actually different apps, and others are part of a rather large range of products named similarly, each of them having its CPE.
- [ ] Support `[system]` section of `security.toml` ?
- Add [Github Security](https://github.com/nextcloud/security-advisories/security/advisories) as database source ? It may not be that interesting, because NIST NVD and EUVD already reference links to Github Security for CVEs when it makes sense. 

## Current dev choices (to be debated)
- Currently at NIST, only vulnerabilities with an ["Analyzed"](https://nvd.nist.gov/vuln/vulnerability-status#divNvdStatus) status are considered.
- The `source` property in `security.toml` is currently meant to be one of this 3 values: `nist`, `euvd` or `other` (`other` can be used for manual contributions for instance) . The 2 first ones are used by the script to retrieve the latest report (by date) per source. It is considered as the start period of the lookup query (the end period being the moment of the query). Alternatively, we could imagine storing a `last_update` param at the top of `security.toml`.
- The product search by CPE (Common Platform Enumeration) is actually not done by full CPE but by what NIST NVD calls Virtual Match String, i.e. the first five portion of the CPE  `cpe:2.3:a:nextcloud:nextcloud`. For reference, the full format version 2.3 of the CPE is: 
    ```txt
	cpe:<cpe_version>:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
	```
