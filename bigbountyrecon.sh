#!/usr/bin/env bash
# ============================================
# BigBountyRecon Lite - Simple Bug Bounty Recon
# ============================================
# Author: David Carpintero Diaz (modified)
# Date:   12-6-2025
#
# Usage: chmod +x bigbountyrecon.sh && ./bigbountyrecon.sh
#
# Description:
#   - Interactive menu with 58 dork-based recon functions.
#   - Prompts for target domain, then shows menu.
#   - Each option opens the corresponding Google dork or site in Firefox.
# ============================================

# --- Colors & Formatting (ANSI codes) ---
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
MAGENTA="\033[35m"
CYAN="\033[36m"
BOLD="\033[1m"
RESET="\033[0m"

# --- Banner ---
print_banner() {
  clear
  echo -e "${CYAN}${BOLD}"
  echo "   ____  ____  _____  _      _                  "
  echo "  |  _ \|  _ \|  __ \| |    (_)                 "
  echo "  | |_) | |_) | |__) | |     _ _ __  _   ___  __"
  echo "  |  _ <|  _ <|  _  /| |    | | '_ \| | | \ \/ /"
  echo "  | |_) | |_) | | \ \| |____| | | | | |_| |>  < "
  echo "  |____/|____/|_|  \_\______|_|_| |_|\__,_/_/\_\\"
  echo -e "${RESET}"
  echo -e "${YELLOW}Simple Bug Bounty Recon Tool - Dork Generator${RESET}"
  echo
}

# --- Prompt for Target ---
read -rp "$(echo -e "${BOLD}Enter target domain (e.g. ${TARGET}):${RESET}") " TARGET
echo

# --- Descriptive option names ---
OPTIONS=(
  "Directory Listing"
  "Configuration Files"
  "Database Files"
  "WordPress Plugins"
  "Log Files"
  "Backup & Old Files"
  "Login Pages"
  "SQL Error Messages"
  "Apache Config Files"
  "Robots.txt Files"
  "DomainEye API Search"
  "Public Documents"
  "phpinfo() Pages"
  "Backdoor Detection"
  "Install/Setup Files"
  "Open Redirects"
  "Apache Struts RCE"
  "Third-Party Exposure"
  "Security Headers Check"
  "GitLab References"
  "Pastebin Entries"
  "LinkedIn Employees"
  ".htaccess Files"
  "Subdomain Enumeration"
  "Sub-Subdomain Enumeration"
  "WordPress Exposure"
  "Bitbucket References"
  "PassiveTotal API"
  "StackOverflow References"
  "Wayback WP Exposure"
  "GitHub References"
  "OpenBugBounty Listings"
  "Reddit Mentions"
  "crossdomain.xml Files"
  "ThreatCrowd API"
  ".git Folder Exposure"
  "YouTube Mentions"
  "DigitalOcean Spaces"
  "SWF Files (Google)"
  "SWF Files (Yandex)"
  "SWF Files (Wayback)"
  "Wayback Archive API"
  "Reverse IP Lookup"
  "Traefik Dashboard"
  "AWS S3 Buckets"
  "GCP/Azure Buckets"
  "PublicWWW API"
  "Censys API"
  "Shodan API"
  "SharePoint _vti_bin"
  "WSDL Endpoints"
  "Gist References"
  "Certificate Transparency"
  "HaveIBeenPwned Leak"
  "WhatCMS Detection"
  "Run All Google Dorks"
  "Run API-Based Scans"
  "Custom Toolchain"
)

# --- Recon Functions ---
# 1. Directory Listing
recon_directory_listing() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} intitle:\"index of\""
}
# 2. Configuration Files
recon_config_files() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini"
}
# 3. Database Files
recon_database_files() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} ext:sql | ext:dbf | ext:mdb"
}
# 4. WordPress Plugins
recon_wp_plugins() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes | inurl:download"
}
# 5. Log Files
recon_log_files() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} ext:log | filetype:log"
}
# 6. Backup & Old Files
recon_backup_files() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup"
}
# 7. Login Pages
recon_login_pages() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} inurl:login | inurl:signin | intitle:Login | intitle: signin | inurl:auth"
}
# 8. SQL Error Messages
recon_sql_errors() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} (\"sql syntax\" OR \"you have an error in your sql\")"
}
# 9. Apache Config Files
recon_apache_conf() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} filetype:config apache"
}
# 10. Robots.txt Files
recon_robots() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox ":${TARGET}/robots.txt"
}
# 11. DomainEye API Search
recon_domaineye() {
  echo -e "${GREEN}DomainEye API:${RESET}"
  echo "  Requires $DOMAINEYE_API_KEY"
  echo "In progress"
}

# 12. Public Documents
recon_public_documents() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv"
}

# 13. phpinfo() Pages
recon_phpinfo() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} intitle:\"phpinfo()\""
}

# 14. Backdoor Detection
recon_backdoor() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor"
}

# 15. Install/Setup Files
recon_install_setup() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config"
}

# 16. Open Redirects
recon_open_redirects() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http"
}

# 17. Apache Struts RCE
recon_struts_rce() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} ext:action | ext:struts | ext:do"
}

# 18. Third-Party Exposure
recon_third_party() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:http://ideone.com | site:http://codebeautify.org | site:http://codeshare.io | site:http://codepen.io | site:http://repl.it | site:http://justpaste.it | site:http://pastebin.com | site:http://jsfiddle.net | site:http://trello.com | site:*.atlassian.net | site:bitbucket.org \"${TARGET}\""
}

# 19. Security Headers Check
recon_sec_headers() {
  echo -e "${GREEN}Headers Check:${RESET}"
  firefox "https://securityheaders.com/?q=\"${TARGET}\"&followRedirects=on"
}

# 20. GitLab References
recon_gitlab() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "inurl:gitlab \"${TARGET}\""
}

# 21. Pastebin Entries
recon_pastebin() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:pastebin.com \"${TARGET}\""
}

# 22. LinkedIn Employees
recon_linkedin() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:linkedin.com employees \"${TARGET}\""
}

# 23. .htaccess Files
recon_htaccess() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} inurl:/phpinfo.php | inurl:.htaccess"
}

# 24. Subdomain Enumeration
recon_subdomains() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:*.${TARGET}"
}

# 25. Sub-Subdomain Enumeration
recon_subsubdomains() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:*.*.${TARGET}"
}

# 26. WordPress Exposure
recon_wp_exposure() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:${TARGET} inurl:wp-content | inurl:wp-includes"
}

# 27. Bitbucket References
recon_bitbucket() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "site:atlassian.net | site:bitbucket.org \"${TARGET}\""
}

# 28. PassiveTotal API
recon_passivetotal() {
  echo -e "${GREEN}PassiveTotal API:${RESET}"
  firefox "https://api.passivetotal.org/v2/enrichment/subdomains?query=${TARGET}&username=${PASSIVETOTAL_API_KEY_USER}&api_key=${PASSIVETOTAL_API_KEY}"
}

# 29. StackOverflow References
recon_stackoverflow() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://www.google.com/search?q=site:stackoverflow.com+\"${TARGET}\""
}

# 30. Wayback WP Exposure
recon_wayback_wp() {
  echo -e "${GREEN}Wayback API:${RESET}"
  firefox "http://wwwb-dedup.us.archive.org:8083/cdx/search?url=${TARGET}/&matchType=domain&collapse=digest&output=text&fl=original,timestamp&filter=urlkey:.*wp[-].*&limit=1000000&xx="
}

# 31. GitHub References
recon_github() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://github.com/search?q=${TARGET}&type=repositories"
}

# 32. OpenBugBounty Listings
recon_openbugbounty() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://www.openbugbounty.org/search/?search=${TARGET}"
}

# 33. Reddit Mentions
recon_reddit() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://www.reddit.com/search/?q=${TARGET}"
}

# 34. crossdomain.xml Files
recon_crossdomain() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://www.google.com/search?q=${TARGET}/crossdomain.xml"
}

# 35. ThreatCrowd API
recon_threatcrowd() {
  echo -e "${GREEN}ThreatCrowd API:${RESET}"
  firefox "https://threatcrowd.org/domain.php?domain=${TARGET}"
}

# 36. .git Folder Exposure
recon_git_folder() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://www.google.com/search?q=site:${TARGET}+intitle:%22.git%22"
}

# 37. YouTube Mentions
recon_youtube() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://www.youtube.com/results?search_query=${TARGET}"
}

# 38. DigitalOcean Spaces
recon_do_spaces() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://www.google.com/search?q=site:digitaloceanspaces.com%20${TARGET}"
}

# 39. SWF Files (Google)
recon_swf_google() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://www.google.com/search?q=inurl:${TARGET}+ext:swf"
}

# 40. SWF Files (Yandex)
recon_swf_yandex() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://yandex.com/search/?text=site:${TARGET}+mime:swf"
}

# 41. SWF Files (Wayback)
recon_swf_wayback() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://web.archive.org/cdx/search?url=${TARGET}/&matchType=domain&collapse=urlkey&output=text&fl=original&filter=urlkey:.*swf&limit=100000"
}

# 42. Wayback Archive API
recon_wayback_api() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://web.archive.org/cdx/search?url=${TARGET}/&matchType=domain&collapse=urlkey&output=text&fl=original&filter=mimetype:application/x-shockwave-flash&limit=100000"
}

# 43. Reverse IP Lookup
recon_reverse_ip() {
  echo -e "${GREEN}Reverse IP Lookup:${RESET}"
  firefox "https://viewdns.info/reverseip/?host=${TARGET}&t=1"
}

# 44. Traefik Dashboard
recon_traefik() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://www.google.com/search?q=intitle:traefik+inurl:8080/dashboard+${TARGET}"
}

# 45. AWS S3 Buckets
recon_aws_s3() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://www.google.com/search?q=site:.s3.amazonaws.com%20${TARGET}"
}

# 46. GCP/Azure Buckets
recon_gcp_azure() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://cse.google.com/cse?cx=002972716746423218710:veac6ui3rio#gsc.tab=0&gsc.q=${TARGET}"
}

# 47. PublicWWW API
recon_publicwww() {
  echo -e "${GREEN}PublicWWW API:${RESET}"
  firefox "https://publicwww.com/websites/%22${TARGET}%22/"
}

# 48. Censys API
recon_censys() {
  echo -e "${GREEN}Censys API:${RESET}"
  firefox "https://censys.io/ipv4?q=${TARGET}"
}

# 49. Shodan API
recon_shodan() {
  echo -e "${GREEN}Shodan API:${RESET}"
  firefox "https://www.shodan.io/search?query=${TARGET}"
}

# 50. SharePoint _vti_bin
recon_sharepoint_vti() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://www.google.com/search?q=site:${TARGET}+inurl:%22_vti_bin%22"
}

# 51. WSDL Endpoints
recon_wsdl() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://www.google.com/search?q=site:${TARGET}+filetype:wsdl+|+filetype:WSDL+|+ext:svc+|+inurl:wsdl+|+Filetype:?wsdl+|+inurl:asmx?wsdl+|+inurl:jws?wsdl+|+intitle:_vti_bin/sites.asmx?wsdl+|+inurl:_vti_bin/sites.asmx?wsdl"
}

# 52. Gist References
recon_gist() {
  echo -e "${GREEN}Google Dork:${RESET}"
  firefox "https://gist.github.com/search?q=*.${TARGET}"
}

# 53. Certificate Transparency
recon_ct_logs() {
  echo -e "${GREEN}CT Log Lookup:${RESET}"
  firefox "https://crt.sh/?q=${TARGET}"
}

# 54. HaveIBeenPwned Leak
recon_hibp() {
  echo -e "${GREEN}Password leak:${RESET}"
  firefox "https://haveibeenpwned.com/unifiedsearch/${TARGET}"
}

# 55. WhatCMS Detection
recon_whatcms() {
  echo -e "${GREEN}WhatCMS Lookup:${RESET}"
  firefox "https://whatcms.org/?s=${TARGET}"
}

# 56. Run All Google Dorks
recon_run_all_dorks() {
  for func in recon_directory_listing recon_config_files recon_database_files recon_wp_plugins recon_log_files recon_backup_files recon_login_pages recon_sql_errors recon_apache_conf recon_robots recon_public_documents recon_phpinfo recon_backdoor recon_install_setup recon_open_redirects recon_struts_rce recon_third_party recon_sec_headers recon_gitlab recon_pastebin recon_linkedin recon_htaccess recon_subdomains recon_subsubdomains recon_wp_exposure recon_bitbucket recon_stackoverflow recon_github recon_openbugbounty recon_reddit recon_crossdomain recon_git_folder recon_youtube recon_do_spaces recon_swf_google recon_swf_yandex recon_swf_wayback; do
    $func
    echo
  done
}

# 57. Run API-Based Scans
recon_run_api_scans() {
  for func in recon_domaineye recon_passivetotal recon_wayback_wp recon_threatcrowd recon_publicwww recon_censys recon_shodan recon_ct_logs recon_hibp recon_whatcms recon_reverse_ip; do
    $func
    echo
  done
}

# 58. Custom Toolchain
recon_custom_toolchain() {
  echo -e "${GREEN}Custom Integration:${RESET}"
  echo "  Integrate with subfinder, amass, httpx, etc., as needed."
}
# Collect function names in order:
FUNCS=(
  recon_directory_listing
  recon_config_files
  recon_database_files
  recon_wp_plugins
  recon_log_files
  recon_backup_files
  recon_login_pages
  recon_sql_errors
  recon_apache_conf
  recon_robots
  recon_domaineye
  recon_public_documents
  recon_phpinfo
  recon_backdoor
  recon_install_setup
  recon_open_redirects
  recon_struts_rce
  recon_third_party
  recon_sec_headers
  recon_gitlab
  recon_pastebin
  recon_linkedin
  recon_htaccess
  recon_subdomains
  recon_subsubdomains
  recon_wp_exposure
  recon_bitbucket
  recon_passivetotal
  recon_stackoverflow
  recon_wayback_wp
  recon_github
  recon_openbugbounty
  recon_reddit
  recon_crossdomain
  recon_threatcrowd
  recon_git_folder
  recon_youtube
  recon_do_spaces
  recon_swf_google
  recon_swf_yandex
  recon_swf_wayback
  recon_wayback_api
  recon_reverse_ip
  recon_traefik
  recon_aws_s3
  recon_gcp_azure
  recon_publicwww
  recon_censys
  recon_shodan
  recon_sharepoint_vti
  recon_wsdl
  recon_gist
  recon_ct_logs
  recon_hibp
  recon_whatcms
  recon_run_all_dorks
  recon_run_api_scans
  recon_custom_toolchain
)

print_menu() {
  echo -e "${YELLOW}${BOLD}Recon options for ${TARGET}:${RESET}"
  local per_line=4
  local count=${#OPTIONS[@]}
  for ((i=0; i<count; i++)); do
    idx=$((i+1))
    printf " %2d) %-25s" "$idx" "${OPTIONS[i]}"
    if (( idx % per_line == 0 )); then
      echo
    fi
  done
  if (( count % per_line != 0 )); then
    echo
  fi
  echo "  q) Quit"
}

# --- Main Loop ---
while true; do
  print_banner
  print_menu
  echo
  read -rp "$(echo -e ${BOLD}Select an option [1-58, q]:${RESET} ) " opt
  echo
  if [[ "$opt" == "q" ]]; then
    echo -e "${CYAN}Goodbye!${RESET}"
    exit 0
  elif [[ "$opt" =~ ^[0-9]+$ ]] && (( opt>=1 && opt<=58 )); then
    func="${FUNCS[opt-1]}"
    echo -e "${MAGENTA}---> Executing: ${OPTIONS[opt-1]}${RESET}"
    $func
  else
    echo -e "${RED}Invalid option. Try again.${RESET}"
  fi
  echo
  read -rp "Press Enter to continue..." _
done
