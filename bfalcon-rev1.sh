#!/bin/bash

clear

function textcolor()
{
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    BLUE='\033[0;34m'
    NC='\033[0m'
}

textcolor

argclientid=$1
argclientsecret=$2
argfalconcloud=$3

file_expirationdate="/tmp/expirationdate"
file_argfalconcloud="/tmp/argfalconcloud"
file_oauth2token="/tmp/oauth2token"

folder_api_result="/tmp/apiresult/"
file_api_result_hash256=$folder_api_result"file_hash256"

logscaleintegration=1

if [[ $# -ne 3 ]]; then
    echo "Missing parameters (you should provide <Client ID> <Secret> <Falcon Cloud>)"
    echo ""
    exit
elif [[ "$argfalconcloud" = "US-1" ]]; then
    falconcloud="https://api.crowdstrike.com"
elif [[ "$argfalconcloud" = "US-2" ]]; then
    falconcloud="https://api.us-2.crowdstrike.com"
elif [[ "$argfalconcloud" = "EU-1" ]]; then
    falconcloud="https://api.eu-1.crowdstrike.com"
else
    echo "Falcon Cloud not valid (valid values are US-1, US-2 or EU-1)"
    echo ""
    exit
fi

if [ ! -d "$folder_api_result" ] 
then
    mkdir "$folder_api_result"
fi

function maintoken()
{

    function checktokenexpiration()
    {
        expirationdate=$(cat $file_expirationdate.$PPID)
        currentdate=$(date '+%s')
        remainingtime=$((expirationdate-currentdate))
        
        if [[ ! -f $file_argfalconcloud.$PPID ]]; then
            diffcloud=1
        elif [[ $argfalconcloud != $(cat $file_argfalconcloud.$PPID) ]]; then
            diffcloud=1
        fi
    }

    function generatetoken()
    {
        read tokenduration oauth2token < <(echo $(curl -s -X POST "$falconcloud/oauth2/token" -H  "accept: application/json" -H  "Content-Type: application/x-www-form-urlencoded" -d "client_id=$argclientid&client_secret=$argclientsecret" | jq -r '.expires_in, .access_token'))
        
        oauth2token=`sed -e 's/^"//' -e 's/"$//' <<<"$oauth2token"`
        printf %s $oauth2token > $file_oauth2token.$PPID
        
        currentdate=$(date '+%s')
        expirationdate=$((currentdate+tokenduration))
        echo $expirationdate > $file_expirationdate.$PPID
        echo $argfalconcloud > $file_argfalconcloud.$PPID

    }

    if [ -f $file_oauth2token.$PPID ]; then
        checktokenexpiration
        echo ""
        echo -e "OAuth2 token is stored in ${GREEN}$file_oauth2token.$PPID${NC} file and is expiring in ${BLUE}$remainingtime${NC} seconds."
        echo""
        if [[ $diffcloud -eq 1 ]]; then
            echo "Existing OAuth2 token has been generated in a different Cloud or no information about Cloud exist; a new token will be generated."
            diffcloud=0
            echo ""
            generatetoken
        elif (( remainingtime > 60 )); then
            echo "No need to generate a new OAuth2 token."
            echo ""
        else
            echo "Existing OAuth2 token is too old, a new one will be generated."
            echo ""
            generatetoken
        fi
    else
        echo ""
        echo -e "OAuth2 token is expected to be in ${GREEN}$file_oauth2token.$PPID${NC} file but does not exist."
        echo ""
        echo "Generating new OAuth2 token."
        echo ""
        generatetoken
    fi

}

# bulkquickscanreportid
bulkquickscanreportid() {
    echo ""
    read -p "Number of QuickScan analysis to retrieve: " limit_quickscan_report
    tempstring=$(mktemp -u XXXXXXXXXX)
    maintoken
    oauth2token=$(cat $file_oauth2token.$PPID)
    quickscanreportid_list=$(curl -s -X GET "$falconcloud/scanner/queries/scans/v1?limit=$limit_quickscan_report" \
    -H  "accept: application/json" \
    -H  "authorization: Bearer $oauth2token" | jq -c -r '.resources[]' > /tmp/quickscanreportid_list.$PPID)
    IFS=$'\n' command eval 'arr_quickscanreportid_list=($(cat /tmp/quickscanreportid_list.$PPID))'
    for traceidquickscan in "${arr_quickscanreportid_list[@]}"
    do
        oIFS=$IFS ; IFS="\;" ; read -a array_obj < <(echo $(curl -s -X GET "$falconcloud/scanner/entities/scans/v1?ids=$traceidquickscan" -H  'accept: application/json' -H  "authorization: Bearer $oauth2token" | jq -r '.resources[] .status, .resources[0] .samples[0] .verdict, .resources[0] .samples[0] .sha256') | paste -d \; - - -)  
        if [ ${array_obj[0]} != "done" ]; then
            echo -e "Analysis is not completed. QuickScan analysis status is: ${RED}${array_obj[0]}${NC}."
        else
            echo -e "Analysis is completed. QuickScan analysis status is: ${BLUE}${array_obj[0]}${NC}."
            if [[ $logscaleintegration -eq 1 ]]; then
                log_log_type="bulkquickscanreportid"
                log_action="Bulk Quickscan verdict"
                printf '%s\n' "log_datetime=\"$(date +'%Y-%m-%d--%H-%M-%S')\" log_type=\"$log_log_type\" action=\"$log_action\" verdict=\"${array_obj[1]}\" trace_id_quickscan=\"$traceidquickscan\" hash_sha256=\"${array_obj[2]}\"" >> "$file_api_result_hash256.$tempstring.$PPID"
            fi
            echo -e "Verdict of the QuickScan analysis: ${BLUE}${array_obj[1]}${NC}."
            echo -e "Hash SHA256: ${BLUE}${array_obj[2]}${NC}."
            echo ""
        fi
    done
}

#bulksandboxreportid
bulksandboxreportid() {
    echo ""
    read -p "Number of Sandbox reports to retrieve: " limit_sandbox_report
    tempstring=$(mktemp -u XXXXXXXXXX)
    maintoken
    oauth2token=$(cat $file_oauth2token.$PPID)
    sandboxreportid_list=$(curl -s -X GET "$falconcloud/falconx/queries/reports/v1?limit=$limit_sandbox_report" \
    -H  "accept: application/json" \
    -H  "authorization: Bearer $oauth2token" | jq -c -r '.resources[]' > /tmp/sandboxreportid_list.$PPID)
    IFS=$'\n' command eval 'arr_sandboxreportid_list=($(cat /tmp/sandboxreportid_list.$PPID))'
    for traceidsandbox in "${arr_sandboxreportid_list[@]}"
    do
        read sandboxstate resources1 < <(echo $(curl -s -X GET "$falconcloud/falconx/entities/submissions/v1?ids=$traceidsandbox" \
        -H  "accept: application/json" \
        -H  "authorization: Bearer $oauth2token" | jq '.resources[0] .state, .resources'))
        sandboxstate=`sed -e 's/^"//' -e 's/"$//' <<<"$sandboxstate"`     
        if [ $sandboxstate = "running" ]; then
            echo -e "Analysis is still ongoing. Sandbox analysis status is: ${RED}$sandboxstate${NC}."
        elif [ $sandboxstate = "success" ]; then
            echo -e "Analysis is completed. Sandbox analysis status is: ${BLUE}$sandboxstate${NC}."
            oIFS=$IFS ; IFS="\;" ; read -a array_obj < <(echo $(curl -s -X GET "$falconcloud/falconx/entities/report-summaries/v1?ids=$traceidsandbox" \
            -H  "accept: application/json" \
            -H  "authorization: Bearer $oauth2token" | jq -r '.resources[0] .sandbox[0] .verdict, .resources[0].sandbox[0] .sha256') | paste -d \; - -)
            if [[ $logscaleintegration -eq 1 ]]; then
                log_log_type="bulksandboxreportid"
                log_action="Bulk Sandbox verdict"
                printf '%s\n' "log_datetime=\"$(date +'%Y-%m-%d--%H-%M-%S')\" log_type=\"$log_log_type\" action=\"$log_action\" verdict=\"${array_obj[0]}\" trace_id_sandbox=\"$traceidsandbox\" hash_sha256=\"${array_obj[1]}\"" >> "$file_api_result_hash256.$tempstring.$PPID"
            fi
            echo -e "Verdict of the Sandbox analysis: ${BLUE}${array_obj[0]}${NC}."
            echo -e "Hash SHA256: ${BLUE}${array_obj[1]}${NC}."
            echo ""
        else
            echo -e "Sandbox analysis status is: ${RED}$sandboxstate${NC}."
        fi
    done
    echo ""
}

# exitfunction
exitfunction() {
    break 2
}

# main menu
echo""
PS3='Main Menu: '
while true; do
    options=("Get Bulk QuickScan Report IDs, verdicts and SHA256" "Get Bulk Sandbox Report IDs, verdicts and SHA256" "Exit")
    COLUMNS=0
    select opt in "${options[@]}"
    do
        case $opt in
            "Get Bulk QuickScan Report IDs, verdicts and SHA256")
                bulkquickscanreportid
                break
                ;;
            "Get Bulk Sandbox Report IDs, verdicts and SHA256")
                bulksandboxreportid
                break
                ;;
            "Exit")
                exitfunction
                ;;
            *) echo "Invalid option $REPLY";;
        esac
    done
done