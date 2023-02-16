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
argfalconcloud=$(echo "$3" | tr '[:lower:]' '[:upper:]')

folder_temp_variables="/tmp/tempvariables"
uploaded_file_hash256=$folder_temp_variables"/file_hash256"
file_traceidquickscan=$folder_temp_variables"/file_traceidquickscan"
quickscan_bulk_reportid_list=$folder_temp_variables"/quickscan_bulk_reportid_list"
sandbox_bulk_reportid_list=$folder_temp_variables"/sandbox_bulk_reportid_list"

folder_api_result="/tmp/apiresult"
file_api_uploaded_file_hash256=$folder_api_result"/file_api_uploaded_file_hash256"
file_api_traceidquickscan=$folder_api_result"/file_api_traceidquickscan"
file_api_result_singlequickscan=$folder_api_result"/file_api_result_singlequickscan"
file_api_bulk_result_quickscan=$folder_api_result"/file_api_bulk_result_quickscan"
file_api_bulk_result_sandbox=$folder_api_result"/file_api_bulk_result_sandbox"

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

if [ ! -d "$folder_temp_variables" ] 
then
    mkdir "$folder_temp_variables"
fi

if [ ! -d "$folder_api_result" ] 
then
    mkdir "$folder_api_result"
fi

function maintoken()
{
    function checktokenexpiration()
    {
        currentdate=$(date '+%s')
        remainingtime=$((expirationdate-currentdate))
    }
    function generatetoken()
    {
        oIFS=$IFS ; IFS="\;" ; read -a array_obj < <(echo $(curl -s -X POST "$falconcloud/oauth2/token" -H  "accept: application/json" -H  "Content-Type: application/x-www-form-urlencoded" -d "client_id=$argclientid&client_secret=$argclientsecret" | jq -r '.expires_in, .access_token') | paste -d \; - -)
        oauth2token=`sed -e 's/^"//' -e 's/"$//' <<<"$oauth2token"`
        tokenduration=${array_obj[0]}
        oauth2token=${array_obj[1]}
        currentdate=$(date '+%s')
        expirationdate=$((currentdate+tokenduration))
    }
    if [ -z $oauth2token ]; then
        echo ""
        echo -e "OAuth2 token does not exist; a new one will be generated."
        echo ""
        echo "Generating new OAuth2 token."
        echo ""
        generatetoken
    else
        checktokenexpiration
        if (( remainingtime > 60 )); then
            echo "Existing token is still valid (it will expire in $remainingtime seconds)."
            echo ""
        elif (( remainingtime > 0 )); then
            echo "Existing token will expire soon (in $remainingtime seconds); a new one will be generated."
            echo ""
            generatetoken
        else
            echo "Existing token is expired; a new one will be generated."
            echo ""
            generatetoken
        fi
    fi
}

function checkpositiveintegernumber() {
    if [[ $1 =~ ^[0-9]+$ ]]; then
        positiveintegernumber=1
    else
        positiveintegernumber=0
    fi
}

# fileupload
fileupload () {
    read -p "Enter filepath: " filepath
    read -p "Enter filename (label): " filename
    if [[ -z $filepath || -z $filename ]]; then
        echo ""
        echo "Both filepath and filename must be provided"
        echo ""
    elif [ -f "$filepath" ]; then
        maintoken
        echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
        echo "Uploading File to CrowdStrike Cloud"
        echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
        echo ""
        hashsha256=$(curl -s -X POST "$falconcloud/samples/entities/samples/v2" \
        -H  'accept: application/json' \
        -H  "authorization: Bearer $oauth2token" \
        -H  'Content-Type: multipart/form-data' \
        -F "sample=@$filepath" \
        -F "file_name=$filename" \
        -F 'is_confidential=true' | jq '.resources[0] .sha256')
        hashsha256=`sed -e 's/^"//' -e 's/"$//' <<<"$hashsha256"`
        printf %s $hashsha256 > "$uploaded_file_hash256.$PPID"
        if [[ $logscaleintegration -eq 1 ]]; then
            log_log_type="fileupload"
            log_action="File uploaded"           
            tempstring=$(mktemp -u XXXXXXXXXX)
            printf '%s\n' "log_datetime=\"$(date +'%Y-%m-%d--%H-%M-%S')\" log_type=\"$log_log_type\" action=\"$log_action\" hash_sha256=\"$hashsha256\"" >> "$file_api_uploaded_file_hash256.$tempstring.$PPID"
        fi
        echo ""
        echo -e "SHA256 Hash of the uploaded file: ${BLUE}$hashsha256${NC}"
        echo ""
    else
        echo "" && echo -e "File ${RED}$filepath${NC} does not exist." && echo ""
    fi
}

# submitquickscan
submitquickscan() {
    hashsha256provided=1
    read -p "Enter SHA256 Hash of the fie (or leave blank to use the one stored in the temp file): " hashsha256
    if [ -z $hashsha256 ]; then
        if [ -f "$uploaded_file_hash256.$PPID" ]; then
            hashsha256=$(cat $uploaded_file_hash256.$PPID)
        else
            echo ""
            echo "No SHA256 Hash provided"
            echo ""
            hashsha256provided=0
        fi
    fi
    if [[ $hashsha256provided -ne 0 ]]; then
        maintoken
        echo ""
        echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
        echo "Launching CrowdStrike QuickScan ML Analysis"
        echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
        echo ""
        traceidquickscan=$(curl -s -X POST "$falconcloud/scanner/entities/scans/v1" \
        -H  'accept: application/json' \
        -H  "authorization: Bearer $oauth2token" \
        -H  'Content-Type: application/json' \
        -d "{ \"samples\": [\"$hashsha256\" ] }" | jq '.resources[0]')
        traceidquickscan=`sed -e 's/^"//' -e 's/"$//' <<<"$traceidquickscan"`
        printf %s $traceidquickscan > "$file_traceidquickscan.$PPID"
        if [[ $logscaleintegration -eq 1 ]]; then
            log_log_type="submitquickscan"
            log_action="File submitted to QuickScan"
            tempstring=$(mktemp -u XXXXXXXXXX)
            printf '%s\n' "log_datetime=\"$(date +'%Y-%m-%d--%H-%M-%S')\" log_type=\"$log_log_type\" action=\"$log_action\" hash_sha256=\"$hashsha256\" trace_id_quickscan=\"$traceidquickscan\"" >> "$file_api_traceidquickscan.$tempstring.$PPID"
        fi

        echo -e "Trace ID of the QuickScan ML analysis: ${BLUE}$traceidquickscan${NC}"
        echo ""
    fi
}

# getquickscanresult
getquickscanresult() {
    traceidquickscanprovided=1
    read -p "Enter QuickScan Trace ID (or leave blank to use the one stored in the file): " traceidquickscan
    if [ -z $traceidquickscan ]; then
        if [ -f "$file_traceidquickscan.$PPID" ]; then
            traceidquickscan=$(cat $file_traceidquickscan.$PPID)
        else
            echo ""
            echo "No QuickScan Trace ID provided"
            echo ""
            traceidquickscanprovided=0
        fi
    fi
    if [[ $traceidquickscanprovided -ne 0 ]]; then
        maintoken
        oIFS=$IFS ; IFS="\;" ; read -a array_obj < <(echo $(curl -s -X GET "$falconcloud/scanner/entities/scans/v1?ids=$traceidquickscan" \
        -H  'accept: application/json' \
        -H  "authorization: Bearer $oauth2token" | jq -r '.resources[0] .id, .resources[0] .samples[0] .verdict, .resources[0] .samples[0] .sha256') | paste -d \; - - -)
        if [[ ${array_obj[0]} = "null" ]]; then
            echo ""
            echo "QuickScan Trace ID not found"
            echo ""
        elif [[ ${array_obj[1]} = "null" ]]; then
            echo ""
            echo "QuickScan ML Analysis is not available yet"
            echo ""
        else
            echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^"
            echo "Retrieving QuickScan ML analysis results"
            echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^"
            echo ""
            if [[ $logscaleintegration -eq 1 ]]; then
                log_log_type="getquickscanresult"
                log_action="QuickScan verdict"
                tempstring=$(mktemp -u XXXXXXXXXX)
                printf '%s\n' "log_datetime=\"$(date +'%Y-%m-%d--%H-%M-%S')\" log_type=\"$log_log_type\" action=\"$log_action\" verdict=\"${array_obj[1]}\" hash_sha256=\"${array_obj[2]}\" trace_id_quickscan=\"${array_obj[0]}\"" >> "$file_api_result_singlequickscan.$tempstring.$PPID"
            fi
            echo -e "Trace ID of the QuickScan analysis: ${BLUE}${array_obj[0]}${NC}"
            echo -e "Hash SHA256 of the analyzed file: ${BLUE}${array_obj[2]}${NC}"
            echo -e "Verdict of the QuickScan analysis: ${BLUE}${array_obj[1]}${NC}"
            echo ""
        fi
    fi
}

# bulkquickscanreportid
bulkquickscanreportid() {
    echo ""
    read -p "Number of QuickScan analysis to retrieve: " limit_quickscan_report
    tempstring=$(mktemp -u XXXXXXXXXX)
    maintoken
    quickscanreportid_list=$(curl -s -X GET "$falconcloud/scanner/queries/scans/v1?limit=$limit_quickscan_report" \
    -H  "accept: application/json" \
    -H  "authorization: Bearer $oauth2token" | jq -c -r '.resources[]' > $quickscan_bulk_reportid_list.$PPID)
    IFS=$'\n' command eval 'arr_quickscanreportid_list=($(cat $quickscan_bulk_reportid_list.$PPID))'
    for traceidquickscan in "${arr_quickscanreportid_list[@]}"
    do
        oIFS=$IFS ; IFS="\;" ; read -a array_obj < <(echo $(curl -s -X GET "$falconcloud/scanner/entities/scans/v1?ids=$traceidquickscan" -H  'accept: application/json' -H  "authorization: Bearer $oauth2token" | jq -r '.resources[] .status, .resources[0] .samples[0] .verdict, .resources[0] .samples[0] .sha256') | paste -d \; - - -)  
        if [ ${array_obj[0]} != "done" ]; then
            echo -e "Analysis is not completed. QuickScan analysis status is: ${RED}${array_obj[0]}${NC}"
        else
            echo -e "Analysis is completed. QuickScan analysis status is: ${BLUE}${array_obj[0]}${NC}"
            if [[ $logscaleintegration -eq 1 ]]; then
                log_log_type="bulkquickscanreportid"
                log_action="Bulk Quickscan verdict"
                printf '%s\n' "log_datetime=\"$(date +'%Y-%m-%d--%H-%M-%S')\" log_type=\"$log_log_type\" action=\"$log_action\" verdict=\"${array_obj[1]}\" trace_id_quickscan=\"$traceidquickscan\" hash_sha256=\"${array_obj[2]}\"" >> "$file_api_bulk_result_quickscan.$tempstring.$PPID"
            fi
            echo -e "Verdict of the QuickScan analysis: ${BLUE}${array_obj[1]}${NC}"
            echo -e "Hash SHA256: ${BLUE}${array_obj[2]}${NC}"
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
    sandboxreportid_list=$(curl -s -X GET "$falconcloud/falconx/queries/reports/v1?limit=$limit_sandbox_report" \
    -H  "accept: application/json" \
    -H  "authorization: Bearer $oauth2token" | jq -c -r '.resources[]' > $sandbox_bulk_reportid_list.$PPID)
    IFS=$'\n' command eval 'arr_sandboxreportid_list=($(cat $sandbox_bulk_reportid_list.$PPID))'
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
                printf '%s\n' "log_datetime=\"$(date +'%Y-%m-%d--%H-%M-%S')\" log_type=\"$log_log_type\" action=\"$log_action\" verdict=\"${array_obj[0]}\" trace_id_sandbox=\"$traceidsandbox\" hash_sha256=\"${array_obj[1]}\"" >> "$file_api_bulk_result_sandbox.$tempstring.$PPID"
            fi
            echo -e "Verdict of the Sandbox analysis: ${BLUE}${array_obj[0]}${NC}"
            echo -e "Hash SHA256: ${BLUE}${array_obj[1]}${NC}"
            echo ""
        else
            echo -e "Sandbox analysis status is: ${RED}$sandboxstate${NC}."
        fi
    done
    echo ""
}

# enablelocalwritinglogscale
enablelocalwritinglogscale() {
    echo ""
    if [[ $logscaleintegration -eq 1 ]]; then
        logscaleintegration=0
        echo -e "Writing to local files (for LogScale integration) is ${RED}Not Active${NC}"
    else
        logscaleintegration=1
        echo -e "Writing to local files (for LogScale integration) is ${GREEN}Active${NC}"
    fi
    echo ""
}

# deletempfilesvar
deletempfilesvar() {
    echo ""
    read -p "List files in $folder_temp_variables that are older than specified minutes (or 0 to see all the files): " minuteslimit
    checkpositiveintegernumber $minuteslimit
    if [[ $positiveintegernumber -eq 1 ]]; then
        echo ""
        IFS=$'\n'
        array=( $(find $folder_temp_variables -type f -mmin +$minuteslimit) )
        for i in ${array[@]}
        do
            echo $i
        done
        echo ""
        read -p "Do you want to delete them (Y or N)?" actiondelete
        actiondelete=$(echo "$actiondelete" | tr '[:lower:]' '[:upper:]')
        if [ -z $actiondelete ]; then
            echo ""
            echo "No choice made; files won't be deleted."
            echo ""
        elif [ $actiondelete = "Y" ]; then
            for i in ${array[@]}
            do
                rm $i
            done
            echo ""
        elif [ $actiondelete != "N" ]; then
            echo ""
            echo "Choice not valid, files won't be removed."
        fi
    else
        echo ""
        echo "Value not valid; a positive integer number should be provided (or 0 to see all the files)."
        echo ""
    fi
}

# deletempfilesapi
deletempfilesapi() {
    echo ""
    read -p "List files in $folder_api_result that are older than specified minutes (or 0 to see all the files): " minuteslimit
    checkpositiveintegernumber $minuteslimit
    if [[ $positiveintegernumber -eq 1 ]]; then
        echo ""
        IFS=$'\n'
        array=( $(find $folder_api_result -type f -mmin +$minuteslimit) )
        for i in ${array[@]}
        do
            echo $i
        done
        echo ""
        read -p "Do you want to delete them (Y or N)?" actiondelete
        actiondelete=$(echo "$actiondelete" | tr '[:lower:]' '[:upper:]')
        if [ -z $actiondelete ]; then
            echo ""
            echo "No choice made; files won't be deleted."
            echo ""
        elif [ $actiondelete = "Y" ]; then
            for i in ${array[@]}
            do
                rm $i
            done
            echo ""
        elif [ $actiondelete != "N" ]; then
            echo ""
            echo "Choice not valid, files won't be removed."
        fi
    else
        echo ""
        echo "Value not valid; a positive integer number should be provided (or 0 to see all the files)."
        echo ""
    fi
}

# exitfunction
exitfunction() {
    exit
}

# main menu
echo""
PS3='Main Menu: '
while true; do
    options=("Upload a file to the CrowdStrike cloud" "Launch a QuickScan ML Analysis" "Get QuickScan ML Analysis result" "Get Bulk QuickScan Report IDs, verdicts and SHA256" "Get Bulk Sandbox Report IDs, verdicts and SHA256" "Enables writing to local files (for LogScale integration)" "Delete temporary files ($folder_temp_variables)" "Delete temporary files ($folder_api_result)" "Exit")
    COLUMNS=0
    select opt in "${options[@]}"
    do
        case $opt in
            "Upload a file to the CrowdStrike cloud")
                fileupload
                break
                ;;
            "Launch a QuickScan ML Analysis")
                submitquickscan
                break
                ;;
            "Get QuickScan ML Analysis result")
                getquickscanresult
                break
                ;;
            "Get Bulk QuickScan Report IDs, verdicts and SHA256")
                bulkquickscanreportid
                break
                ;;
            "Get Bulk Sandbox Report IDs, verdicts and SHA256")
                bulksandboxreportid
                break
                ;;
            "Enables writing to local files (for LogScale integration)")
                enablelocalwritinglogscale
                break
                ;;
            "Delete temporary files ($folder_temp_variables)")
                deletempfilesvar
                break
                ;;
            "Delete temporary files ($folder_api_result)")
                deletempfilesapi
                break
                ;;
            "Exit")
                exitfunction
                ;;
            *) echo "Invalid option $REPLY";;
        esac
    done
done