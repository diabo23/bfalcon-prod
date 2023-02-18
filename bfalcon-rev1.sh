#!/bin/bash

clear

echo ""
echo "██████╗  █████╗ ███████╗██╗  ██╗    ███████╗ █████╗ ██╗      ██████╗ ██████╗ ███╗   ██╗"
echo "██╔══██╗██╔══██╗██╔════╝██║  ██║    ██╔════╝██╔══██╗██║     ██╔════╝██╔═══██╗████╗  ██║"
echo "██████╔╝███████║███████╗███████║    █████╗  ███████║██║     ██║     ██║   ██║██╔██╗ ██║"
echo "██╔══██╗██╔══██║╚════██║██╔══██║    ██╔══╝  ██╔══██║██║     ██║     ██║   ██║██║╚██╗██║"
echo "██████╔╝██║  ██║███████║██║  ██║    ██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
echo "╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
echo ""

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
bulk_uploaded_file_hash256=$folder_temp_variables"/bulk_uploaded_file_hash256"
file_traceidquickscan=$folder_temp_variables"/file_traceidquickscan"
quickscan_bulk_reportid_list=$folder_temp_variables"/quickscan_bulk_reportid_list"
sandbox_bulk_reportid_list=$folder_temp_variables"/sandbox_bulk_reportid_list"

folder_api_result="/tmp/apiresult"
file_api_uploaded_file_hash256=$folder_api_result"/file_api_uploaded_file_hash256"
file_api_bulk_uploaded_file_hash256=$folder_api_result"/file_api_bulk_uploaded_file_hash256"
file_api_traceidquickscan=$folder_api_result"/file_api_traceidquickscan"
file_api_result_singlequickscan=$folder_api_result"/file_api_result_singlequickscan"
file_api_bulk_result_quickscan=$folder_api_result"/file_api_bulk_result_quickscan"
file_api_bulk_result_sandbox=$folder_api_result"/file_api_bulk_result_sandbox"

file_list_of_files=$folder_temp_variables"/file_list_of_files"
file_filtered_list_of_files=$folder_temp_variables"/file_filtered_list_of_files"

default_folder_to_search=/tmp/samples

mime_docx="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
mime_xlsx="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
mime_pptx="application/vnd.openxmlformats-officedocument.presentationml.presentation"
mime_exe="application/x-dosexec"
mime_macho="application/x-mach-binary"
mime_pdf="application/pdf"

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
            echo ""
            echo "Existing token is still valid (it will expire in $remainingtime seconds)."
            echo ""
        elif (( remainingtime > 0 )); then
            echo ""
            echo "Existing token will expire soon (in $remainingtime seconds); a new one will be generated."
            echo ""
            generatetoken
        else
            echo ""
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
    if [ -z "$1" ]; then
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
            hashsha256=$(curl -X POST "$falconcloud/samples/entities/samples/v2" \
            --progress-bar \
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
    elif [ "$1" = "AUTOMATIC" ]; then
        tempstring=$(mktemp -u XXXXXXXXXX)
        if [ -f $bulk_uploaded_file_hash256.$PPID ]; then
            rm $bulk_uploaded_file_hash256.$PPID
        fi
        maintoken
        while IFS= read -r line; do
            hashsha256=$(curl -X POST "$falconcloud/samples/entities/samples/v2" \
            --progress-bar \
            -H  'accept: application/json' \
            -H  "authorization: Bearer $oauth2token" \
            -H  'Content-Type: multipart/form-data' \
            -F "sample=@$line" \
            -F "file_name=$line" \
            -F 'is_confidential=true' | jq '.resources[0] .sha256')
            hashsha256=`sed -e 's/^"//' -e 's/"$//' <<<"$hashsha256"`
            printf %s $hashsha256 >> "$bulk_uploaded_file_hash256.$PPID"
            if [[ $logscaleintegration -eq 1 ]]; then
                    log_log_type="fileuploadbulk"
                    log_action="File uploaded via bulk upload" 
                    printf '%s\n' "log_datetime=\"$(date +'%Y-%m-%d--%H-%M-%S')\" log_type=\"$log_log_type\" action=\"$log_action\" hash_sha256=\"$hashsha256\"" >> "$file_api_bulk_uploaded_file_hash256.$tempstring.$PPID"
            fi
            echo ""
            echo -e "File ${BLUE}$line${NC} uploaded. SHA256 Hash: ${BLUE}$hashsha256${NC}"
            echo ""
        done < "$file_filtered_list_of_files.$PPID"
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

# bulkupload
bulkupload() {
    launchbulkupload=0
    read -p "Target directory (the default is $default_folder_to_search): " folder_to_search
    if [ -z $folder_to_search ]; then
        folder_to_search=$default_folder_to_search
    fi
    if [ ! -d $folder_to_search ]; then
            echo ""
            echo "Folder $folder_to_search does not exist."
            echo ""
    elif [[ $folder_to_search = $folder_temp_variables || $folder_to_search = $folder_api_result ]]; then
            echo ""
            echo "Folder $folder_to_search is used for BFalcon purposes."
            echo ""
    elif [ -d $folder_to_search ]; then
            folder_to_search=${folder_to_search%/}
            echo ""
            echo "Folder $folder_to_search exists."
            echo ""
            if [ -f "$file_list_of_files.$PPID" ]; then
                rm "$file_list_of_files.$PPID"
            fi
            echo ""
            echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
            echo -e "Listing files in ${BLUE}$folder_to_search${NC} folder"
            echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
            echo ""
            for element in "$folder_to_search"/*
            do
                if [ -f "$element" ]; then
                    mime_type=$(file -b --mime-type "$element")
                    echo "$element"
                    echo "$mime_type"
                    /bin/ls -lsh $element | awk '{print $6}'
                    echo ""
                    printf '%s\n' "$element" >> "$file_list_of_files.$PPID"
                fi
            done
            if [ ! -f $file_list_of_files.$PPID ]; then
                echo ""
                echo "Folder $folder_to_search does not contain files."
                echo ""
            else
                read -p "What type of files you want to filter (PDF, EXE, XLSX, DOCX, PPTX, MACH-O, ALL; default ALL): " chosen_file_type
                chosen_file_type=$(echo "$chosen_file_type" | tr '[:lower:]' '[:upper:]')
                if [ -f $file_filtered_list_of_files.$PPID ]; then
                    rm $file_filtered_list_of_files.$PPID
                fi
                if [ -z $chosen_file_type ]; then
                    chosen_file_type="ALL"
                fi
                if [ $chosen_file_type = "PDF" ]; then
                    echo ""
                    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
                    echo -e "Listing ${BLUE}$chosen_file_type${NC} files in ${BLUE}$folder_to_search${NC} folder"
                    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
                    echo ""
                    while IFS= read -r line; do
                        mime_type=$(file -b --mime-type "$line")
                        if [ $mime_type = $mime_pdf ]; then
                            echo "$line"
                            printf '%s\n' "$line" >> "$file_filtered_list_of_files.$PPID"
                            launchbulkupload=1
                        fi
                    done < "$file_list_of_files.$PPID"
                    echo ""
                elif [ $chosen_file_type = "EXE" ]; then
                    echo ""
                    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
                    echo -e "Listing ${BLUE}$chosen_file_type${NC} files in ${BLUE}$folder_to_search${NC} folder"
                    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
                    echo ""
                    while IFS= read -r line; do
                        mime_type=$(file -b --mime-type "$line")
                        if [ $mime_type = $mime_exe ]; then
                            echo "$line"
                            printf '%s\n' "$line" >> "$file_filtered_list_of_files.$PPID"
                            launchbulkupload=1
                        fi
                    done < "$file_list_of_files.$PPID"
                    echo ""
                elif [ $chosen_file_type = "XLSX" ]; then
                    echo ""
                    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
                    echo -e "Listing ${BLUE}$chosen_file_type${NC} files in ${BLUE}$folder_to_search${NC} folder"
                    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
                    echo ""
                    while IFS= read -r line; do
                        mime_type=$(file -b --mime-type "$line")
                        if [ $mime_type = $mime_xlsx ]; then
                            echo "$line"
                            printf '%s\n' "$line" >> "$file_filtered_list_of_files.$PPID"
                            launchbulkupload=1
                        fi
                    done < "$file_list_of_files.$PPID"
                    echo ""
                elif [ $chosen_file_type = "DOCX" ]; then
                    echo ""
                    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
                    echo -e "Listing ${BLUE}$chosen_file_type${NC} files in ${BLUE}$folder_to_search${NC} folder"
                    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
                    echo ""
                    while IFS= read -r line; do
                        mime_type=$(file -b --mime-type "$line")
                        if [ $mime_type = $mime_docx ]; then
                            echo "$line"
                            printf '%s\n' "$line" >> "$file_filtered_list_of_files.$PPID"
                            launchbulkupload=1
                        fi
                    done < "$file_list_of_files.$PPID"
                    echo ""
                elif [ $chosen_file_type = "PPTX" ]; then
                    echo ""
                    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
                    echo -e "Listing ${BLUE}$chosen_file_type${NC} files in ${BLUE}$folder_to_search${NC} folder"
                    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
                    echo ""
                    while IFS= read -r line; do
                        mime_type=$(file -b --mime-type "$line")
                        if [ $mime_type = $mime_pptx ]; then
                            echo "$line"
                            printf '%s\n' "$line" >> "$file_filtered_list_of_files.$PPID"
                            launchbulkupload=1
                        fi
                    done < "$file_list_of_files.$PPID"
                    echo ""
                elif [ $chosen_file_type = "MACH-O" ]; then
                    echo ""
                    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
                    echo -e "Listing ${BLUE}$chosen_file_type${NC} files in ${BLUE}$folder_to_search${NC} folder"
                    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
                    echo ""
                    while IFS= read -r line; do
                        mime_type=$(file -b --mime-type "$line")
                        if [ $mime_type = $mime_macho ]; then
                            echo "$line"
                            printf '%s\n' "$line" >> "$file_filtered_list_of_files.$PPID"
                            launchbulkupload=1
                        fi
                    done < "$file_list_of_files.$PPID"
                    echo ""
                elif [ $chosen_file_type = "ALL" ]; then
                    echo ""
                    echo "ALL"
                    echo ""
                    while IFS= read -r line; do
                            echo "$line"
                            printf '%s\n' "$line" >> "$file_filtered_list_of_files.$PPID"
                            launchbulkupload=1
                    done < "$file_list_of_files.$PPID"
                    #file_filtered_list_of_files=$file_list_of_files
                    echo ""
                else
                    echo ""
                    echo "Choice not valid."
                    echo ""
                fi
                if [[ $launchbulkupload -eq 1 ]]; then
                    read -p "Do you want to upload them to CrowdStrike Cloud (Y or N; default N)?" answerbulkupload
                    answerbulkupload=$(echo "$answerbulkupload" | tr '[:lower:]' '[:upper:]')
                    if [ ! -z $answerbulkupload ] && [ $answerbulkupload = "Y" ]; then
                        upload_method="AUTOMATIC"
                        fileupload $upload_method
                    elif [ ! -z $answerbulkupload ] && [ $answerbulkupload != "N" ]; then
                        echo ""
                        echo "Choice not valid"
                    fi
                    echo ""
                elif [[ $launchbulkupload -eq 0 ]]; then
                    echo -e "Folder ${BLUE}$folder_to_search${NC} does not contain ${BLUE}$chosen_file_type${NC} files."
                    echo ""
                fi
            fi
    fi
}

# bulkquickscanreportid
bulkquickscanreportid() {
    echo ""
    read -p "Number of QuickScan analysis to retrieve: " limit_quickscan_report
    checkpositiveintegernumber $limit_quickscan_report
    if [[ $positiveintegernumber -ne 1 ]] || [[ $limit_quickscan_report = 0 ]]; then
        echo ""
        echo "Value not valid; a positive integer number should be provided."
        echo ""
    else
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
    fi
}

#bulksandboxreportid
bulksandboxreportid() {
    echo ""
    read -p "Number of Sandbox reports to retrieve: " limit_sandbox_report
    checkpositiveintegernumber $limit_sandbox_report
    if [[ $positiveintegernumber -ne 1 ]] || [[ $limit_sandbox_report = 0 ]]; then
        echo ""
        echo "Value not valid; a positive integer number should be provided."
        echo ""
    else
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
                echo -e "Verdict of the Sandbox analysis: ${BLUE}${array_obj[0]}${NC}."
                echo -e "Hash SHA256: ${BLUE}${array_obj[1]}${NC}."
                echo ""
            else
                echo -e "Sandbox analysis status is: ${RED}$sandboxstate${NC}."
                echo ""
            fi
        done
    fi
}

# getquickscanquota
getquickscanquota() {
    echo ""
    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^"
    echo -e "Getting information about QuickScan ML Quota"
    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^"
    maintoken
    oIFS=$IFS ; IFS="\;" ; read -a array_obj < <(echo $(curl -s -X GET "$falconcloud/scanner/queries/scans/v1" \
    -H  "accept: application/json" \
    -H  "authorization: Bearer $oauth2token" | jq '.meta .quota .total, .meta .quota .used, .meta .quota .in_progress') | paste -d \; - - -)
    echo -e "QuickScan analysis quota: ${BLUE}${array_obj[0]}${NC}"
    echo -e "QuickScan analysis used: ${RED}${array_obj[1]}${NC}"
    echo "QuickScan analysis in progress: ${array_obj[2]}"
    echo ""
}

# getsandboxquota
getsandboxquota() {
    echo ""
    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
    echo -e "Getting information about Sandbox Quota"
    echo "~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~"
    maintoken
    oIFS=$IFS ; IFS="\;" ; read -a array_obj < <(echo $(curl -s -X GET "$falconcloud/falconx/queries/reports/v1" \
    -H  "accept: application/json" \
    -H  "authorization: Bearer $oauth2token" | jq '.meta .quota .total, .meta .quota .used, .meta .quota .in_progress') | paste -d \; - - -)
    echo -e "Sandbox analysis quota: ${BLUE}${array_obj[0]}${NC}"
    echo -e "Sandbox analysis used: ${RED}${array_obj[1]}${NC}"
    echo "Sandbox analysis in progress: ${array_obj[2]}"
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
            echo "Choice not valid, files won't be deleted."
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
            echo "Choice not valid, files won't be deleted."
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
    options=("Upload a File to the CrowdStrike cloud" "Launch a QuickScan ML Analysis" "Get QuickScan ML Analysis result" "Get Bulk QuickScan Report IDs, verdicts and SHA256" "Get Bulk Sandbox Report IDs, verdicts and SHA256" "Bulk Upload Files in a Folder to the CrowdStrike cloud" "Get QuickScan Quota" "Get Sandbox Quota" "Enables writing to local files (for LogScale integration)" "Delete temporary files ($folder_temp_variables)" "Delete temporary files ($folder_api_result)" "Exit")
    COLUMNS=0
    select opt in "${options[@]}"
    do
        case $opt in
            "Upload a File to the CrowdStrike cloud")
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
            "Bulk Upload Files in a Folder to the CrowdStrike cloud")
                bulkupload
                break
                ;;
            "Get QuickScan Quota")
                getquickscanquota
                break
                ;;
            "Get Sandbox Quota")
                getsandboxquota
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