#!/bin/bash

#This script pulls various information from the Synology NAS
##/etc/crontab then restart, synoservice -restart crond

#create a lock file in the ramdisk directory to prevent more than one instance of this script from executing  at once
if ! mkdir /volume1/web/logging/notifications/fortigate_snmp.lock; then
	echo "Failed to aquire lock.\n" >&2
	exit 1
fi
trap 'rm -rf /volume1/web/logging/notifications/fortigate_snmp.lock' EXIT #remove the lockdir on exit

from_email_address="admin@admin.com"

#reading in variables from configuration file
if [ -r "/volume1/web/config/config_files/config_files_local/fortigate_config.txt" ]; then
	#file is available and readable 
	read input_read < /volume1/web/config/config_files/config_files_local/fortigate_config.txt
	explode=(`echo $input_read | sed 's/,/\n/g'`)
	email_address=${explode[0]} #done
	email_interval=${explode[1]}
	capture_system=${explode[2]}
	capture_memory=${explode[3]}
	capture_cpu=${explode[4]}
	data_transfer=${explode[5]}
	capture_SSLVPN=${explode[6]}
	capture_FW_policy=${explode[7]}
	capture_interval=${explode[8]}
	memory_limit=${explode[9]} #done
	snmp_device_url=${explode[10]}
	snmp_device_name=${explode[11]}
	ups_group="NAS"
	influxdb_host=${explode[12]}
	influxdb_port=${explode[13]}
	influxdb_name=${explode[14]}
	influxdb_user=${explode[15]}
	influxdb_pass=${explode[16]}
	script_enable=${explode[17]}
	AuthPass1="password"
	PrivPass2="password"
	day_of_month_cycle_starts=${explode[18]}


	if [ $script_enable -eq 1 ]
	then
		#reading in variables from previous script executions. a separate variable is needed per drive in the system this script will send a message about
		#the variable data is saved as follows: disk0,disk1,disk2,disk3,disk4,disk5,disk6,disk7,disk8,CPU0. we need to explode the array using the commas as a delimiter
		if [ -r "/volume1/web/logging/notifications/fortigate_logging_variable.txt" ]; then
		#	#file is available and readable 
			read input_read < /volume1/web/logging/notifications/fortigate_logging_variable.txt #determine how manu minutes it has been since the last memory status email has been sent
			explode=(`echo $input_read | sed 's/,/\n/g'`)
			memory_email=${explode[0]}
		else
		#	#file is not available so let's make the file
			echo "0" > /volume1/web/logging/notifications/fortigate_logging_variable.txt
			memory_email=0
		fi

		#loop the script 
		total_executions=$(( 60 / $capture_interval))
		echo "Capturing $total_executions times"
		i=0
		while [ $i -lt $total_executions ]; do
			
			#Create empty URL
			post_url=

			#GETTING VARIOUS SYSTEM INFORMATION
			if [ $capture_system -eq 1 ]
			then
				
				measurement="fortigate_system"
				
				#Serial number
				serial_number=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.100.1.1.1.0 -Ovt`

				
function filter_data(){
	#removing unneeded text "STRING: " from SNMP output
	local sub_string_to_remove="$1"
	local item_being_filtered="$2"
	local filtered=$(echo ${item_being_filtered#${sub_string_to_remove}})
	#removing unneeded " characters before and after serial number
	local secondString=""
	filtered=${filtered//\"/$secondString}
	echo "$filtered"
}			

				#removing unneeded text "STRING: " and unneeded " marks from SNMP output
				serial_number=$(filter_data "STRING: " "$serial_number")
				
				###################################################################################
				
				#System Version
				system_version=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.1.1.0 -Ovt`
				
				#removing unneeded text "STRING: " and unneeded " marks from SNMP output
				system_version=$(filter_data "STRING: " "$system_version")
				
				###################################################################################
				
				#System uptime  (in hundredths of a second)
				system_uptime=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.1.20.0 -Ovt`
				
				#removing unneeded text "Counter64: " and unneeded " marks from SNMP output
				system_uptime=$(filter_data "Counter64: " "$system_uptime")
				
				###################################################################################
				
				#System session count
				system_session_count=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.1.8.0 -Ovt`
				
				#removing unneeded text "Gauge32: " and unneeded " marks from SNMP output
				system_session_count=$(filter_data "Gauge32: " "$system_session_count")
				
				###################################################################################
				
				#System antivirus_version
				system_antivirus_version=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.2.1.0 -Ovt`
				
				#removing unneeded text "STRING: " and unneeded " marks from SNMP output
				system_antivirus_version=$(filter_data "STRING: " "$system_antivirus_version")
				
				###################################################################################
				
				#System IPS Version
				system_ips_version=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.2.2.0 -Ovt`
				
				#removing unneeded text "STRING: " and unneeded " marks from SNMP output
				system_ips_version=$(filter_data "STRING: " "$system_ips_version")
				
				###################################################################################
				
				#System antivirus_version extended
				system_antivirus_version_ex=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.2.3.0 -Ovt`
				
				#removing unneeded text "STRING: " and unneeded " marks from SNMP output
				system_antivirus_version_ex=$(filter_data "STRING: " "$system_antivirus_version_ex")
			
				###################################################################################
				
				#System IPS version extended
				system_ips_version_ex=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.2.4.0 -Ovt`
				
				#removing unneeded text "STRING: " and unneeded " marks from SNMP output
				system_ips_version_ex=$(filter_data "STRING: " "$system_ips_version_ex")
				
				#System details to post
				post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name serial_number=\""$serial_number"\",system_version=\""$system_version"\",system_uptime=$system_uptime,system_session_count=$system_session_count,system_antivirus_version=\""$system_antivirus_version"\",system_ips_version=\""$system_ips_version"\",system_antivirus_version_ex=\""$system_antivirus_version_ex"\",system_ips_version_ex=\""$system_ips_version_ex"\"
		"
			else
				echo "Skipping system capture"
			fi
			
			
			# GETTING MEMORY STATS
			if [ $capture_memory -eq 1 ]
			then
				
				measurement="fortigate_memory"
				
				#System memory usage (%)
				memory_usage=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.1.4.0 -Ovt`
				
				#removing unneeded text "Gauge32: " and unneeded " marks from SNMP output
				memory_usage=$(filter_data "Gauge32: " "$memory_usage")
				
				#System memory capacity [Total physical memory (RAM) installed (KB)]
				memory_capacity=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.1.5.0 -Ovt`
				
				#removing unneeded text "Gauge32: " and unneeded " marks from SNMP output
				memory_capacity=$(filter_data "Gauge32: " "$memory_capacity")
				
				if [ $memory_usage -gt $memory_limit ]
				then
				#echo the memory usage is getting too high
					if [ $memory_email -ge $email_interval ]
					then
					#echo the email has not been sent in over 1 hour, re-sending email
						mailbody="Warning Fortigate Memory Usage has exceeded $memory_limit%. Current Memory usage is $memory_usage"
						echo "from: $from_email_address " > /volume1/web/logging/notifications/fortigate_email.txt
						echo "to: $email_address " >> /volume1/web/logging/notifications/fortigate_email.txt
						echo "subject: Fortigate Memory Warning " >> /volume1/web/logging/notifications/fortigate_email.txt
						echo "" >> /volume1/web/logging/notifications/fortigate_email.txt
						echo $mailbody >> /volume1/web/logging/notifications/fortigate_email.txt
						cat /volume1/web/logging/notifications/fortigate_email.txt | sendmail -t
						memory_email=0
					fi
				fi		
			
				post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name memory_usage=$memory_usage,memory_capacity=$memory_capacity
		"
			else
				echo "Skipping memory capture"
			fi
			
			
			# GETTING CPU USAGE
			if [ $capture_cpu -eq 1 ]
			then
				
				measurement="fortigate_cpu"
				
				##################need to explode each CPU usages into 4x different areas for each core
				
				processor_usage=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.4.2.1.3 -Oqv`
				
				explode=(`echo $processor_usage | sed 's/,/\n/g'`)
				processor_usage_core0=${explode[0]}
				processor_usage_core1=${explode[1]}
				processor_usage_core2=${explode[2]}
				processor_usage_core3=${explode[3]}
				
				processor_usage_overall_average=$((( $processor_usage_core0 + $processor_usage_core1 + $processor_usage_core2 + $processor_usage_core3 ) / 4 ))
				
				processor_user_usage=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.4.2.1.9 -Oqv`
				
				explode=(`echo $processor_user_usage | sed 's/,/\n/g'`)
				processor_user_usage_core0=${explode[0]}
				processor_user_usage_core1=${explode[1]}
				processor_user_usage_core2=${explode[2]}
				processor_user_usage_core3=${explode[3]}
				
				processor_system_usage=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.4.2.1.10 -Oqv`
				
				explode=(`echo $processor_system_usage | sed 's/,/\n/g'`)
				processor_system_usage_core0=${explode[0]}
				processor_system_usage_core1=${explode[1]}
				processor_system_usage_core2=${explode[2]}
				processor_system_usage_core3=${explode[3]}
				
				post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name processor_usage_core0=$processor_usage_core0,processor_usage_core1=$processor_usage_core1,processor_usage_core2=$processor_usage_core2,processor_usage_core3=$processor_usage_core3,processor_user_usage_core0=$processor_user_usage_core0,processor_user_usage_core1=$processor_user_usage_core1,processor_user_usage_core2=$processor_user_usage_core2,processor_user_usage_core3=$processor_user_usage_core3,processor_system_usage_core0=$processor_system_usage_core0,processor_system_usage_core1=$processor_system_usage_core1,processor_system_usage_core2=$processor_system_usage_core2,processor_system_usage_core3=$processor_system_usage_core3,processor_usage_overall_average=$processor_usage_overall_average
		"
			else
				echo "Skipping CPU capture"
			fi

function get_index(){
	local xx=0
	local value="$1"
	local exploded=(`echo "$2" | sed 's/,/\n/g'`)
	for xx in "${!exploded[@]}"; do
		if [[ "${exploded[$xx]}" = "${value}" ]]; then
			echo "${xx}";
		fi
	done
}
			
			# GETTING data transfer information
			if [ $data_transfer -eq 1 ]
			then
				measurement="fortigate_data_transfer"
				
				interface_names=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 .1.3.6.1.2.1.31.1.1.1.1 -Oqv`
				
				#determine the index value within the interface_names_exploded array based on the name of the interface
				wan1_index=$(get_index "wan1" "$interface_names")
				
				internal_index=$(get_index "internal" "$interface_names")
				
				wifi_index=$(get_index "CORE_WIFI" "$interface_names")
				
				lan_index=$(get_index "lan" "$interface_names")
				
				FWF_60E_index=$(get_index "FWF-60E" "$interface_names")
				
				APC_VLAN20_index=$(get_index "APC_VLAN20" "$interface_names")
				
				Tablo_VLAN21_index=$(get_index "Tablo_VLAN21" "$interface_names")
				
				Roku_VLAN22_index=$(get_index "Roku_VLAN22" "$interface_names")
				
				Denon_VLAN24_index=$(get_index "Denon_VLAN24" "$interface_names")
				
				guest_wifi_index=$(get_index "WIFI" "$interface_names")
				
				
				#(Number of octets received on interfaces. one octet = 1 byte
				interface_in_bytes=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.2.1.2.2.1.10 -Oqv`
				explode=(`echo $interface_in_bytes | sed 's/,/\n/g'`)
				
				declare -i wan_in=${explode[$wan1_index]}
				declare -i internal_in=${explode[$internal_index]}
				declare -i wifi_in=${explode[$wifi_index]}
				declare -i lan_in=${explode[$lan_index]}
				declare -i FWF_60E_in=${explode[$FWF_60E_index]}
				declare -i APC_VLAN20_in=${explode[$APC_VLAN20_index]}
				declare -i Tablo_VLAN21_in=${explode[$Tablo_VLAN21_index]}
				declare -i Roku_VLAN22_in=${explode[$Roku_VLAN22_index]}
				declare -i Denon_VLAN24_in=${explode[$Denon_VLAN24_index]}
				declare -i guest_wifi_in=${explode[$guest_wifi_index]}
				
								
				#(Number of octets sent on wan.  one octet = 1 byte
				interface_out_bytes=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.2.1.2.2.1.16 -Oqv`
				explode=(`echo $interface_out_bytes | sed 's/,/\n/g'`)
				
				declare -i wan_out=${explode[$wan1_index]}
				declare -i internal_out=${explode[$internal_index]}
				declare -i wifi_out=${explode[$wifi_index]}
				declare -i lan_out=${explode[$lan_index]}
				declare -i FWF_60E_out=${explode[$FWF_60E_index]}
				declare -i APC_VLAN20_out=${explode[$APC_VLAN20_index]}
				declare -i Tablo_VLAN21_out=${explode[$Tablo_VLAN21_index]}
				declare -i Roku_VLAN22_out=${explode[$Roku_VLAN22_index]}
				declare -i Denon_VLAN24_out=${explode[$Denon_VLAN24_index]}
				declare -i guest_wifi_out=${explode[$guest_wifi_index]}
				
				
				#the fortigate unfortunately uses 32bit numbers so they frequently roll over. due to grafana using a derivative 
				#to determine bits/second, when the value rolls over it causes a huge erroneous negative delta
				#bash uses 64 bit numbers. saving a running total of bytes 
				if [ -r "/volume1/web/logging/notifications/fortigate_data_transfer_variable.txt" ]; then
					#file is available and readable 
					read input_read < /volume1/web/logging/notifications/fortigate_data_transfer_variable.txt
					explode=(`echo $input_read | sed 's/,/\n/g'`)
				
				#definition of what the different "explode" arary index items are for
				#	0=wan_in_tracking
				#	1=wan_out_tracking
				#	2=wan_in
				#	3=wan_out
				#	4=internal_in_tracking
				#	5=internal_out_tracking
				#	6=internal_in
				#	7=internal_out
				#	8=wifi_in_tracking
				#	9=wifi_out_tracking
				#	10=wifi_in
				#	11=wifi_out
				#	12=lan_in_tracking
				#	13=lan_out_tracking
				#	14=lan_in
				#	15=lan_out
				#	16=FWF_60E_in_tracking
				#	17=FWF_60E_out_tracking
				#	18=FWF_60E_in
				#	19=FWF_60E_out
				#	20=APC_VLAN20_in_tracking
				#	21=APC_VLAN20_out_tracking
				#	22=APC_VLAN20_in
				#	23=APC_VLAN20_out
				#	24=Tablo_VLAN21_in_tracking
				#	25=Tablo_VLAN21_out_Tracking
				#	26=Tablo_VLAN21_in
				#	27=Tablo_VLAN21_out
				#	28=Roku_VLAN22_in_tracking
				#	29=Roku_VLAN22_out_tracking
				#	30=Roku_VLAN22_in
				#	31=Roku_VLAN22_out
				#	32=Denon_VLAN24_in_tracking
				#	33=Denon_VLAN24_out_tracking
				#	34=Denon_VLAN24_in
				#	35=Denon_VLAN24_out
				#	36=guest_wifi_in_tracking
				#	37=guest_wifi_out_tracking
				#	38=guest_wifi_in
				#	39=guest_wifi_out
				#	40=wan_total_data_tracking
				#	41=last_hour_tracking
				#	42=last_day_tracking
				#	43=last_month_tracking

					####################################################
					#Wan_IN and WAN_out
					####################################################
					#did the Fortigate value roll over 4294967295?
					if [ $wan_in -lt ${explode[0]} ]; then #is wan_in less than the previous time we captures it's value? if it is less than the previous time, then the value must have rolled over
						wan_in_tracking=$wan_in #save the current value of wan_in so we can compare it next time
						wan_in=$((( $wan_in + ${explode[2]} ) + ( 4294967295 - ${explode[0]} ))) # since wan_in rolled over, let's add its current value to our 64 but running counter, and also account for any delta between the old wan_in value that was below the 32 bit limit and the bit limit itself
					else
						wan_in_tracking=$wan_in #save the current value of wan_in so we can compare it next time
						wan_in=$(( ${explode[2]} + ( $wan_in - ${explode[0]} )))
					fi

					#did the Fortigate value roll over 4294967295?
					if [ $wan_out -lt ${explode[1]} ]; then
						wan_out_tracking=$wan_out
						wan_out=$((( $wan_out + ${explode[3]} ) + ( 4294967295 - ${explode[1]} )))
					else
						wan_out_tracking=$wan_out
						wan_out=$(( ${explode[3]} + ( $wan_out - ${explode[1]} )))
					fi
					
					####################################################
					#Wan_IN and WAN_out data usage over 1 hour, 1 day, and 1 month
					####################################################
					day=`date '+%d'`
					min=`date '+%M'`
					hour=`date '+%H'`
					seconds=`date '+%S'`

					#echo "day is $day"
					#echo "hour is $hour"
					#echo "min is $min"
					#echo "seconds is $seconds"
					
					wan_total_data=$(( $wan_out + $wan_in ))

					if [[ $day == "$day_of_month_cycle_starts" && $min == "00" && $hour == "00" ]];then
						#echo "it is the beginning of a new month"
						lastMonth_wan=0
					else
						#lastMonth_wan = last_month_tracking + (wan_total_data - wan_total_data_tracking)
						lastMonth_wan=$(( ${explode[43]} + ( $wan_total_data - ${explode[40]} )))
					fi

					if [[ $min == "00" && $hour == "00" ]];then
						#echo "it is the beginning of a new day"
						lastDay_wan=0
					else
						#lastDay_wan = last_day_tracking + (wan_total_data - wan_total_data_tracking)
						lastDay_wan=$(( ${explode[42]} + ( $wan_total_data - ${explode[40]} )))
					fi

					if [[ $min == "00" ]];then
						#echo "it is the beginning of a new hour"
						lastHour_wan=0
					else
						#lastHour_wan = (value of "lastHour_wan" from previous execution) + [ (current value reported of total data on the wan) - (value of total wan data from previous execution) ]
						#lastHour_wan = last_hour_tracking + (wan_total_data - wan_total_data_tracking)
						lastHour_wan=$(( ${explode[41]} + ( $wan_total_data - ${explode[40]} )))
					fi
					
					####################################################
					#internal_in and internal_out
					####################################################
					#did the Fortigate value roll over 4294967295?
					if [ $internal_in -lt ${explode[4]} ]; then #is internal_in less than the previous time we captures it's value? if it is less than the previous time, then the value must have rolled over
						internal_in_tracking=$internal_in #save the current value of internal_in so we can compare it next time
						internal_in=$((( $internal_in + ${explode[6]} ) + ( 4294967295 - ${explode[4]} ))) # since internal_in rolled over, let's add its current value to our 64 but running counter, and also account for any delta between the old wan_in value that was below the 32 bit limit and the bit limit itself
					else
						internal_in_tracking=$internal_in #save the current value of internal_in so we can compare it next time
						internal_in=$(( ${explode[6]} + ( $internal_in - ${explode[4]} )))
					fi

					#did the Fortigate value roll over 4294967295?
					if [ $internal_out -lt ${explode[5]} ]; then
						internal_out_tracking=$internal_out
						internal_out=$((( $internal_out + ${explode[7]} ) + ( 4294967295 - ${explode[5]} )))
					else
						internal_out_tracking=$internal_out
						internal_out=$(( ${explode[7]} + ( $internal_out - ${explode[5]} )))
					fi
					
					####################################################
					#wifi_in and wifi_out
					####################################################
					#did the Fortigate value roll over 4294967295?
					if [ $wifi_in -lt ${explode[8]} ]; then #is wifi_in less than the previous time we captures it's value? if it is less than the previous time, then the value must have rolled over
						wifi_in_tracking=$wifi_in #save the current value of wifi_in so we can compare it next time
						wifi_in=$((( $wifi_in + ${explode[10]} ) + ( 4294967295 - ${explode[8]} ))) # since wifi_in rolled over, let's add its current value to our 64 but running counter, and also account for any delta between the old wan_in value that was below the 32 bit limit and the bit limit itself
					else
						wifi_in_tracking=$wifi_in #save the current value of wifi_in so we can compare it next time
						wifi_in=$(( ${explode[10]} + ( $wifi_in - ${explode[8]} )))
					fi

					#did the Fortigate value roll over 4294967295?
					if [ $wifi_out -lt ${explode[9]} ]; then
						wifi_out_tracking=$wifi_out
						wifi_out=$((( $wifi_out + ${explode[11]} ) + ( 4294967295 - ${explode[9]} )))
					else
						wifi_out_tracking=$wifi_out
						wifi_out=$(( ${explode[11]} + ( $wifi_out - ${explode[9]} )))
					fi
					
					####################################################
					#lan_in and lan_out
					####################################################
					#did the Fortigate value roll over 4294967295?
					if [ $lan_in -lt ${explode[12]} ]; then #is lan_in less than the previous time we captures it's value? if it is less than the previous time, then the value must have rolled over
						lan_in_tracking=$lan_in #save the current value of lan_in so we can compare it next time
						lan_in=$((( $lan_in + ${explode[14]} ) + ( 4294967295 - ${explode[12]} ))) # since lan_in rolled over, let's add its current value to our 64 but running counter, and also account for any delta between the old wan_in value that was below the 32 bit limit and the bit limit itself
					else
						lan_in_tracking=$lan_in #save the current value of lan_in so we can compare it next time
						lan_in=$(( ${explode[14]} + ( $lan_in - ${explode[12]} )))
					fi

					#did the Fortigate value roll over 4294967295?
					if [ $lan_out -lt ${explode[13]} ]; then
						lan_out_tracking=$lan_out
						lan_out=$((( $lan_out + ${explode[15]} ) + ( 4294967295 - ${explode[13]} )))
					else
						lan_out_tracking=$lan_out
						lan_out=$(( ${explode[15]} + ( $lan_out - ${explode[13]} )))
					fi
					
					####################################################
					#FWF_60E_in and FWF_60E_out
					####################################################
					#did the Fortigate value roll over 4294967295?
					if [ $FWF_60E_in -lt ${explode[16]} ]; then #is FWF_60E_in less than the previous time we captures it's value? if it is less than the previous time, then the value must have rolled over
						FWF_60E_in_tracking=$FWF_60E_in #save the current value of FWF_60E_in so we can compare it next time
						FWF_60E_in=$((( $FWF_60E_in + ${explode[18]} ) + ( 4294967295 - ${explode[16]} ))) # since FWF_60E_in rolled over, let's add its current value to our 64 but running counter, and also account for any delta between the old wan_in value that was below the 32 bit limit and the bit limit itself
					else
						FWF_60E_in_tracking=$FWF_60E_in #save the current value of FWF_60E_in so we can compare it next time
						FWF_60E_in=$(( ${explode[18]} + ( $FWF_60E_in - ${explode[16]} )))
					fi

					#did the Fortigate value roll over 4294967295?
					if [ $FWF_60E_out -lt ${explode[17]} ]; then
						FWF_60E_out_tracking=$FWF_60E_out
						FWF_60E_out=$((( $FWF_60E_out + ${explode[19]} ) + ( 4294967295 - ${explode[17]} )))
					else
						FWF_60E_out_tracking=$FWF_60E_out
						FWF_60E_out=$(( ${explode[19]} + ( $FWF_60E_out - ${explode[17]} )))
					fi
					
					####################################################
					#APC_VLAN20_in and APC_VLAN20_out
					####################################################
					#did the Fortigate value roll over 4294967295?
					if [ $APC_VLAN20_in -lt ${explode[20]} ]; then #is APC_VLAN20_in less than the previous time we captures it's value? if it is less than the previous time, then the value must have rolled over
						APC_VLAN20_in_tracking=$APC_VLAN20_in #save the current value of APC_VLAN20_in so we can compare it next time
						APC_VLAN20_in=$((( $APC_VLAN20_in + ${explode[22]} ) + ( 4294967295 - ${explode[20]} ))) # since APC_VLAN20_in rolled over, let's add its current value to our 64 but running counter, and also account for any delta between the old wan_in value that was below the 32 bit limit and the bit limit itself
					else
						APC_VLAN20_in_tracking=$APC_VLAN20_in #save the current value of APC_VLAN20_in so we can compare it next time
						APC_VLAN20_in=$(( ${explode[22]} + ( $APC_VLAN20_in - ${explode[20]} )))
					fi

					#did the Fortigate value roll over 4294967295?
					if [ $APC_VLAN20_out -lt ${explode[21]} ]; then
						APC_VLAN20_out_tracking=$APC_VLAN20_out
						APC_VLAN20_out=$((( $APC_VLAN20_out + ${explode[23]} ) + ( 4294967295 - ${explode[21]} )))
					else
						APC_VLAN20_out_tracking=$APC_VLAN20_out
						APC_VLAN20_out=$(( ${explode[23]} + ( $APC_VLAN20_out - ${explode[21]} )))
					fi
					
					####################################################
					#Tablo_VLAN21_in and Tablo_VLAN21_out
					####################################################
					#did the Fortigate value roll over 4294967295?
					if [ $Tablo_VLAN21_in -lt ${explode[24]} ]; then #is Tablo_VLAN21_in less than the previous time we captures it's value? if it is less than the previous time, then the value must have rolled over
						Tablo_VLAN21_in_tracking=$Tablo_VLAN21_in #save the current value of Tablo_VLAN21_in so we can compare it next time
						Tablo_VLAN21_in=$((( $Tablo_VLAN21_in + ${explode[26]} ) + ( 4294967295 - ${explode[24]} ))) # since Tablo_VLAN21_in rolled over, let's add its current value to our 64 but running counter, and also account for any delta between the old wan_in value that was below the 32 bit limit and the bit limit itself
					else
						Tablo_VLAN21_in_tracking=$Tablo_VLAN21_in #save the current value of Tablo_VLAN21_in so we can compare it next time
						Tablo_VLAN21_in=$(( ${explode[26]} + ( $Tablo_VLAN21_in - ${explode[24]} )))
					fi

					#did the Fortigate value roll over 4294967295?
					if [ $Tablo_VLAN21_out -lt ${explode[25]} ]; then
						Tablo_VLAN21_out_tracking=$Tablo_VLAN21_out
						Tablo_VLAN21_out=$((( $Tablo_VLAN21_out + ${explode[27]} ) + ( 4294967295 - ${explode[25]} )))
					else
						Tablo_VLAN21_out_tracking=$Tablo_VLAN21_out
						Tablo_VLAN21_out=$(( ${explode[27]} + ( $Tablo_VLAN21_out - ${explode[25]} )))
					fi
					
					####################################################
					#Roku_VLAN22_in and Roku_VLAN22_out
					####################################################
					#did the Fortigate value roll over 4294967295?
					if [ $Roku_VLAN22_in -lt ${explode[28]} ]; then #is Roku_VLAN22_in less than the previous time we captures it's value? if it is less than the previous time, then the value must have rolled over
						Roku_VLAN22_in_tracking=$Roku_VLAN22_in #save the current value of Roku_VLAN22_in so we can compare it next time
						Roku_VLAN22_in=$((( $Roku_VLAN22_in + ${explode[30]} ) + ( 4294967295 - ${explode[28]} ))) # since Roku_VLAN22_in rolled over, let's add its current value to our 64 but running counter, and also account for any delta between the old wan_in value that was below the 32 bit limit and the bit limit itself
					else
						Roku_VLAN22_in_tracking=$Roku_VLAN22_in #save the current value of Roku_VLAN22_in so we can compare it next time
						Roku_VLAN22_in=$(( ${explode[30]} + ( $Roku_VLAN22_in - ${explode[28]} )))
					fi

					#did the Fortigate value roll over 4294967295?
					if [ $Roku_VLAN22_out -lt ${explode[29]} ]; then
						Roku_VLAN22_out_tracking=$Roku_VLAN22_out
						Roku_VLAN22_out=$((( $Roku_VLAN22_out + ${explode[31]} ) + ( 4294967295 - ${explode[29]} )))
					else
						Roku_VLAN22_out_tracking=$Roku_VLAN22_out
						Roku_VLAN22_out=$(( ${explode[31]} + ( $Roku_VLAN22_out - ${explode[29]} )))
					fi
					
					####################################################
					#Denon_VLAN24_in and Denon_VLAN24_out
					####################################################
					#did the Fortigate value roll over 4294967295?
					if [ $Denon_VLAN24_in -lt ${explode[32]} ]; then #is Denon_VLAN24_in less than the previous time we captures it's value? if it is less than the previous time, then the value must have rolled over
						Denon_VLAN24_in_tracking=$Denon_VLAN24_in #save the current value of Denon_VLAN24_in so we can compare it next time
						Denon_VLAN24_in=$((( $Denon_VLAN24_in + ${explode[34]} ) + ( 4294967295 - ${explode[32]} ))) # since Denon_VLAN24_in rolled over, let's add its current value to our 64 but running counter, and also account for any delta between the old wan_in value that was below the 32 bit limit and the bit limit itself
					else
						Denon_VLAN24_in_tracking=$Denon_VLAN24_in #save the current value of Denon_VLAN24_in so we can compare it next time
						Denon_VLAN24_in=$(( ${explode[34]} + ( $Denon_VLAN24_in - ${explode[32]} )))
					fi

					#did the Fortigate value roll over 4294967295?
					if [ $Denon_VLAN24_out -lt ${explode[33]} ]; then
						Denon_VLAN24_out_tracking=$Denon_VLAN24_out
						Denon_VLAN24_out=$((( $Denon_VLAN24_out + ${explode[35]} ) + ( 4294967295 - ${explode[33]} )))
					else
						Denon_VLAN24_out_tracking=$Denon_VLAN24_out
						Denon_VLAN24_out=$(( ${explode[35]} + ( $Denon_VLAN24_out - ${explode[33]} )))
					fi
					
					####################################################
					#guest_wifi_in and guest_wifi_out
					####################################################
					#did the Fortigate value roll over 4294967295?
					if [ $guest_wifi_in -lt ${explode[36]} ]; then #is guest_wifi_in less than the previous time we captures it's value? if it is less than the previous time, then the value must have rolled over
						guest_wifi_in_tracking=$guest_wifi_in #save the current value of guest_wifi_in so we can compare it next time
						guest_wifi_in=$((( $guest_wifi_in + ${explode[38]} ) + ( 4294967295 - ${explode[36]} ))) # since guest_wifi_in rolled over, let's add its current value to our 64 but running counter, and also account for any delta between the old wan_in value that was below the 32 bit limit and the bit limit itself
					else
						guest_wifi_in_tracking=$guest_wifi_in #save the current value of guest_wifi_in so we can compare it next time
						guest_wifi_in=$(( ${explode[38]} + ( $guest_wifi_in - ${explode[36]} )))
					fi

					#did the Fortigate value roll over 4294967295?
					if [ $guest_wifi_out -lt ${explode[37]} ]; then
						guest_wifi_out_tracking=$guest_wifi_out
						guest_wifi_out=$((( $guest_wifi_out + ${explode[39]} ) + ( 4294967295 - ${explode[37]} )))
					else
						guest_wifi_out_tracking=$guest_wifi_out
						guest_wifi_out=$(( ${explode[39]} + ( $guest_wifi_out - ${explode[37]} )))
					fi

					
					echo "$wan_in_tracking,$wan_out_tracking,$wan_in,$wan_out,$internal_in_tracking,$internal_out_tracking,$internal_in,$internal_out,$wifi_in_tracking,$wifi_out_tracking,$wifi_in,$wifi_out,$lan_in_tracking,$lan_out_tracking,$lan_in,$lan_out,$FWF_60E_in_tracking,$FWF_60E_out_tracking,$FWF_60E_in,$FWF_60E_out,$APC_VLAN20_in_tracking,$APC_VLAN20_out_tracking,$APC_VLAN20_in,$APC_VLAN20_out,$Tablo_VLAN21_in_tracking,$Tablo_VLAN21_out_tracking,$Tablo_VLAN21_in,$Tablo_VLAN21_out,$Roku_VLAN22_in_tracking,$Roku_VLAN22_out_tracking,$Roku_VLAN22_in,$Roku_VLAN22_out,$Denon_VLAN24_in_tracking,$Denon_VLAN24_out_tracking,$Denon_VLAN24_in,$Denon_VLAN24_out,$guest_wifi_in_tracking,$guest_wifi_out_tracking,$guest_wifi_in,$guest_wifi_out,$wan_total_data,$lastHour_wan,$lastDay_wan,$lastMonth_wan" > /volume1/web/logging/notifications/fortigate_data_transfer_variable.txt
				else
					
					echo "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0" > /volume1/web/logging/notifications/fortigate_data_transfer_variable.txt
				fi
				
				post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name wan_in=$wan_in,wan_out=$wan_out,internal_in=$internal_in,internal_out=$internal_out,wifi_in=$wifi_in,wifi_out=$wifi_out,lan_in=$lan_in,lan_out=$lan_out,FWF_60E_in=$FWF_60E_in,FWF_60E_out=$FWF_60E_out,APC_VLAN20_in=$APC_VLAN20_in,APC_VLAN20_out=$APC_VLAN20_out,Tablo_VLAN21_in=$Tablo_VLAN21_in,Tablo_VLAN21_out=$Tablo_VLAN21_out,Roku_VLAN22_in=$Roku_VLAN22_in,Roku_VLAN22_out=$Roku_VLAN22_out,Denon_VLAN24_in=$Denon_VLAN24_in,Denon_VLAN24_out=$Denon_VLAN24_out,lastHour_wan=$lastHour_wan,lastDay_wan=$lastDay_wan,lastMonth_wan=$lastMonth_wan,guest_wifi_in=$guest_wifi_in,guest_wifi_out=$guest_wifi_out
		"
				
			else
				echo "Skipping Data Transfer capture"
			fi
			
			
			#GETTING SSL VPN INFO
			if [ $capture_SSLVPN -eq 1 ]
			then
				measurement="fortigate_SSLVPN"
					
				#number of active tunnels
				ssl_stats_active_tunnels=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.3.1.6 -Oqv`
				
				if [[ "$ssl_stats_active_tunnels" == "No Such Instance currently exists at this OID" ]]; then
					echo "no active SSL tunnels"
					ssl_stats_active_tunnels=0
				else
					echo "Number of Acvtive SSLVPN sessions: $ssl_stats_active_tunnels"
				fi
				
				#SSLVPN active users
				ssl_tunnel_user_name=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.4.1.3 -Oqv`
				
				#removing unneeded " characters before and after serial number
				ssl_tunnel_user_name=${ssl_tunnel_user_name//\"/$secondString}
				
				#source IP of active users
				ssl_tunnel_src_ip=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.4.1.4 -Oqv`
				
				#removing unneeded " characters before and after serial number
				ssl_tunnel_src_ip=${ssl_tunnel_src_ip//\"/$secondString}
				
				#IP assigned to active tunnel
				ssl_tunnel_ip=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.4.1.5 -Oqv`
				
				#removing unneeded " characters before and after serial number
				ssl_tunnel_ip=${ssl_tunnel_ip//\"/$secondString}
				
				#uptime of active tunnel
				ssl_tunnel_up_time=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.4.1.6 -Oqv`
				
				#removing unneeded " characters before and after serial number
				ssl_tunnel_up_time=${ssl_tunnel_up_time//\"/$secondString}
				
				#bytes received on tunnel
				ssl_tunnel_byte_in=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.4.1.7 -Oqv`
				
				#removing unneeded " characters before and after serial number
				ssl_tunnel_byte_in=${ssl_tunnel_byte_in//\"/$secondString}
				
				#bytes sent on tunnel
				ssl_tunnel_byte_out=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.4.1.8 -Oqv`
				
				#removing unneeded " characters before and after serial number
				ssl_tunnel_byte_out=${ssl_tunnel_byte_out//\"/$secondString}
				
				if [ $ssl_stats_active_tunnels -gt 0 ]
					then
						#explode out the different user names, separated by \n
						explode1=(`echo $ssl_tunnel_up_time | sed 's/,/\n/g'`)
						#explode out the different user names, separated by \n
						explode2=(`echo $ssl_tunnel_ip | sed 's/,/\n/g'`)
						#explode out the different user names, separated by \n
						explode3=(`echo $ssl_tunnel_src_ip | sed 's/,/\n/g'`)
						#explode out the different user names, separated by \n
						explode4=(`echo $ssl_tunnel_user_name | sed 's/,/\n/g'`)
						#explode out the different bytes in, separated by \n
						explode5=(`echo $ssl_tunnel_byte_in | sed 's/,/\n/g'`)
						#explode out the different bytes in, separated by \n
						explode6=(`echo $ssl_tunnel_byte_out | sed 's/,/\n/g'`)
						ii=0
						sql_insert_command="INSERT INTO fortigate (num_sessions, user0_username, user1_username, user2_username, user3_username, user4_username, user0_source_IP, user1_source_IP, user2_source_IP, user3_source_IP, user4_source_IP, user0_tunnel_ip, user1_tunnel_ip, user2_tunnel_ip, user3_tunnel_ip, user4_tunnel_ip, user0_uptime, user1_uptime, user2_uptime, user3_uptime, user4_uptime, user0_bytes_in, user1_bytes_in, user2_bytes_in, user3_bytes_in, user4_bytes_in, user0_bytes_out, user1_bytes_out, user2_bytes_out, user3_bytes_out, user4_bytes_out) VALUES ("
						
						if [ $ssl_stats_active_tunnels -eq 1 ]; then
							sql_insert_command=$sql_insert_command"$ssl_stats_active_tunnels, '${explode4[0]}', '', '', '', '', '${explode3[0]}', '', '', '', '', '${explode2[0]}', '', '', '', '', ${explode1[0]}, 0, 0, 0, 0, ${explode5[0]}, 0, 0, 0, 0, ${explode6[0]}, 0, 0, 0, 0);"
							
							#post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name ssl_stats_active_tunnels=$ssl_stats_active_tunnels,user0_username=${explode4[0]},user1_username="",user2_username="",user3_username="",user4_username="",user0_source_IP=${explode3[0]},user1_source_IP="",user2_source_IP="",user3_source_IP="",user4_source_IP="",user0_tunnel_ip=${explode2[0]},user1_tunnel_ip="",user2_tunnel_ip="",user3_tunnel_ip="",user4_tunnel_ip="",user0_uptime=${explode1[0]},user1_uptime=0,user2_uptime=0,user3_uptime=0,user4_uptime=0,user0_bytes_in=${explode5[0]},user1_bytes_in=0,user2_bytes_in=0,user3_bytes_in=0,user4_bytes_in=0,user0_bytes_out=${explode6[0]},user1_bytes_out=0,user2_bytes_out=0,user3_bytes_out=0,user4_bytes_out=0
							#"
						fi 
						
						if [ $ssl_stats_active_tunnels -eq 2 ]; then
							sql_insert_command=$sql_insert_command"$ssl_stats_active_tunnels, '${explode4[0]}', '${explode4[1]}', '', '', '', '${explode3[0]}', '${explode3[1]}', '', '', '', '${explode2[0]}', '${explode2[1]}', '', '', '', ${explode1[0]}, ${explode1[1]}, 0, 0, 0, ${explode5[0]}, ${explode5[1]}, 0, 0, 0, ${explode6[0]}, ${explode6[1]}, 0, 0, 0);"
						fi 
						
						if [ $ssl_stats_active_tunnels -eq 3 ]; then
							sql_insert_command=$sql_insert_command"$ssl_stats_active_tunnels, '${explode4[0]}', '${explode4[1]}', '${explode4[2]}', '', '', '${explode3[0]}', '${explode3[1]}', '${explode3[2]}', '', '', '${explode2[0]}', '${explode2[1]}', '${explode2[2]}', '', '', ${explode1[0]}, ${explode1[1]}, ${explode1[2]}, '', '', ${explode5[0]}, ${explode5[1]}, ${explode5[2]}, 0, 0,${explode6[0]}, ${explode6[1]}, ${explode6[2]}, 0, 0);"
						fi
						
						if [ $ssl_stats_active_tunnels -eq 4 ]; then
							sql_insert_command=$sql_insert_command"$ssl_stats_active_tunnels, '${explode4[0]}', '${explode4[1]}', '${explode4[2]}', '${explode4[3]}', '', '${explode3[0]}', '${explode3[1]}', '${explode3[2]}', '${explode3[3]}', '', '${explode2[0]}', '${explode2[1]}', '${explode2[2]}', '${explode2[3]}', '', ${explode1[0]}, ${explode1[1]}, ${explode1[2]}, ${explode1[3]}, 0, ${explode5[0]}, ${explode5[1]}, ${explode5[2]}, ${explode5[3]}, 0, ${explode6[0]}, ${explode6[1]}, ${explode6[2]}, ${explode6[3]}, 0);"
						fi
						
						if [ $ssl_stats_active_tunnels -eq 5 ]; then
							sql_insert_command=$sql_insert_command"$ssl_stats_active_tunnels, '${explode4[0]}', '${explode4[1]}', '${explode4[2]}', '${explode4[3]}', '${explode4[4]}', '${explode3[0]}', '${explode3[1]}', '${explode3[2]}', '${explode3[3]}', '${explode3[4]}', '${explode2[0]}', '${explode2[1]}', '${explode2[2]}', '${explode2[3]}', '${explode2[4]}', ${explode1[0]}, ${explode1[1]}, ${explode1[2]}, ${explode1[3]}, ${explode1[4]}, ${explode5[0]}, ${explode5[1]}, ${explode5[2]}, ${explode5[3]}, ${explode5[4]}, ${explode6[0]}, ${explode6[1]}, ${explode6[2]}, ${explode6[3]}, ${explode6[4]});"
						fi
						
						cd /volume1/@appstore/MariaDB10/usr/local/mariadb10/bin

						./mysql -u root -ppassword -D network -e "$sql_insert_command"
				
					else
						#post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name ssl_stats_active_tunnels=$ssl_stats_active_tunnels,user0_username='',user1_username='',user2_username='',user3_username='',user4_username='',user0_source_IP='',user1_source_IP='',user2_source_IP='',user3_source_IP='',user4_source_IP='',user0_tunnel_ip='',user1_tunnel_ip='',user2_tunnel_ip='',user3_tunnel_ip='',user4_tunnel_ip='',user0_uptime=0,user1_uptime=0,user2_uptime=0,user3_uptime=0,user4_uptime=0,user0_bytes_in=0,user1_bytes_in=0,user2_bytes_in=0,user3_bytes_in=0,user4_bytes_in=0,user0_bytes_out=0,user1_bytes_out=0,user2_bytes_out=0,user3_bytes_out=0,user4_bytes_out=0
						#"
						echo "no active tunnels"
					fi
				post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name ssl_stats_active_tunnels=$ssl_stats_active_tunnels
						"
			else
				echo "Skipping SSLVPN capture"
			fi
			
			# GETTING FIREWALL POLICY DETAILS
			if [ $capture_FW_policy -eq 1 ]
			then
				
				measurement="fortigate_fw_policy"
				
				#getting policy IDs
				policy_id=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.5.1.2.1.1.1 -Ovt`
				secondString=""
				policy_id=${policy_id//\INTEGER: /$secondString}
				
				#explode out the different user names, separated by \n
				policy_id_explode=(`echo $policy_id | sed 's/,/\n/g'`)
				
				##################################################
				#getting policy last time used (in minutes)
				policy_last_used=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.5.1.2.1.1.4 -Ovt`
				
				secondString=""
				policy_last_used=${policy_last_used//\STRING: /$secondString}
				
				secondString=""
				policy_last_used=${policy_last_used//\"/$secondString}
				
				#replacing text string "ago)" with character "@" to allow for array exploding using the "@" as the deliniator
				secondString="@"
				policy_last_used=${policy_last_used//\ago)/$secondString}
				
				#replacing text string "data" with character "@" to allow for array exploding using the "@" as the deliniator
				secondString="@"
				policy_last_used=${policy_last_used//\Data/$secondString}
				
				#explode out the different items, separated by \n
				IFS="@" read -a policy_last_used_explode <<< $policy_last_used
				
								
				##################################################
				#getting policy data usage
				policy_data_used=`snmpwalk -v3 -l authPriv -u fortigate -a MD5 -A $AuthPass1 -x DES -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.5.1.2.1.1.6 -Ovt`
				
				#removing unneeded text "Counter64: \n" from SNMP output
				secondString=""
				policy_data_used=${policy_data_used//\Counter64: /$secondString}
				
				#explode out the different items, separated by \n
				policy_data_used_explode=(`echo $policy_data_used | sed 's/,/\n/g'`)
				
				
				post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name "
				xx=0
				for xx in "${!policy_id_explode[@]}"; do
					post_url=$post_url"policy${policy_id_explode[${xx}]}_last_used=\"${policy_last_used_explode[${xx}]}\",policy${policy_id_explode[${xx}]}_data_used=${policy_data_used_explode[${xx}]},"
				done
				
				post_url=$post_url"number_policy=$xx"
				
				
			
				#post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name memory_usage=$memory_usage,memory_capacity=$memory_capacity
		#"
			else
				echo "Skipping FIREWALL POLICY DETAILS capture"
			fi
			
			
		
			
			#Post to influxdb
			#if [[ -z $influxdb_user ]]; then
			#	curl -i -XPOST "http://$influxdb_host:$influxdb_port/write?db=$influxdb_name" --data-binary "$post_url"
			#else
			#	curl -i -XPOST "http://$influxdb_host:$influxdb_port/write?u=$influxdb_user&p=$influxdb_pass&db=$influxdb_name" --data-binary "$post_url"
			#fi
			curl -XPOST "http://$influxdb_host:$influxdb_port/api/v2/write?bucket=$influxdb_name&org=home" -H "Authorization: Token $influxdb_pass" --data-raw "$post_url"
			echo "$post_url"
			
			let i=i+1
			
			echo "Capture #$i complete"
			
			#Sleeping for capture interval unless its last capture then we dont sleep
			if (( $i < $total_executions)); then
				sleep $(( $capture_interval -2))
			else
			#	#increment each disk counter by one to keep track of "minutes elapsed" since this script is expected to execute every minute 
				let memory_email=memory_email+1
			#	#save the increments to a file so we can get that back on the next execution of the script 
				echo "$memory_email" > /volume1/web/logging/notifications/fortigate_logging_variable.txt
			fi
			
		done
	else
		echo "script is disabled"
	fi
else
	echo "Configuration file unavailable"
fi
