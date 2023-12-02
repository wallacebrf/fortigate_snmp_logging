#!/bin/bash
#Version 12/02/2023
#By Brian Wallace

#This script pulls various information from a fortigate unit over SNMP

#############################################
#REVISION HISTORY
#############################################
# 3/17/23 -- initial release

# 8/27/2023 
	#1.) added fortigate sensor data collection and notifications emails. updated PHP web interface to allow configuration of up to 10x sensors being >, <, or = a user defined value of their choosing 
	#2.) corrected "number of polices" reported, as it was off by 1
	#3.) rewrote some sections to make code more efficient. on my test fortigate reduced script execution by 0.2 seconds 
	#4.) corrected issue with USB data reporting 
	#5.) updated CPU usage data collection to not hard code only the first 4x CPU cores. Code now will collect any/all cores on its own
	#6.) updated the fortiAP data collection to collect based on FAP serial number rather than IP address
		#code now gets data from the fortigate rather than directly from the FortiAP. this allows gathering more data. it also speeds up the script as it does not need to ping the FAP. 
		#FAP specific SNMP user/password is no longer needed as all data is collected directly from the fortigate. 
		#also updated the FortiAP SNMP failure email notifications to distinguish between FAP being offline or just returning bad data

# 10/19/2023
	#modified the snmp_fail_fortAP_email function code to accept a different input parameter
	#new parameter is the next of the email title and body directly
	#this add more detail to the title and email body text like why the email is being sent based on the different status the AP can be in
	#made code slightly simpler. 

# 12/02/2023
	#modified the snmp_fail_fortAP_email function to change the email subject and to add the current time of the message inside the email body
	#added fortiAP monitoring of the number of clients connected to the access point

#############################################
#VERIFICATIONS
#############################################

#*NOTICE! - I AM NOT USING IPSEC VPN SO I CANNOT VERIFY THE CODE WORKS PROPERLY FOR THAT SECTION

#1.) data is collected into influx properly......................................................................... VERIFIED 8/27/2023*
	#NOTICE - I do not use IPSEC VPNs and so I cannot determine if the code section works. if you use this and IPSEC is not logging, please let me know.
#2.) SNMP errors:
	#a.) bad SNMP username causes script to shutdown with email..................................................... VERIFIED 8/27/2023
	#b.) bad SNMP authpass causes script to shutdown with email..................................................... VERIFIED 8/27/2023
	#c.) bad SNMP privacy pass causes script to shutdown with email................................................. VERIFIED 8/27/2023
	#d.) bad SNMP ip address causes script to shutdown with email................................................... VERIFIED 8/27/2023
	#e.) bad SNMP port causes script to shutdown with email......................................................... VERIFIED 8/27/2023
	#f.) error emails a through e above only are sent within the allowed time interval.............................. VERIFIED 8/27/2023
#3.) verify that when "sendmail" is unavailable, emails are not sent, and the appropriate warnings are displayed.... VERIFIED 8/27/2023
#4.) verify script behavior when config file is unavailable......................................................... VERIFIED 8/27/2023
#5.) verify script behavior when config file has wrong number of arguments.......................................... VERIFIED 8/27/2023
#6.) verify script behavior when the target device is not available................................................. VERIFIED 8/27/2023
#7.) verify email send when memory usage is over limit and only sends emails within allowed time interval........... VERIFIED 8/27/2023
#8.) Verify fortiAP emails are sent if the AP is not "ONLINE"....................................................... VERIFIED 8/27/2023
#9.) Verify disk space overages send email notification............................................................. VERIFIED 8/27/2023
#10.) Verify USB device connections send email notification......................................................... VERIFIED 8/27/2023
#11.) verify emails are sent when sensors are outside of configured parameters...................................... VERIFIED 8/27/2023

#########################################
#variable initialization
#########################################

config_file_location="/volume1/web/config/config_files/config_files_local/fortigate_config.txt"
lock_file_location="/volume1/web/logging/notifications/fortigate_snmp.lock"
email_last_sent="/volume1/web/logging/notifications/fortigate_snmp_last_email_sent.txt"
log_file_location="/volume1/web/logging/notifications"

#########################################################
#EMAIL SETTINGS USED IF CONFIGURATION FILE IS UNAVAILABLE
#These variables will be overwritten with new corrected data if the configuration file loads properly. 
email_address="admin@email.com"
from_email_address="admin@email..com"
#########################################################

#########################################################
#this function pings google.com to confirm internet access is working prior to sending email notifications 
#########################################################
check_internet() {
ping -c1 "www.google.com" > /dev/null #ping google.com									
	local status=$?
	if ! (exit $status); then
		false
	else
		true
	fi
}

#########################################################
#this function removes unneeded text "STRING: " from SNMP output, and unneeded " characters
#########################################################
function filter_data(){
	local sub_string_to_remove="$1"
	local item_being_filtered="$2"
	local filtered=$(echo ${item_being_filtered#${sub_string_to_remove}})
	local secondString=""
	filtered=${filtered//\"/$secondString}
	echo "$filtered"
}

#########################################################
#this function is used to send notification if the SNMP data collection fails
#########################################################
function snmp_fail_fortigate_email(){
	if check_internet; then
		if [ $sendmail_installed -eq 1 ]; then
			local current_time=$( date +%s )
			if [ -r "$email_last_sent" ]; then #file is available and readable 
				read message_tracker < $email_last_sent
				local time_diff=$((( $current_time - $message_tracker ) / 60 ))
			else
				echo -n "$current_time" > $email_last_sent
				local time_diff=$(( $email_interval + 1 ))
			fi
				
			if [ $time_diff -ge $email_interval ]; then
				local now=$(date +"%T")
				echo "the email has not been sent in over $email_interval minutes, re-sending email"
				local mailbody="$now - ALERT Fortigate Unit at IP $snmp_device_url appears to have an issue with SNMP as it returned invalid data or was not reachable. Script \"${0##*/}\" failed"
				echo "from: $from_email_address " > $log_file_location/fortigate_contents.txt
				echo "to: $email_address " >> $log_file_location/fortigate_contents.txt
				echo "subject: Fortigate SNMP Data Collection failed" >> $log_file_location/fortigate_contents.txt
				echo "" >> $log_file_location/fortigate_contents.txt
				echo $mailbody >> $log_file_location/fortigate_contents.txt
				local email_response=$(sendmail -t < $log_file_location/fortigate_contents.txt  2>&1)
				if [[ "$email_response" == "" ]]; then
					echo "" |& tee -a $log_file_location/fortigate_contents.txt
					echo "Email Sent Successfully" |& tee -a $log_file_location/fortigate_contents.txt
					message_tracker=$current_time
					time_diff=0
					echo -n "$message_tracker" > $email_last_sent
				else
					echo "Warning, an error occurred while sending the Fortigate SNMP Failure notification email. the error was: $email_response" |& tee -a $log_file_location/fortigate_contents.txt
				fi
			else
				echo "Only $time_diff minuets have passed since the last notification, email will be sent every $email_interval minutes. $(( $email_interval - $time_diff )) Minutes Remaining Until Next Email"
			fi
		else
			echo "Unable to send email, \"sendmail\" command is unavailable"
		fi
	else
		echo "Internet is not available, skipping sending email"
	fi
	exit 1
}

#########################################################
#this function is used to send notification if the SNMP data collection fails
#########################################################
function snmp_fail_fortAP_email(){
#fortiap_device_serial=${1}
#fail_text=${2}
	echo "${2}"
	echo ""
	if check_internet; then
		if [ $sendmail_installed -eq 1 ]; then
			local current_time=$( date +%s )
			if [ -r "$email_last_sent" ]; then #file is available and readable 
				read message_tracker < $email_last_sent
				local time_diff=$((( $current_time - $message_tracker ) / 60 ))
			else
				echo -n "$current_time" > $email_last_sent
				local time_diff=$(( $email_interval + 1 ))
			fi
				
			if [ $time_diff -ge $email_interval ]; then
				local now=$(date +"%T")
				echo "the email has not been sent in over $email_interval minutes, re-sending email"
				echo "from: $from_email_address " > $log_file_location/fortigate_contents.txt
				echo "to: $email_address " >> $log_file_location/fortigate_contents.txt
				echo "subject: FORTI-AP OFFLINE" >> $log_file_location/fortigate_contents.txt
				echo "" >> $log_file_location/fortigate_contents.txt
				echo "$now - ${2}" >> $log_file_location/fortigate_contents.txt #adding the mailbody text. 
				local email_response=$(sendmail -t < $log_file_location/fortigate_contents.txt  2>&1)
				if [[ "$email_response" == "" ]]; then
					echo "" |& tee -a $log_file_location/fortigate_contents.txt
					echo "Email Sent Successfully" |& tee -a $log_file_location/fortigate_contents.txt
					message_tracker=$current_time
					time_diff=0
					echo -n "$message_tracker" > $email_last_sent
				else
					echo "Warning, an error occurred while sending the FORTIAP SNMP Failure notification email. the error was: $email_response" |& tee -a $log_file_location/fortigate_contents.txt
				fi
			else
				echo "Only $time_diff minuets have passed since the last notification, email will be sent every $email_interval minutes. $(( $email_interval - $time_diff )) Minutes Remaining Until Next Email"
			fi
		else
			echo "Unable to send email, \"sendmail\" command is unavailable"
		fi
	else
		echo "Internet is not available, skipping sending email"
	fi
}

#########################################################
#SCRIPT START
#########################################################

#create a lock file in the ramdisk directory to prevent more than one instance of this script from executing at once
if ! mkdir $lock_file_location; then
	echo "Failed to acquire lock.\n" >&2
	exit 1
fi
trap 'rm -rf $lock_file_location' EXIT #remove the lockdir on exit

#verify MailPlus Server package is installed and running as the "sendmail" command is not installed in Synology by default. the MailPlus Server package is required
install_check=$(/usr/syno/bin/synopkg list | grep MailPlus-Server)

if [ "$install_check" = "" ];then
	echo "WARNING!  ----   MailPlus Server NOT is installed, cannot send email notifications"
	sendmail_installed=0
else
	#echo "MailPlus Server is installed, verify it is running and not stopped"
	status=$(/usr/syno/bin/synopkg is_onoff "MailPlus-Server")
	if [ "$status" = "package MailPlus-Server is turned on" ]; then
		sendmail_installed=1
	else
		sendmail_installed=0
		echo "WARNING!  ----   MailPlus Server NOT is running, cannot send email notifications"
	fi
fi

#reading in variables from configuration file
if [ -r "$config_file_location" ]; then
	#file is available and readable 
	read input_read < $config_file_location
	explode=(`echo $input_read | sed 's/,/\n/g'`)
	
	#verify the correct number of configuration parameters are in the configuration file
	if [[ ! ${#explode[@]} == 70 ]]; then
		echo "WARNING - the configuration file is incorrect or corrupted. It should have 70 parameters, it currently has ${#explode[@]} parameters."
		exit 1
	fi	
	
	email_address=${explode[0]}
	email_interval=${explode[1]}
	capture_system=${explode[2]}
	capture_memory=${explode[3]}
	capture_cpu=${explode[4]}
	data_transfer=${explode[5]}
	capture_SSLVPN=${explode[6]}
	capture_FW_policy=${explode[7]}
	capture_interval=${explode[8]}
	memory_limit=${explode[9]}
	snmp_device_url=${explode[10]}
	snmp_device_name=${explode[11]}
	influxdb_host=${explode[12]}
	influxdb_port=${explode[13]}
	influxdb_name=${explode[14]}
	influxdb_user=${explode[15]}
	influxdb_pass=${explode[16]}
	script_enable=${explode[17]}
	from_email_address=${explode[18]}
	AuthPass1=${explode[19]}
	PrivPass2=${explode[20]}
	snmp_privacy_protocol=${explode[21]}
	snmp_auth_protocol=${explode[22]}
	snmp_user=${explode[23]}
	capture_disk=${explode[24]}
	capture_USB=${explode[25]}
	capture_antivirus_stats=${explode[26]}
	capture_web_filter_stats=${explode[27]}
	capture_access_point=${explode[28]}	
	accesspoint_list=${explode[29]}	
	enable_access_point_down_email=${explode[31]}
	capture_IPSEC_VPN=${explode[32]}
	enable_disk_space_warning_email=${explode[33]}
	disk_space_warning_threashold=${explode[34]}
	enable_USB_port_state_change_email=${explode[35]}
	influxdb_org=${explode[36]}
	influxdb_http_type=${explode[37]}
	
	sensor_paramter_name+=(${explode[38]})
	sensor_paramter_name+=(${explode[40]})
	sensor_paramter_name+=(${explode[42]})
	sensor_paramter_name+=(${explode[44]})
	sensor_paramter_name+=(${explode[46]})
	sensor_paramter_name+=(${explode[48]})
	sensor_paramter_name+=(${explode[50]})
	sensor_paramter_name+=(${explode[52]})
	sensor_paramter_name+=(${explode[54]})
	sensor_paramter_name+=(${explode[56]})
	
	sensor_paramter_type+=(${explode[58]})
	sensor_paramter_type+=(${explode[59]})
	sensor_paramter_type+=(${explode[60]})
	sensor_paramter_type+=(${explode[61]})
	sensor_paramter_type+=(${explode[62]})
	sensor_paramter_type+=(${explode[63]})
	sensor_paramter_type+=(${explode[64]})
	sensor_paramter_type+=(${explode[65]})
	sensor_paramter_type+=(${explode[66]})
	sensor_paramter_type+=(${explode[67]})
	
	sensor_paramter_notification_threshold+=(${explode[39]})
	sensor_paramter_notification_threshold+=(${explode[41]})
	sensor_paramter_notification_threshold+=(${explode[43]})
	sensor_paramter_notification_threshold+=(${explode[45]})
	sensor_paramter_notification_threshold+=(${explode[47]})
	sensor_paramter_notification_threshold+=(${explode[49]})
	sensor_paramter_notification_threshold+=(${explode[51]})
	sensor_paramter_notification_threshold+=(${explode[53]})
	sensor_paramter_notification_threshold+=(${explode[55]})
	sensor_paramter_notification_threshold+=(${explode[57]})
	
	enable_sensor_email_notifications=${explode[68]}
	capture_sensors=${explode[69]}
	
	if [ $script_enable -eq 1 ]
	then
			
		#collect device Serial number
		serial_number=$(snmpwalk -v3 -r 1 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.100.1.1.1.0 -Ovt 2>&1)
				
				
		#since $serial_number is the first time we have performed a SNMP request, let's make sure we did not receive any errors that could be caused by things like bad passwords, bad user name, incorrect auth or privacy types etc
		#if we receive an error now, then something is wrong with the SNMP settings and this script will not be able to function so we should exit out of it. 
		#the five main error are
		#1 - too short of a password
			#Error: pass phrase chosen is below the length requirements of the USM (min=8).
			#snmpwalk:  (The supplied password length is too short.)
			#Error generating a key (Ku) from the supplied privacy pass phrase.

		#2
			#Timeout: No Response from localhost:161
		#3
			#snmpwalk: Unknown user name

		#4
			#snmpwalk: Authentication failure (incorrect password, community or key)
				
		#5
			#we get nothing, the results are blank

				
		if [[ "$serial_number" == "Error:"* ]]; then #will search for the first error type
			echo "warning, the SNMP Auth password and or the Privacy password supplied is below the minimum 8 characters required. Exiting Script"
			snmp_fail_fortigate_email
		fi
				
		if [[ "$serial_number" == "Timeout:"* ]]; then #will search for the second error type
			echo "The SNMP target did not respond. This could be the result of a bad SNMP privacy password, the wrong IP address, the wrong port, or SNMP services not being enabled on the target device"
			echo "Exiting Script"
			snmp_fail_fortigate_email
		fi
				
		if [[ "$serial_number" == "snmpwalk: Unknown user name"* ]]; then #will search for the third error type
			echo "warning, The supplied username is incorrect. Exiting Script"
			snmp_fail_fortigate_email
		fi
				
		if [[ "$serial_number" == "snmpwalk: Authentication failure (incorrect password, community or key)"* ]]; then #will search for the fourth error type
			echo "The Authentication protocol or password is incorrect. Exiting Script"
			snmp_fail_fortigate_email
		fi
				
		if [[ "$serial_number" == "" ]]; then #will search for the fifth error type
			echo "Something is wrong with the SNMP settings, the results returned a blank/empty value. Exiting Script"
			snmp_fail_fortigate_email
		fi

		if [[ "$serial_number" == "snmpwalk: Timeout" ]]; then #will search for the fifth error type
			echo "The SNMP target did not respond. This could be the result of a bad SNMP privacy password, the wrong IP address, the wrong port, or SNMP services not being enabled on the target device"
			echo "Exiting Script"
			snmp_fail_fortigate_email
		fi

		if [ ! $capture_interval -eq 10 ]; then
			if [ ! $capture_interval -eq 15 ]; then
				if [ ! $capture_interval -eq 30 ]; then
					if [ ! $capture_interval -eq 60 ]; then
						echo "capture interval is not one of the allowable values of 10, 15, 30, or 60 seconds. Exiting the script"
						exit 1
					fi
				fi
			fi
		fi

		#loop the script 
		total_executions=$(( 60 / $capture_interval))
		echo "Capturing $total_executions times"
		i=0
		while [ $i -lt $total_executions ]; do
		
		#Create empty URL
		post_url=""

			#GETTING VARIOUS SYSTEM INFORMATION
			if [ $capture_system -eq 1 ]
			then
				
				measurement="fortigate_system"
				
				#removing unneeded text "STRING: " and unneeded " marks from SNMP output
				serial_number=$(filter_data "STRING: " "$serial_number")
				
				###################################################################################
				
				#System Version
				system_version=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.1.1.0 -Ovt`
				
				#removing unneeded text "STRING: " and unneeded " marks from SNMP output
				system_version=$(filter_data "STRING: " "$system_version")
				
				###################################################################################
				
				#System uptime  (in hundredths of a second)
				system_uptime=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.1.20.0 -Ovt`
				
				#removing unneeded text "Counter64: " and unneeded " marks from SNMP output
				system_uptime=$(filter_data "Counter64: " "$system_uptime")
				
				###################################################################################
				
				#System session count
				system_session_count=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.1.8.0 -Ovt`
				
				#removing unneeded text "Gauge32: " and unneeded " marks from SNMP output
				system_session_count=$(filter_data "Gauge32: " "$system_session_count")
				
				###################################################################################
				
				#System antivirus_version
				system_antivirus_version=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.2.1.0 -Ovt`
				
				#removing unneeded text "STRING: " and unneeded " marks from SNMP output
				system_antivirus_version=$(filter_data "STRING: " "$system_antivirus_version")
				
				###################################################################################
				
				#System IPS Version
				system_ips_version=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.2.2.0 -Ovt`
				
				#removing unneeded text "STRING: " and unneeded " marks from SNMP output
				system_ips_version=$(filter_data "STRING: " "$system_ips_version")
				
				###################################################################################
				
				#System antivirus_version extended
				system_antivirus_version_ex=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.2.3.0 -Ovt`
				
				#removing unneeded text "STRING: " and unneeded " marks from SNMP output
				system_antivirus_version_ex=$(filter_data "STRING: " "$system_antivirus_version_ex")
			
				###################################################################################
				
				#System IPS version extended
				system_ips_version_ex=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.2.4.0 -Ovt`
				
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
				memory_usage=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.1.4.0 -Ovt`
				
				#removing unneeded text "Gauge32: " and unneeded " marks from SNMP output
				memory_usage=$(filter_data "Gauge32: " "$memory_usage")
				
				#System memory capacity [Total physical memory (RAM) installed (KB)]
				memory_capacity=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.1.5.0 -Ovt`
				
				#removing unneeded text "Gauge32: " and unneeded " marks from SNMP output
				memory_capacity=$(filter_data "Gauge32: " "$memory_capacity")
				
				#Current memory threshold level to enter kernel conserve mode
				enter_kernel_conserve_mode=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.6.1.5 -Ovt`
				
				#removing unneeded text "Gauge32: " and unneeded " marks from SNMP output
				enter_kernel_conserve_mode=$(filter_data "Gauge32: " "$enter_kernel_conserve_mode")
				
				#Current memory threshold level to leave kernel conserve mode
				leave_kernel_conserve_mode=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.6.1.6 -Ovt`
				
				#removing unneeded text "Gauge32: " and unneeded " marks from SNMP output
				leave_kernel_conserve_mode=$(filter_data "Gauge32: " "$leave_kernel_conserve_mode")
				
				#Current memory threshold level to enter proxy conserve mode
				enter_proxy_conserve_mode=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.6.1.7 -Ovt`
				
				#removing unneeded text "Gauge32: " and unneeded " marks from SNMP output
				enter_proxy_conserve_mode=$(filter_data "Gauge32: " "$enter_proxy_conserve_mode")
				
				#Current memory threshold level to leave proxy conserve mode
				leave_proxy_conserve_mode=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.6.1.8 -Ovt`
				
				#removing unneeded text "Gauge32: " and unneeded " marks from SNMP output
				leave_proxy_conserve_mode=$(filter_data "Gauge32: " "$leave_proxy_conserve_mode")
				
				if [ $memory_usage -gt $memory_limit ]; then #the memory usage is getting too high
					if [ $sendmail_installed -eq 1 ]; then
						if check_internet; then
							current_time=$( date +%s )
							if [ -r "$email_last_sent" ]; then #file is available and readable 
								read message_tracker < $email_last_sent
								time_diff=$((( $current_time - $message_tracker ) / 60 ))
							else
								echo -n "$current_time" > $email_last_sent
								time_diff=$(( $email_interval + 1 ))
							fi

							if [ $time_diff -ge $email_interval ]; then
								now=$(date +"%T")
								mailbody="$now - Warning Fortigate Memory Usage has exceeded $memory_limit%. Current Memory usage is $memory_usage"
								echo "from: $from_email_address " > $log_file_location/fortigate_contents.txt
								echo "to: $email_address " >> $log_file_location/fortigate_contents.txt
								echo "subject: Fortigate Memory Warning " >> $log_file_location/fortigate_contents.txt
								echo "" >> $log_file_location/fortigate_contents.txt
								echo $mailbody >> $log_file_location/fortigate_contents.txt
								email_response=$(sendmail -t < $log_file_location/fortigate_contents.txt  2>&1)
								if [[ "$email_response" == "" ]]; then
									echo "" |& tee -a $log_file_location/fortigate_contents.txt
									echo "Email Sent Successfully" |& tee -a $log_file_location/fortigate_contents.txt
									message_tracker=$current_time
									time_diff=0
									echo -n "$message_tracker" > $email_last_sent
								else
									echo "Warning, an error occurred while sending the Fortigate Memory Usage notification email. the error was: $email_response" |& tee $log_file_location/fortigate_contents.txt
								fi
							else
								echo "Only $time_diff minuets have passed since the last notification, email will be sent every $email_interval minutes. $(( $email_interval - $time_diff )) Minutes Remaining Until Next Email"
							fi
						else
							echo "Internet is not available, skipping sending email"
						fi
					else
						echo "Unable to send email, \"sendmail\" command is unavailable"
					fi
				fi	
			
				post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name memory_usage=$memory_usage,memory_capacity=$memory_capacity,enter_kernel_conserve_mode=$enter_kernel_conserve_mode,leave_kernel_conserve_mode=$leave_kernel_conserve_mode,enter_proxy_conserve_mode=$enter_proxy_conserve_mode,leave_proxy_conserve_mode=$leave_proxy_conserve_mode

"
			else
				echo "Skipping memory capture"
			fi
			
			
			# GETTING DISK USAGE
			if [ $capture_disk -eq 1 ]
			then
				
				measurement="fortigate_disk"
				
				#Current hard disk usage (MB), if disk is present:
				disk_usage=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.1.6 -Ovt`
				
				#removing unneeded text "Gauge32: " and unneeded " marks from SNMP output
				disk_usage=$(filter_data "Gauge32: " "$disk_usage")
				
				#Total hard disk capacity (MB), if disk is present
				disk_size=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.1.7 -Ovt`
				
				#removing unneeded text "Gauge32: " and unneeded " marks from SNMP output
				disk_size=$(filter_data "Gauge32: " "$disk_size")
								
				disk_used_percent=$(echo $(( 100 * $disk_usage / $disk_size )))
				
				if [ $disk_used_percent -ge $disk_space_warning_threashold ]; then
					if [ $enable_disk_space_warning_email -eq 1 ]; then
						current_time=$( date +%s )
						if [ -r "$email_last_sent" ]; then #file is available and readable
							read message_tracker < $email_last_sent
							email_time_diff=$((( $current_time - $message_tracker ) / 60 ))
						else
							email_time_diff=1441 #send an email daily (60 min per hour * 24 hours = 1440 min)
							echo "$current_time" > $email_last_sent
						fi
								
						now=$(date +"%T")
						echo "Disk space usage on device IP $snmp_device_url is above $disk_space_warning_threashold percent. It is currently at $disk_used_percent percent."
						if [ $email_time_diff -ge 1440 ]; then
							if check_internet; then
								#send an email indicating script config file is missing and script will not run
								mailbody="$now - Disk space usage on device IP $snmp_device_url is above $disk_space_warning_threashold percent. It is currently at $disk_used_percent percent."
								echo "from: $from_email_address " > $log_file_location/fortigate_contents.txt
								echo "to: $email_address " >> $log_file_location/fortigate_contents.txt
								echo "subject: Fortigate Disk Usage Warning" >> $log_file_location/fortigate_contents.txt
								echo "" >> $log_file_location/fortigate_contents.txt
								echo $mailbody >> $log_file_location/fortigate_contents.txt
								
								if [[ "$email_address" == "" || "$from_email_address" == "" ]];then
									echo -e "\n\nNo email address information is configured, Cannot send an email about disk space usage"
								else
									if [ $sendmail_installed -eq 1 ]; then
										email_response=$(sendmail -t < $log_file_location/fortigate_contents.txt  2>&1)
										if [[ "$email_response" == "" ]]; then
											echo -e "\nEmail Sent Successfully" |& tee -a $log_file_location/fortigate_contents.txt
											echo "$current_time" > $email_last_sent
											email_time_diff=0
										else
											echo -e "\n\nWARNING -- An error occurred while sending email. The error was: $email_response\n\n" |& tee $log_file_location/fortigate_contents.txt
										fi	
									else
										echo "Unable to send email, \"sendmail\" command is unavailable"
									fi
								fi
							else
								echo "Internet is not available, skipping sending email"
							fi
						else
							echo -e "\n\nAnother email notification will be sent in $(( 1440 - $email_time_diff)) Minutes"
						fi
					fi
				fi
				post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name disk_usage=$disk_usage,disk_size=$disk_size,disk_used_percent=$disk_used_percent

"
			else
				echo "Skipping DISK capture"
			fi
			
			# GETTING USB USAGE
			if [ $capture_USB -eq 1 ]
			then
				
				measurement="fortigate_USB"
				
				#A unique identifier within the fgUsbportTable
				usb_identifier_array=()
				while IFS= read -r line; do
					
					usb_identifier=${line#*INTEGER: }; usb_identifier=${usb_identifier// /};usb_identifier=${usb_identifier//\"}
					usb_identifier_array+=($usb_identifier)
				
				done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.7.2.1.1 -Ovt)
						
				#The USB port's plugged status [unplugged(0), plugged(1)]
				usb_status_array=()
				while IFS= read -r line; do
					
					usb_identifier=${line#*INTEGER: }; usb_identifier=${usb_identifier// /};usb_identifier=${usb_identifier//\"}
					usb_status_array+=($usb_identifier)
				
				done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.7.2.1.2 -Ovt)
								
				#The USB device class [ifc(0), audio(1), comm(2), hid(3), physical(5), image(6), printer(7), storage(8), hub(9), cdcData(10), chipSmartCard(11), contentSecurity(13), appSpec(254), vendorSpec(255)]
				usb_device_array=()
				while IFS= read -r line; do
					
					usb_identifier=${line#*INTEGER: }; usb_identifier=${usb_identifier// /};usb_identifier=${usb_identifier//\"}
					usb_device_array+=($usb_identifier)
				
				done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.7.2.1.4 -Ovt)
				
				xx=0
				for xx in "${!usb_identifier_array[@]}"; do
					post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name,usb_identifier=${usb_identifier_array[$xx]} usb_status=${usb_status_array[$xx]},usb_device=${usb_device_array[$xx]}

"
					
					if [[ ${usb_status_array[$xx]} == 1 ]]; then
						if [ $enable_USB_port_state_change_email -eq 1 ]; then
							current_time=$( date +%s )
							if [ -r "$email_last_sent" ]; then #file is available and readable
								read message_tracker < $email_last_sent
								email_time_diff=$((( $current_time - $message_tracker ) / 60 ))
							else
								email_time_diff=61 
								echo "$current_time" > $email_last_sent
							fi
							
							if [ ${usb_device_array[$xx]} -eq 0 ]; then
								device_type="IFC"
							elif [ ${usb_device_array[$xx]} -eq 1 ]; then
								device_type="audio"
							elif [ ${usb_device_array[$xx]} -eq 2 ]; then
								device_type="comm"
							elif [ ${usb_device_array[$xx]} -eq 3 ]; then
								device_type="hid"
							elif [ ${usb_device_array[$xx]} -eq 5 ]; then
								device_type="physical"
							elif [ ${usb_device_array[$xx]} -eq 6 ]; then
								device_type="image"
							elif [ ${usb_device_array[$xx]} -eq 7 ]; then
								device_type="printer"
							elif [ ${usb_device_array[$xx]} -eq 8 ]; then
								device_type="storage"
							elif [ ${usb_device_array[$xx]} -eq 9 ]; then
								device_type="hub"
							elif [ ${usb_device_array[$xx]} -eq 10 ]; then
								device_type="cdcData"
							elif [ ${usb_device_array[$xx]} -eq 11 ]; then
								device_type="chipSmartCard"
							elif [ ${usb_device_array[$xx]} -eq 13 ]; then
								device_type="contentSecurity"
							elif [ ${usb_device_array[$xx]} -eq 254 ]; then
								device_type="appSpec"
							elif [ ${usb_device_array[$xx]} -eq 255 ]; then
								device_type="vendorSpec"
							fi
									
							now=$(date +"%T")
							echo "USB Device detected on device IP $snmp_device_url. Device type is \"$device_type\""
							if [ $email_time_diff -ge 60 ]; then
								if check_internet; then
									#send an email indicating script config file is missing and script will not run
									mailbody="$now - USB Device detected on device IP $snmp_device_url. Device type is \"$device_type\""
									echo "from: $from_email_address " > $log_file_location/fortigate_contents.txt
									echo "to: $email_address " >> $log_file_location/fortigate_contents.txt
									echo "subject: Fortigate USB Port Active Alert" >> $log_file_location/fortigate_contents.txt
									echo "" >> $log_file_location/fortigate_contents.txt
									echo $mailbody >> $log_file_location/fortigate_contents.txt
									
									if [[ "$email_address" == "" || "$from_email_address" == "" ]];then
										echo -e "\n\nNo email address information is configured, Cannot send an email about USB port"
									else
										if [ $sendmail_installed -eq 1 ]; then
											email_response=$(sendmail -t < $log_file_location/fortigate_contents.txt  2>&1)
											if [[ "$email_response" == "" ]]; then
												echo -e "\nEmail Sent Successfully" |& tee -a $log_file_location/fortigate_contents.txt
												echo "$current_time" > $email_last_sent
												email_time_diff=0
											else
												echo -e "\n\nWARNING -- An error occurred while sending email. The error was: $email_response\n\n" |& tee $log_file_location/fortigate_contents.txt
											fi	
										else
											echo "Unable to send email, \"sendmail\" command is unavailable"
										fi
									fi
								else
									echo "Internet is not available, skipping sending email"
								fi
							else
								echo -e "\n\nAnother email notification will be sent in $(( 60 - $email_time_diff)) Minutes"
							fi
						fi
					fi
				done
			else
				echo "Skipping USB capture"
			fi
			
			
			# GETTING CPU USAGE
			if [ $capture_cpu -eq 1 ]
			then
				
				measurement="fortigate_cpu"
				
				xx=0
				processor_usage_overall_average=0
				processor_user_average=0
				processor_system_average=0
				cpu_string=""
				while IFS= read -r line; do
					
					processor_usage=${line#*Gauge32: }; processor_usage=${processor_usage// /};processor_usage=${processor_usage//\"}
					processor_usage_overall_average=$(( $processor_usage_overall_average + $processor_usage ))
					cpu_string=$cpu_string"processor_usage_core$xx=$processor_usage,"
					
					let xx=xx+1
				
				done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.4.2.1.3 -Ovt)
				
				processor_usage_overall_average=$(( $processor_usage_overall_average / ( $xx - 1 ) ))
				
				xx=0
				while IFS= read -r line; do
					
					processor_usage=${line#*Gauge32: }; processor_usage=${processor_usage// /};processor_usage=${processor_usage//\"}
					processor_user_average=$(( $processor_user_average + $processor_usage ))
					cpu_string=$cpu_string"processor_user_usage_core$xx=$processor_usage,"
					
					let xx=xx+1
				
				done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.4.2.1.9 -Ovt)
				
				processor_user_average=$(( $processor_user_average / ( $xx - 1 ) ))
				
				xx=0
				while IFS= read -r line; do
					
					processor_usage=${line#*Gauge32: }; processor_usage=${processor_usage// /};processor_usage=${processor_usage//\"}
					processor_system_average=$(( $processor_system_average + $processor_usage ))
					cpu_string=$cpu_string"processor_system_usage_core$xx=$processor_usage,"
					
					let xx=xx+1
				
				done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.4.2.1.10 -Ovt)
				
				processor_system_average=$(( $processor_system_average / ( $xx - 1 ) ))
				
				post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name ${cpu_string%?},processor_usage_overall_average=$processor_usage_overall_average,processor_user_average=$processor_user_average,processor_system_average=$processor_system_average

"
			else
				echo "Skipping CPU capture"
			fi
			
			# GETTING data transfer information
			if [ $data_transfer -eq 1 ]
			then
				measurement="fortigate_data_transfer"
				
				interface_names=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 .1.3.6.1.2.1.31.1.1.1.1 -Oqv`
				#replace any white spaces in the interface name with an underscore 
				secondString="_"
				interface_names=${interface_names//\ /$secondString}
				interface_names=(`echo "$interface_names" | sed 's/,/\n/g'`)
				
				#(Number of octets received on interfaces. one octet = 1 byte
				interface_in_bytes=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 .1.3.6.1.2.1.31.1.1.1.6 -Oqv`
				interface_in_bytes=(`echo $interface_in_bytes | sed 's/,/\n/g'`)
												
				#(Number of octets sent on interface.  one octet = 1 byte
				interface_out_bytes=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 .1.3.6.1.2.1.31.1.1.1.10 -Oqv`
				interface_out_bytes=(`echo $interface_out_bytes | sed 's/,/\n/g'`)
				
				xx=0
				for xx in "${!interface_names[@]}"; do
					post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name,interface=${interface_names[$xx]} data_sent=${interface_out_bytes[$xx]},data_received=${interface_in_bytes[$xx]}

"
				done
			else
				echo "Skipping Data Transfer capture"
			fi
			
			
			# GETTING IPSEC VPN Info
			if [ $capture_IPSEC_VPN -eq 1 ]
			then
				measurement="fortigate_IPSEC_VPN"
				
				IPSEC_tunnel_index=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.1 -Oqv`
				IPSEC_tunnel_index=(`echo $IPSEC_tunnel_index | sed 's/,/\n/g'`)
				
				#Descriptive name of phase1 configuration for the tunnel
				phase1_config=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.2 -Oqv`
				phase1_config=(`echo $phase1_config | sed 's/,/\n/g'`)
												
				#Descriptive name of phase2 configuration for the tunnel
				phase2_config=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.3 -Oqv`
				phase2_config=(`echo $phase2_config | sed 's/,/\n/g'`)
				
				#IP of remote gateway used by the tunnel 
				remote_IP=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.4 -Oqv`
				remote_IP=(`echo $remote_IP | sed 's/,/\n/g'`)
				
				#port of remote gateway used by tunnel, if UDP
				remote_port=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.5 -Oqv`
				remote_port=(`echo $remote_port | sed 's/,/\n/g'`)
				
				#IP of local gateway used by the tunnel
				local_IP=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.6 -Oqv`
				local_IP=(`echo $local_IP | sed 's/,/\n/g'`)
				
				#port of local gateway used by the tunnel
				local_port=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.7 -Oqv`
				local_port=(`echo $local_port | sed 's/,/\n/g'`)
				
				#Beginning of address range of source selector
				source_selector_beginning=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.8 -Oqv`
				source_selector_beginning=(`echo $source_selector_beginning | sed 's/,/\n/g'`)
				
				#End of address range of source selector
				source_selector_end=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.9 -Oqv`
				source_selector_end=(`echo $source_selector_end | sed 's/,/\n/g'`)
				
				#Source selector port
				source_selector_port=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.10 -Oqv`
				source_selector_port=(`echo $source_selector_port | sed 's/,/\n/g'`)
				
				#Beginning of address range of destination selector
				destination_selector_beginning=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.11 -Oqv`
				destination_selector_beginning=(`echo $destination_selector_beginning | sed 's/,/\n/g'`)
				
				#End of address range of destination selector
				destination_selector_end=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.12 -Oqv`
				destination_selector_end=(`echo $destination_selector_end | sed 's/,/\n/g'`)
				
				#Destination selector port
				destination_selector_port=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.13 -Oqv`
				destination_selector_port=(`echo $destination_selector_port | sed 's/,/\n/g'`)
				
				#Protocol number for selector
				protocol_number=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.14 -Oqv`
				protocol_number=(`echo $protocol_number | sed 's/,/\n/g'`)
				
				#Lifetime of tunnel in seconds, if time based lifetime used
				IPSEC_Tunnel_Lifetime_uptime=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.15 -Oqv`
				IPSEC_Tunnel_Lifetime_uptime=(`echo $IPSEC_Tunnel_Lifetime_uptime | sed 's/,/\n/g'`)
				
				#Lifetime of tunnel in bytes, if byte transfer based lifetime used
				IPSEC_Tunnel_Lifetime_bytes=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.16 -Oqv`
				IPSEC_Tunnel_Lifetime_bytes=(`echo $IPSEC_Tunnel_Lifetime_bytes | sed 's/,/\n/g'`)
				
				#Number of bytes received on tunnel
				IPSEC_Tunnel_bytes_received=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.18 -Oqv`
				IPSEC_Tunnel_bytes_received=(`echo $IPSEC_Tunnel_bytes_received | sed 's/,/\n/g'`)
				
				#Number of bytes sent on tunnel
				IPSEC_Tunnel_bytes_sent=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.19 -Oqv`
				IPSEC_Tunnel_bytes_sent=(`echo $IPSEC_Tunnel_bytes_sent | sed 's/,/\n/g'`)
				
				#Current status of tunnel (up or down) down(1), up(2)
				IPSEC_Tunnel_status=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.2.1.20 -Oqv`
				IPSEC_Tunnel_status=(`echo $IPSEC_Tunnel_status | sed 's/,/\n/g'`)
				
				xx=0
				for xx in "${!IPSEC_tunnel_index[@]}"; do
					post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name,interface=${IPSEC_tunnel_index[$xx]} phase1_config=${phase1_config[$xx]},phase2_config=${phase2_config[$xx]},remote_IP=${remote_IP[$xx]},remote_port=${remote_port[$xx]},local_IP=${local_IP[$xx]},local_port=${local_port[$xx]},source_selector_beginning=${source_selector_beginning[$xx]},source_selector_end=${source_selector_end[$xx]},source_selector_port=${source_selector_port[$xx]},destination_selector_beginning=${destination_selector_beginning[$xx]},destination_selector_end=${destination_selector_end[$xx]},destination_selector_port=${destination_selector_port[$xx]},protocol_number=${protocol_number[$xx]},IPSEC_Tunnel_Lifetime_uptime=${IPSEC_Tunnel_Lifetime_uptime[$xx]},IPSEC_Tunnel_Lifetime_bytes=${IPSEC_Tunnel_Lifetime_bytes[$xx]},IPSEC_Tunnel_bytes_received=${IPSEC_Tunnel_bytes_received[$xx]},IPSEC_Tunnel_bytes_sent=${IPSEC_Tunnel_bytes_sent[$xx]},IPSEC_Tunnel_status=${IPSEC_Tunnel_status[$xx]}

"
				done
			else
				echo "Skipping IPSEC VPN capture"
			fi
			
			
			#GETTING SSL VPN INFO
			if [ $capture_SSLVPN -eq 1 ]
			then
				measurement="fortigate_SSLVPN"
					
				#number of active tunnels
				ssl_stats_active_tunnels=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.3.1.6 -Oqv`
				
				if [ $ssl_stats_active_tunnels -gt 0 ]; then
					secondString=""
									
					#SSLVPN active users
					ssl_tunnel_user_name=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.4.1.3 -Oqv`
					ssl_tunnel_user_name=${ssl_tunnel_user_name//\"/$secondString} #removing unneeded " characters before and after serial number
					ssl_tunnel_user_name=(`echo $ssl_tunnel_user_name | sed 's/,/\n/g'`)
					
					#source IP of active users
					ssl_tunnel_src_ip=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.4.1.4 -Oqv`
					ssl_tunnel_src_ip=${ssl_tunnel_src_ip//\"/$secondString}
					ssl_tunnel_src_ip=(`echo $ssl_tunnel_src_ip | sed 's/,/\n/g'`)
					
					#IP assigned to active tunnel
					ssl_tunnel_ip=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.4.1.5 -Oqv`
					ssl_tunnel_ip=${ssl_tunnel_ip//\"/$secondString}
					ssl_tunnel_ip=(`echo $ssl_tunnel_ip | sed 's/,/\n/g'`)
					
					#uptime of active tunnel
					ssl_tunnel_up_time=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.4.1.6 -Oqv`
					ssl_tunnel_up_time=${ssl_tunnel_up_time//\"/$secondString}
					ssl_tunnel_up_time=(`echo $ssl_tunnel_up_time | sed 's/,/\n/g'`)
					
					#bytes received on tunnel
					ssl_tunnel_byte_in=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.4.1.7 -Oqv`
					ssl_tunnel_byte_in=${ssl_tunnel_byte_in//\"/$secondString}
					ssl_tunnel_byte_in=(`echo $ssl_tunnel_byte_in | sed 's/,/\n/g'`)
					
					#bytes sent on tunnel
					ssl_tunnel_byte_out=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.12.2.4.1.8 -Oqv`
					ssl_tunnel_byte_out=${ssl_tunnel_byte_out//\"/$secondString}
					ssl_tunnel_byte_out=(`echo $ssl_tunnel_byte_out | sed 's/,/\n/g'`)
					
					xx=0
					for xx in "${!ssl_tunnel_up_time[@]}"; do
						post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name,tunnel_number=$xx ssl_tunnel_user_name=\""${ssl_tunnel_user_name[$xx]}"\",ssl_tunnel_src_ip=\""${ssl_tunnel_src_ip[$xx]}"\",ssl_tunnel_ip=\""${ssl_tunnel_ip[$xx]}"\",ssl_tunnel_up_time=\""${ssl_tunnel_up_time[$xx]}"\",ssl_tunnel_byte_in=${ssl_tunnel_byte_in[$xx]},ssl_tunnel_byte_out=${ssl_tunnel_byte_out[$xx]}

"
					done
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
				policy_id=()
				
				while IFS= read -r line; do
					
					policy_id+=(${line#*INTEGER: })
				
				done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.5.1.2.1.1.1 -Ovt)	
				
				##################################################
				#getting policy last time used (in minutes)
				policy_last_used=`snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.5.1.2.1.1.4 -Ovt`
				
				secondString=""
				policy_last_used=${policy_last_used//\STRING: /$secondString}
				
				secondString=""
				policy_last_used=${policy_last_used//\"/}
				
				#explode out the different items, separated by \n
				IFS=$'\n' read -rd '' -a policy_last_used_explode <<<"$policy_last_used"
								
				##################################################
				#getting policy data usage
				policy_data_used=()
				
				while IFS= read -r line; do
					
					policy_data_used+=(${line#*Counter64: })
				
				done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.5.1.2.1.1.6 -Ovt)			
				
				post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name "
				xx=0
				for xx in "${!policy_id[@]}"; do
					post_url=$post_url"policy${policy_id[${xx}]}_last_used=\""${policy_last_used_explode[${xx}]}"\",policy${policy_id[${xx}]}_data_used=${policy_data_used[${xx}]},"
				done
				
				post_url=$post_url"number_policy=$(( $xx + 1 ))

"
			else
				echo "Skipping FIREWALL POLICY DETAILS capture"
			fi
			
			
			# GETTING ANTIVIRUS POLICY DETAILS
			if [ $capture_antivirus_stats -eq 1 ]
			then
				
				measurement="fortigate_antivirus"
				#Anti-virus statistics for a particular virtual domain
				
				virus_detected=0
				while IFS= read -r line; do
					
					virus_detected=$(( $virus_detected + ${line#*Counter32: } ))
				
				done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.8.2.1.1 -Ovt)
				
				post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name virus_detected=$virus_detected

"
			else
				echo "Skipping FIREWALL ANTIVIRUS DETAILS capture"
			fi
			
			# GETTING WEBFILTER POLICY DETAILS
			if [ $capture_web_filter_stats -eq 1 ]
			then
				
				measurement="fortigate_webfilter"
				#Web-filter statistics for a particular virtual domain
				webfilter_stats=()
				
				while IFS= read -r line; do
					
					webfilter_stats+=(${line#*Counter32: })
				
				done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.10.1.2.1.1 -Ovt)	
				
				post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name http_sessions_blocked=${webfilter_stats[0]},https_sessions_blocked=${webfilter_stats[1]},http_url_blocked=${webfilter_stats[2]},https_url_blocked=${webfilter_stats[3]},activex_blocked=${webfilter_stats[4]},http_cookies_blocked=${webfilter_stats[5]},applets_blocked=${webfilter_stats[6]}

"
			else
				echo "Skipping FIREWALL WEBFILTER DETAILS capture"
			fi
			
			# GETTING FORTI-AP DETAILS
			if [ $capture_access_point -eq 1 ]
			then
				explode=(`echo $accesspoint_list | sed 's/-/\n/g'`)
				measurement="fortigate_fortiAP"
				
				xx=0
				for xx in "${!explode[@]}"; do
					skip_fortiap=0
				
					echo "Collecting Data from FORTI-AP SN ${explode[$xx]}"		

					#to gather the CPU and memory details of a specific fortiAP, we need to convert the serial number of decimal version as outlined here
					#https://community.fortinet.com/t5/Support-Forum/FortiAP-431F-CPU-and-memory-usage-monitoring-using-SNMP/td-p/46262
					#OID: 1.3.6.1.4.1.12356.101.14.4.4.1.20 (or 21 for memory) 
						
					#This is a column OID so to get value for one AP (WTP) you must add ID of that AP to the OID above. 
					#Default ID of AP is its serial number - it must be written as TypeLenValue format (type in this case is string - code 1). 
					#For example: WTPID of AP with serial number: "FP221ETF19906655" is: 1.16.70.80.50.50.49.69.84.70.49.57.57.48.54.54.53.53 
					#	because: 1 = typecode of value WTPID (1 = string) 16 = len of value WTPID = len of string "FP221ETF19906655" 
					#	70.80.50.50.49.69.84.70.49.57.57.48.54.54.53.53 = string "FP221ETF19906655" as ASCII codes (decimal) ("F"=70,"P"=80,"2"=50 etc). 
					#	So: if you want to get cpu usage for AP with serial number, for example: FP221ETF19906655 you should query Fortigate for value of this OID: 1.3.6.1.4.1.12356.101.14.4.4.1.20.1.16.70.80.50.50.49.69.84.70.49.57.57.48.54.54.53.53 and for memory usage: 1.3.6.1.4.1.12356.101.14.4.4.1.21.1.16.70.80.50.50.49.69.84.70.49.57.57.48.54.54.53.53
					
					secondString="."
					WTPID=$(echo -n "${explode[$xx]}" | od -A n -t d1) #details of using this command here: https://stackoverflow.com/questions/6791798/convert-string-to-hexadecimal-on-command-line
					WTPID=${WTPID//\   /$secondString} #replacing all spaces with a period to form an IOD compatible string
						
					#now we can collect data from the fortigate requested by the specific serial number

					#FAP Connection State
					#other(0), offLine(1), onLine(2), downloadingImage(3), connectedImage(4), standby(5)
					fap_state=$(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.14.4.4.1.7.1.16$WTPID -Ovt 2>&1)
					fap_state=$(filter_data "INTEGER: " "$fap_state")
					if [[ "$fap_state" == *"OID"* ]]; then 
						snmp_fail_fortAP_email ${explode[$xx]} "The FAP did not return valid data"
					elif [[ "$fap_state" != 2 ]]; then 
						if [[ "$fap_state" != 0 ]]; then
							snmp_fail_fortAP_email ${explode[$xx]} "Warning FortiAP ${explode[$xx]} is not ONLINE, its state is \"OTHER\""
						elif [[ "$fap_state" != 1 ]]; then
							snmp_fail_fortAP_email ${explode[$xx]} "Warning FortiAP ${explode[$xx]} is not ONLINE, its state is \"OFFLINE\""
						elif [[ "$fap_state" != 3 ]]; then
							snmp_fail_fortAP_email ${explode[$xx]} "Warning FortiAP ${explode[$xx]} is not ONLINE, its state is \"Downloading Image\""
						elif [[ "$fap_state" != 4 ]]; then
							snmp_fail_fortAP_email ${explode[$xx]} "Warning FortiAP ${explode[$xx]} is not ONLINE, its state is \"Connected Image\""
						elif [[ "$fap_state" != 5 ]]; then
							snmp_fail_fortAP_email ${explode[$xx]} "Warning FortiAP ${explode[$xx]} is not ONLINE, its state is \"STANBY\""
						fi
					else
						#since the status is "2" the FortiAP is online, let's get its details
					
						#FAP CPU usage
						fap_CPU=$(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.14.4.4.1.20.1.16$WTPID -Ovt 2>&1)
						fap_CPU=$(filter_data "Gauge32: " "$fap_CPU")
						if [[ "$fap_CPU" == *"OID"* ]]; then 
							skip_fortiap=1 #unit is online, otherwise this response would not be received, but it is not returning data at the requested IOD
						fi
						
						#FAP client count
						fap_client=$(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.14.4.4.1.17.1.16$WTPID -Ovt 2>&1)
						fap_client=$(filter_data "Gauge32: " "$fap_client")
						if [[ "$fap_client" == *"OID"* ]]; then 
							skip_fortiap=1 #unit is online, otherwise this response would not be received, but it is not returning data at the requested IOD
						fi
							
						#FAP Memory usage
						fap_MEM=$(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.14.4.4.1.21.1.16$WTPID -Ovt 2>&1)
						fap_MEM=$(filter_data "Gauge32: " "$fap_MEM")
						if [[ "$fap_MEM" == *"OID"* ]]; then 
							skip_fortiap=1 #unit is online, otherwise this response would not be received, but it is not returning data at the requested IOD
						fi
						
						#FAP IP Address
						fap_IP=$(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.14.4.4.1.5.1.16$WTPID -Ovt 2>&1)
						fap_IP=$(filter_data "Hex-STRING: " "$fap_IP")
						if [[ "$fap_IP" == *"OID"* ]]; then 
							skip_fortiap=1 #unit is online, otherwise this response would not be received, but it is not returning data at the requested IOD
						else
							explode2=(`echo $fap_IP | sed 's/ /\n/g'`)
							yy=0; fap_IP=""
							for yy in "${!explode2[@]}"; do #convert IP from HEX to decimal formatted IP address
								fap_IP=$fap_IP"$(echo $(( 16#${explode2[$yy]} )))."
							done
							fap_IP=${fap_IP%?}
						fi
						
						#FAP Uptime (in hundredths of a second)
						fap_uptime=$(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.14.4.4.1.8.1.16$WTPID -Ovt 2>&1)
						if [[ "$fap_uptime" == *"OID"* ]]; then 
							skip_fortiap=1 #unit is online, otherwise this response would not be received, but it is not returning data at the requested IOD
						fi
						
						#FAP model
						fap_model=$(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.14.4.4.1.12.1.16$WTPID -Ovt 2>&1)
						fap_model=$(filter_data "STRING: " "$fap_model")
						if [[ "$fap_model" == *"OID"* ]]; then 
							skip_fortiap=1 #unit is online, otherwise this response would not be received, but it is not returning data at the requested IOD
						fi
						
						#FAP software version
						fap_software=$(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.14.4.4.1.14.1.16$WTPID -Ovt 2>&1)
						fap_software=$(filter_data "STRING: " "$fap_software")
						if [[ "$fap_software" == *"OID"* ]]; then 
							skip_fortiap=1 #unit is online, otherwise this response would not be received, but it is not returning data at the requested IOD
						fi
						
						#FAP bytes received
						fap_rx=$(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.14.4.4.1.18.1.16$WTPID -Ovt 2>&1)
						fap_rx=$(filter_data "Counter64: " "$fap_rx")
						if [[ "$fap_rx" == *"OID"* ]]; then 
							skip_fortiap=1 #unit is online, otherwise this response would not be received, but it is not returning data at the requested IOD
						fi
						
						#FAP bytes sent
						fap_tx=$(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.14.4.4.1.19.1.16$WTPID -Ovt 2>&1)
						fap_tx=$(filter_data "Counter64: " "$fap_tx")
						if [[ "$fap_tx" == *"OID"* ]]; then 
							skip_fortiap=1 #unit is online, otherwise this response would not be received, but it is not returning data at the requested IOD
						fi
						
								
						if [ $skip_fortiap -eq 0 ]; then							
							post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name,fap_serial=${explode[$xx]} serial=\""${explode[$xx]}"\",fap_CPU=$fap_CPU,fap_MEM=$fap_MEM,fap_IP=\""$fap_IP"\",fap_uptime=$fap_uptime,fap_model=\""$fap_model"\",fap_software=\""$fap_software"\",fap_rx=$fap_rx,fap_tx=$fap_tx,fap_client=$fap_client

"
						else
							snmp_fail_fortAP_email ${explode[$xx]} "FORTI-AP ${explode[$xx]} returned one or more \"IOD is not available\" errors so data is being skipped"
						fi
					fi	
				done
			else
				echo "Skipping FIREWALL FORTI-AP DETAILS capture"
			fi
			
			#GETTING VARIOUS SESNOR INFORMATION
			if [ $capture_sensors -eq 1 ]
			then
				#check to make sure the fortigate model even has sensors to collect
				sensor_count=$(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 1.3.6.1.4.1.12356.101.4.3.1.0 -Ovt 2>&1)
				sensor_count=$(filter_data "INTEGER: " "$sensor_count")
				if [[ "$sensor_count" == *"OID"* || "$sensor_count" == "0" ]]; then 
					echo "Fortigate does not appear to have any available sensors, skipping sensor check"
				else
					measurement="fortigate_sensors"
					raw_sensor=""
					post_url=$post_url"$measurement,snmp_device_name=$snmp_device_name "
					
					sensor_names_array=()
					sensor_alarm_array=()
					
					while IFS= read -r line; do
						
						sensor_name=${line#*STRING: }; sensor_name=${sensor_name// /};sensor_name=${sensor_name//\"}
						sensor_names_array+=($sensor_name)
					
					done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 .1.3.6.1.4.1.12356.101.4.3.2.1.2 -Ovt)
					
					while IFS= read -r line; do
						
						sensor_alarm=${line#*INTEGER: }; sensor_alarm=${sensor_alarm// /};sensor_alarm=${sensor_alarm//\"}
						sensor_alarm_array+=($sensor_alarm)
					
					done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 .1.3.6.1.4.1.12356.101.4.3.2.1.4 -Ovt)
					
					xx=0
					while IFS= read -r line; do
						
						sensor_value=${line#*STRING: }; sensor_value=${sensor_value// /};sensor_value=${sensor_value//\"}
						if [[ $sensor_value == "LOST" ]]; then
							sensor_value=0
						elif [[ $sensor_value == "ON" ]]; then
							sensor_value=1
						fi
						
						if [[ $xx < $(( ${#sensor_names_array[@]} - 1 )) ]]; then
							raw_sensor=$raw_sensor"${sensor_names_array[$xx]}_value=$sensor_value,${sensor_names_array[$xx]}_alarm=${sensor_alarm_array[$xx]},"
						else
							raw_sensor=$raw_sensor"${sensor_names_array[$xx]}_value=$sensor_value,${sensor_names_array[$xx]}_alarm=${sensor_alarm_array[$xx]}"
						fi
						
						for attribute_counter in "${!sensor_paramter_name[@]}" 
						do
							if [[ ${sensor_names_array[$xx]} == ${sensor_paramter_name[$attribute_counter]} ]]; then
								if [[ ${sensor_paramter_type[$attribute_counter]} == ">" ]]; then
									if [[ $sensor_value > ${sensor_paramter_notification_threshold[$attribute_counter]} ]]; then
										#send_mail ${sensor_names_array[$xx]} ${sensor_paramter_notification_threshold[$attribute_counter]} $disk_path $nas_name $attribute_raw $email_contents $from_email_address $email_address "has exceeded"
										echo -e "\n\n${sensor_names_array[$xx]} has exceeded ${sensor_paramter_notification_threshold[$attribute_counter]}, current value = $sensor_value\n\n"
									fi
								elif [[ ${sensor_paramter_type[$attribute_counter]} == "=" ]]; then
									if [[ $sensor_value == ${sensor_paramter_notification_threshold[$attribute_counter]} ]]; then
										#send_mail ${sensor_names_array[$xx]} ${sensor_paramter_notification_threshold[$attribute_counter]} $disk_path $nas_name $attribute_raw $email_contents $from_email_address $email_address "is equal to"
										echo -e "\n\n${sensor_names_array[$xx]} is equal to ${sensor_paramter_notification_threshold[$attribute_counter]}, current value = $sensor_value\n\n"
									fi
								elif [[ ${sensor_paramter_type[$attribute_counter]} == "<" ]]; then
									if [[ $sensor_value < ${sensor_paramter_notification_threshold[$attribute_counter]} ]]; then
										#send_mail ${sensor_names_array[$xx]} ${sensor_paramter_notification_threshold[$attribute_counter]} $disk_path $nas_name $attribute_raw $email_contents $from_email_address $email_address "is less than"
										echo -e "\n\n${sensor_names_array[$xx]} is less than ${sensor_paramter_notification_threshold[$attribute_counter]}, current value = $sensor_value\n\n"
									fi
								fi
							fi
						done
						
						let xx=xx+1
					
					done < <(snmpwalk -v3 -l authPriv -u $snmp_user -a $snmp_auth_protocol -A $AuthPass1 -x $snmp_privacy_protocol -X $PrivPass2 $snmp_device_url:161 .1.3.6.1.4.1.12356.101.4.3.2.1.3 -Ovt)
					
					post_url=$post_url"$raw_sensor

"
				fi
			else
				echo "Skipping sensor collection"
			fi
			
			#echo -e "\n\n"
		
			curl -XPOST "$influxdb_http_type://$influxdb_host:$influxdb_port/api/v2/write?bucket=$influxdb_name&org=$influxdb_org" -H "Authorization: Token $influxdb_pass" --data-raw "$post_url"
			#echo -e "\n\n\n $post_url"
			
			let i=i+1
			
			echo "Capture #$i complete"
			
			#Sleeping for capture interval unless its last capture then we dont sleep
			if (( $i < $total_executions)); then
				sleep $(( $capture_interval -3))
			fi
			
		done
	else
		echo "script is disabled"
	fi
else
	#determine when the last time a general notification email was sent out. this will make sure we send an email only every x minutes
	current_time=$( date +%s )
	if [ -r "$email_last_sent" ]; then #file is available and readable
		read message_tracker < $email_last_sent
		email_time_diff=$((( $current_time - $message_tracker ) / 60 ))
	else
		email_time_diff=61
		echo "$current_time" > $email_last_sent
	fi
			
	now=$(date +"%T")
	echo "Configuration file for script \"${0##*/}\" is missing, skipping script and will send alert email every 60 minuets"
	if [ $email_time_diff -ge 60 ]; then
		if check_internet; then
			#send an email indicating script config file is missing and script will not run
			mailbody="$now - Warning SNMP Monitoring Failed for script \"${0##*/}\" - Configuration file is missing "
			echo "from: $from_email_address " > $log_file_location/fortigate_contents.txt
			echo "to: $email_address " >> $log_file_location/fortigate_contents.txt
			echo "subject: Warning SNMP Monitoring Failed for script \"${0##*/}\" - Configuration file is missing " >> $log_file_location/fortigate_contents.txt
			echo "" >> $log_file_location/fortigate_contents.txt
			echo $mailbody >> $log_file_location/fortigate_contents.txt
			
			if [[ "$email_address" == "" || "$from_email_address" == "" ]];then
				echo -e "\n\nNo email address information is configured, Cannot send an email indicating script \"${0##*/}\" config file is missing and script will not run"
			else
				if [ $sendmail_installed -eq 1 ]; then
					email_response=$(sendmail -t < $log_file_location/fortigate_contents.txt  2>&1)
					if [[ "$email_response" == "" ]]; then
						echo -e "\nEmail Sent Successfully indicating script \"${0##*/}\" config file is missing and script will not run" |& tee -a $log_file_location/fortigate_contents.txt
						echo "$current_time" > $email_last_sent
						email_time_diff=0
					else
						echo -e "\n\nWARNING -- An error occurred while sending email. The error was: $email_response\n\n" |& tee $log_file_location/fortigate_contents.txt
					fi	
				else
					echo "Unable to send email, \"sendmail\" command is unavailable"
				fi
			fi
		else
			echo "Internet is not available, skipping sending email"
		fi
	else
		echo -e "\n\nAnother email notification will be sent in $(( 60 - $email_time_diff)) Minutes"
	fi
	exit 1
fi
