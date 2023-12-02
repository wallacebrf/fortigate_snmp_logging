<?php
///////////////////////////////////////////////////
//User Defined Variables
///////////////////////////////////////////////////

$config_file="/volume1/web/config/config_files/config_files_local/fortigate_config.txt";
$use_login_sessions=true; //set to false if not using user login sessions
$form_submittal_destination="index.php?page=6&config_page=fortigate"; //set to the destination the HTML form submit should be directed to
$page_title="Fortigate SNMP Logging Configuration Settings";

///////////////////////////////////////////////////
//Beginning of configuration page
///////////////////////////////////////////////////
if($use_login_sessions){
	if($_SERVER['HTTPS']!="on") {

	$redirect= "https://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];

	header("Location:$redirect"); } 

	// Initialize the session
	if(session_status() !== PHP_SESSION_ACTIVE) session_start();
	 
	// Check if the user is logged in, if not then redirect him to login page
	if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true){
		header("location: login.php");
		exit;
	}
}
error_reporting(E_NOTICE);
include $_SERVER['DOCUMENT_ROOT']."/functions.php";
$fortigate_memory_error="";
$fortigate_email_error="";
$fortigate_email_interval_error="";
$fortigate_nas_url_error="";
$fortigate_nas_name_error="";
$fortigate_ups_group_error="";
$fortigate_influxdb_host_error="";
$fortigate_influxdb_port_error="";
$fortigate_influxdb_name_error="";
$fortigate_influxdb_user_error="";
$fortigate_influxdb_pass_error="";
$generic_error="";
$fortigate_from_email_error="";
$fortigate_auth_pass_error="";
$fortigate_priv_pass_error="";
$snmp_user_error="";
$fortigate_capture_accesspoint_list_error="";
$fortigate_access_point_user_error="";
$influxdb_org_error="";
$fortigate_disk_space_warning_threashold_error="";
$paramter_1_name_error="";
$paramter_1_notification_threshold_error="";
$paramter_2_name_error="";
$paramter_2_notification_threshold_error="";
$paramter_3_name_error="";
$paramter_3_notification_threshold_error="";
$paramter_4_name_error="";
$paramter_4_notification_threshold_error="";
$paramter_5_name_error="";
$paramter_5_notification_threshold_error="";
$paramter_6_name_error="";
$paramter_6_notification_threshold_error="";
$paramter_7_name_error="";
$paramter_7_notification_threshold_error="";
$paramter_8_name_error="";
$paramter_8_notification_threshold_error="";
$paramter_9_name_error="";
$paramter_9_notification_threshold_error="";
$paramter_10_name_error="";
$paramter_10_notification_threshold_error="";

if(isset($_POST['submit_fortigate'])){
	if (file_exists("".$config_file."")) {
		$data = file_get_contents("".$config_file."");
		$pieces = explode(",", $data);
	}
		   
	[$fortigate_memory_error, $fortigate_memory_error_error] = test_input_processing($_POST['fortigate_memory_error'], $pieces[9], "numeric", 20, 100);
		   
	[$fortigate_email, $fortigate_email_error] = test_input_processing($_POST['fortigate_email'], $pieces[0], "email", 0, 0);
		   
	[$fortigate_email_interval, $generic_error] = test_input_processing($_POST['fortigate_email_interval'], $pieces[1], "numeric", 60, 360);	  
		  		  
	[$fortigate_capture_system, $generic_error] = test_input_processing($_POST['fortigate_capture_system'], "", "checkbox", 0, 0);

	[$fortigate_capture_memory, $generic_error] = test_input_processing($_POST['fortigate_capture_memory'], "", "checkbox", 0, 0);
	
	[$fortigate_capture_cpu, $generic_error] = test_input_processing($_POST['fortigate_capture_cpu'], "", "checkbox", 0, 0);
		  
	[$fortigate_data_transfer, $generic_error] = test_input_processing($_POST['fortigate_data_transfer'], "", "checkbox", 0, 0);	  
	
	[$fortigate_capture_SSLvpn, $generic_error] = test_input_processing($_POST['fortigate_capture_SSLvpn'], "", "checkbox", 0, 0);	
	
	[$fortigate_capture_FW_policy, $generic_error] = test_input_processing($_POST['fortigate_capture_FW_policy'], "", "checkbox", 0, 0);	
		 
	[$fortigate_script_enable, $generic_error] = test_input_processing($_POST['fortigate_script_enable'], "", "checkbox", 0, 0);
		 
	[$fortigate_capture_interval, $generic_error] = test_input_processing($_POST['fortigate_capture_interval'], $pieces[8], "numeric", 10, 60);	  
		  
	[$fortigate_nas_url, $fortigate_nas_url_error] = test_input_processing($_POST['fortigate_nas_url'], $pieces[10], "ip", 0, 0);	  	  

	[$fortigate_nas_name, $fortigate_nas_name_error] = test_input_processing($_POST['fortigate_nas_name'], $pieces[10], "name", 0, 0);	 

	[$fortigate_ups_group, $generic_error] = test_input_processing($_POST['fortigate_ups_group'], "", "name", 0, 0);

	[$fortigate_influxdb_host, $fortigate_influxdb_host_error] = test_input_processing($_POST['fortigate_influxdb_host'], $pieces[12], "ip", 0, 0);
	
	[$fortigate_influxdb_port, $fortigate_influxdb_port_error] = test_input_processing($_POST['fortigate_influxdb_port'], $pieces[13], "numeric", 0, 65000);
	
	[$fortigate_influxdb_name, $fortigate_influxdb_name_error] = test_input_processing($_POST['fortigate_influxdb_name'], $pieces[14], "name", 0, 0);

	[$fortigate_influxdb_user, $fortigate_influxdb_user_error] = test_input_processing($_POST['fortigate_influxdb_user'], $pieces[15], "name", 0, 0);
	
	[$fortigate_influxdb_pass, $fortigate_influxdb_pass_error] = test_input_processing($_POST['fortigate_influxdb_pass'], $pieces[16], "password", 0, 0);
	
	[$fortigate_from_email, $fortigate_from_email_error] = test_input_processing($_POST['fortigate_from_email'], $pieces[18], "email", 0, 0);
	
	[$fortigate_auth_pass, $fortigate_auth_pass_error] = test_input_processing($_POST['fortigate_auth_pass'], $pieces[19], "password", 0, 0);
	
	[$fortigate_priv_pass, $fortigate_priv_pass_error] = test_input_processing($_POST['fortigate_priv_pass'], $pieces[20], "password", 0, 0);
	
	if ($_POST['snmp_privacy_protocol']=="AES" || $_POST['snmp_privacy_protocol']=="DES"){
		[$snmp_privacy_protocol, $generic_error] = test_input_processing($_POST['snmp_privacy_protocol'], $pieces[21], "name", 0, 0);
	}else{
		$snmp_privacy_protocol=$pieces[21];
	}
		   

	if ($_POST['snmp_auth_protocol']=="MD5" || $_POST['snmp_auth_protocol']=="SHA"){
		[$snmp_auth_protocol, $generic_error] = test_input_processing($_POST['snmp_auth_protocol'], $pieces[22], "name", 0, 0);
	}else{
		$snmp_auth_protocol=$pieces[22];
	}
	
	[$snmp_user, $snmp_user_error] = test_input_processing($_POST['snmp_user'], $pieces[23], "name", 0, 0);
	
	
	[$fortigate_capture_disk, $generic_error] = test_input_processing($_POST['fortigate_capture_disk'], "", "checkbox", 0, 0);
	
	[$fortigate_capture_USB, $generic_error] = test_input_processing($_POST['fortigate_capture_USB'], "", "checkbox", 0, 0);
	
	[$fortigate_capture_antivirus, $generic_error] = test_input_processing($_POST['fortigate_capture_antivirus'], "", "checkbox", 0, 0);
	
	[$fortigate_capture_webfilter, $generic_error] = test_input_processing($_POST['fortigate_capture_webfilter'], "", "checkbox", 0, 0);
	
	[$fortigate_capture_accesspoint, $generic_error] = test_input_processing($_POST['fortigate_capture_accesspoint'], "", "checkbox", 0, 0);
	
	$fortigate_capture_accesspoint_list_explode  = explode('-', $_POST['fortigate_capture_accesspoint_list']);
	for ($x = 0; $x < count($fortigate_capture_accesspoint_list_explode); $x++) {
		[$fortigate_capture_accesspoint_list_part, $generic_error] = test_input_processing($fortigate_capture_accesspoint_list_explode[$x], "", "name", 0, 0);
		if ($generic_error!=""){
			$fortigate_capture_accesspoint_list_error=$generic_error;
			$fortigate_capture_accesspoint_list=$pieces[29];
		}else{
			if ($x==0){
				$fortigate_capture_accesspoint_list=$fortigate_capture_accesspoint_list_part;
			}else{
				$concantinate="-";
				$fortigate_capture_accesspoint_list=$fortigate_capture_accesspoint_list.$concantinate.$fortigate_capture_accesspoint_list_part;
			}
		}
	}
	
	
	[$fortigate_access_point_user, $fortigate_access_point_user_error] = test_input_processing($_POST['fortigate_access_point_user'], $pieces[30], "name", 0, 0);
	
	[$fortigate_enable_access_point_down_email, $generic_error] = test_input_processing($_POST['fortigate_enable_access_point_down_email'], "", "checkbox", 0, 0);
	
	[$fortigate_capture_ipsec, $generic_error] = test_input_processing($_POST['fortigate_capture_ipsec'], "", "checkbox", 0, 0);
	
	[$fortigate_enable_disk_space_warning_email, $generic_error] = test_input_processing($_POST['fortigate_enable_disk_space_warning_email'], "", "checkbox", 0, 0);
	
	[$fortigate_disk_space_warning_threashold, $fortigate_disk_space_warning_threashold_error] = test_input_processing($_POST['fortigate_disk_space_warning_threashold'], $pieces[34], "numeric", 0, 100);
	
	[$fortigate_enable_USB_port_state_change_email, $generic_error] = test_input_processing($_POST['fortigate_enable_USB_port_state_change_email'], "", "checkbox", 0, 0);
	
	[$influxdb_org, $influxdb_org_error] = test_input_processing($_POST['influxdb_org'], $pieces[36], "name", 0, 0);
	
	if ($_POST['influxdb_http_type']=="http"){
		$influxdb_http_type="http";
	}else if($_POST['influxdb_http_type']=="https"){
		$influxdb_http_type="https";
	}else{
		$influxdb_http_type="http";
	}
	
	
	
	[$paramter_1_name, $paramter_1_name_error] = test_input_processing($_POST['paramter_1_name'], $pieces[38], "name", 0, 0);
	
	[$paramter_1_notification_threshold, $paramter_1_notification_threshold_error] = test_input_processing($_POST['paramter_1_notification_threshold'], $pieces[39], "numeric", 0, 100000);
	
	[$paramter_2_name, $paramter_2_name_error] = test_input_processing($_POST['paramter_2_name'], $pieces[40], "name", 0, 0);
	
	[$paramter_2_notification_threshold, $paramter_2_notification_threshold_error] = test_input_processing($_POST['paramter_2_notification_threshold'], $pieces[41], "numeric", 0, 100000);
	
	[$paramter_3_name, $paramter_3_name_error] = test_input_processing($_POST['paramter_3_name'], $pieces[42], "name", 0, 0);
	
	[$paramter_3_notification_threshold, $paramter_3_notification_threshold_error] = test_input_processing($_POST['paramter_3_notification_threshold'], $pieces[43], "numeric", 0, 100000);
	
	[$paramter_4_name, $paramter_4_name_error] = test_input_processing($_POST['paramter_4_name'], $pieces[44], "name", 0, 0);
	
	[$paramter_4_notification_threshold, $paramter_4_notification_threshold_error] = test_input_processing($_POST['paramter_4_notification_threshold'], $pieces[45], "numeric", 0, 100000);
	
	[$paramter_5_name, $paramter_5_name_error] = test_input_processing($_POST['paramter_5_name'], $pieces[46], "name", 0, 0);
	
	[$paramter_5_notification_threshold, $paramter_5_notification_threshold_error] = test_input_processing($_POST['paramter_5_notification_threshold'], $pieces[47], "numeric", 0, 100000);
	
	[$paramter_6_name, $paramter_6_name_error] = test_input_processing($_POST['paramter_6_name'], $pieces[48], "name", 0, 0);
	
	[$paramter_6_notification_threshold, $paramter_6_notification_threshold_error] = test_input_processing($_POST['paramter_6_notification_threshold'], $pieces[49], "numeric", 0, 100000);
	
	[$paramter_7_name, $paramter_7_name_error] = test_input_processing($_POST['paramter_7_name'], $pieces[50], "name", 0, 0);
	
	[$paramter_7_notification_threshold, $paramter_7_notification_threshold_error] = test_input_processing($_POST['paramter_7_notification_threshold'], $pieces[51], "numeric", 0, 100000);
	
	[$paramter_8_name, $paramter_8_name_error] = test_input_processing($_POST['paramter_8_name'], $pieces[52], "name", 0, 0);
	
	[$paramter_8_notification_threshold, $paramter_8_notification_threshold_error] = test_input_processing($_POST['paramter_8_notification_threshold'], $pieces[53], "numeric", 0, 100000);
	
	[$paramter_9_name, $paramter_9_name_error] = test_input_processing($_POST['paramter_9_name'], $pieces[54], "name", 0, 0);
	
	[$paramter_9_notification_threshold, $paramter_9_notification_threshold_error] = test_input_processing($_POST['paramter_9_notification_threshold'], $pieces[55], "numeric", 0, 100000);
	
	[$paramter_10_name, $paramter_10_name_error] = test_input_processing($_POST['paramter_10_name'], $pieces[56], "name", 0, 0);
	
	[$paramter_10_notification_threshold, $paramter_10_notification_threshold_error] = test_input_processing($_POST['paramter_10_notification_threshold'], $pieces[57], "numeric", 0, 100000);	
		
		
		
		
		
	if ($_POST['paramter_1_type']==">" || $_POST['paramter_1_type']=="=" || $_POST['paramter_1_type']=="<"){
		$paramter_1_type=($_POST['paramter_1_type']);
	}else{
		$paramter_1_type=$pieces[58];
	}
	
	if ($_POST['paramter_2_type']==">" || $_POST['paramter_2_type']=="=" || $_POST['paramter_2_type']=="<"){
		$paramter_2_type=($_POST['paramter_2_type']);
	}else{
		$paramter_2_type=$pieces[59];
	}
	
	if ($_POST['paramter_3_type']==">" || $_POST['paramter_3_type']=="=" || $_POST['paramter_3_type']=="<"){
		$paramter_3_type=($_POST['paramter_3_type']);
	}else{
		$paramter_3_type=$pieces[60];
	}
	
	if ($_POST['paramter_4_type']==">" || $_POST['paramter_4_type']=="=" || $_POST['paramter_4_type']=="<"){
		$paramter_4_type=($_POST['paramter_4_type']);
	}else{
		$paramter_4_type=$pieces[61];
	}
	
	if ($_POST['paramter_5_type']==">" || $_POST['paramter_5_type']=="=" || $_POST['paramter_5_type']=="<"){
		$paramter_5_type=($_POST['paramter_5_type']);
	}else{
		$paramter_5_type=$pieces[62];
	}
	
	if ($_POST['paramter_6_type']==">" || $_POST['paramter_6_type']=="=" || $_POST['paramter_6_type']=="<"){
		$paramter_6_type=($_POST['paramter_6_type']);
	}else{
		$paramter_6_type=$pieces[63];
	}
	
	if ($_POST['paramter_7_type']==">" || $_POST['paramter_7_type']=="=" || $_POST['paramter_7_type']=="<"){
		$paramter_7_type=($_POST['paramter_7_type']);
	}else{
		$paramter_7_type=$pieces[64];
	}
	
	if ($_POST['paramter_8_type']==">" || $_POST['paramter_8_type']=="=" || $_POST['paramter_8_type']=="<"){
		$paramter_8_type=($_POST['paramter_8_type']);
	}else{
		$paramter_8_type=$pieces[65];
	}
	
	if ($_POST['paramter_9_type']==">" || $_POST['paramter_9_type']=="=" || $_POST['paramter_9_type']=="<"){
		$paramter_9_type=($_POST['paramter_9_type']);
	}else{
		$paramter_9_type=$pieces[66];
	}
	
	if ($_POST['paramter_10_type']==">" || $_POST['paramter_10_type']=="=" || $_POST['paramter_10_type']=="<"){
		$paramter_10_type=($_POST['paramter_10_type']);
	}else{
		$paramter_10_type=$pieces[67];
	}	
	
	[$fortigate_enable_sensor_warning_email, $generic_error] = test_input_processing($_POST['fortigate_enable_sensor_warning_email'], "", "checkbox", 0, 0);
	
	[$fortigate_enable_sensor_capture, $generic_error] = test_input_processing($_POST['fortigate_enable_sensor_capture'], "", "checkbox", 0, 0);
  
	$put_contents_string="".$fortigate_email.",".$fortigate_email_interval.",".$fortigate_capture_system.",".$fortigate_capture_memory.",".$fortigate_capture_cpu.",".$fortigate_data_transfer.",".$fortigate_capture_SSLvpn.",".$fortigate_capture_FW_policy.",".$fortigate_capture_interval.",".$fortigate_memory_error.",".$fortigate_nas_url.",".$fortigate_nas_name.",".$fortigate_influxdb_host.",".$fortigate_influxdb_port.",".$fortigate_influxdb_name.",".$fortigate_influxdb_user.",".$fortigate_influxdb_pass.",".$fortigate_script_enable.",".$fortigate_from_email.",".$fortigate_auth_pass.",".$fortigate_priv_pass.",".$snmp_privacy_protocol.",".$snmp_auth_protocol.",".$snmp_user.",".$fortigate_capture_disk.",".$fortigate_capture_USB.",".$fortigate_capture_antivirus.",".$fortigate_capture_webfilter.",".$fortigate_capture_accesspoint.",".$fortigate_capture_accesspoint_list.",".$fortigate_access_point_user.",".$fortigate_enable_access_point_down_email.",".$fortigate_capture_ipsec.",".$fortigate_enable_disk_space_warning_email.",".$fortigate_disk_space_warning_threashold.",".$fortigate_enable_USB_port_state_change_email.",".$influxdb_org.",".$influxdb_http_type.",".$paramter_1_name.",".$paramter_1_notification_threshold.",".$paramter_2_name.",".$paramter_2_notification_threshold.",".$paramter_3_name.",".$paramter_3_notification_threshold.",".$paramter_4_name.",".$paramter_4_notification_threshold.",".$paramter_5_name.",".$paramter_5_notification_threshold.",".$paramter_6_name.",".$paramter_6_notification_threshold.",".$paramter_7_name.",".$paramter_7_notification_threshold.",".$paramter_8_name.",".$paramter_8_notification_threshold.",".$paramter_9_name.",".$paramter_9_notification_threshold.",".$paramter_10_name.",".$paramter_10_notification_threshold.",".$paramter_1_type.",".$paramter_2_type.",".$paramter_3_type.",".$paramter_4_type.",".$paramter_5_type.",".$paramter_6_type.",".$paramter_7_type.",".$paramter_8_type.",".$paramter_9_type.",".$paramter_10_type.",".$fortigate_enable_sensor_warning_email.",".$fortigate_enable_sensor_capture."";
		  
	file_put_contents("".$config_file."",$put_contents_string );
		  
}else{
	if (file_exists("".$config_file."")) {
		$data = file_get_contents("".$config_file."");
		$pieces = explode(",", $data);
		$fortigate_memory_error=$pieces[9];
		$fortigate_email=$pieces[0];
		$fortigate_email_interval=$pieces[1];
		$fortigate_capture_system=$pieces[2];
		$fortigate_capture_memory=$pieces[3];
		$fortigate_capture_cpu=$pieces[4];
		$fortigate_data_transfer=$pieces[5];
		$fortigate_capture_SSLvpn=$pieces[6];
		$fortigate_capture_FW_policy=$pieces[7];
		$fortigate_capture_interval=$pieces[8];
		$fortigate_nas_url=$pieces[10];
		$fortigate_nas_name=$pieces[11];
		$fortigate_influxdb_host=$pieces[12];
		$fortigate_influxdb_port=$pieces[13];
		$fortigate_influxdb_name=$pieces[14];
		$fortigate_influxdb_user=$pieces[15];
		$fortigate_influxdb_pass=$pieces[16];
		$fortigate_script_enable=$pieces[17];
		$fortigate_from_email=$pieces[18];
		$fortigate_auth_pass=$pieces[19];
		$fortigate_priv_pass=$pieces[20];
		$snmp_privacy_protocol=$pieces[21];
		$snmp_auth_protocol=$pieces[22];
		$snmp_user=$pieces[23];
		$fortigate_capture_disk=$pieces[24];
		$fortigate_capture_USB=$pieces[25];
		$fortigate_capture_antivirus=$pieces[26];
		$fortigate_capture_webfilter=$pieces[27];
		$fortigate_capture_accesspoint=$pieces[28];
		$fortigate_capture_accesspoint_list=$pieces[29];
		$fortigate_access_point_user=$pieces[30];
		$fortigate_enable_access_point_down_email=$pieces[31];
		$fortigate_capture_ipsec=$pieces[32];
		$fortigate_enable_disk_space_warning_email=$pieces[33];
		$fortigate_disk_space_warning_threashold=$pieces[34];
		$fortigate_enable_USB_port_state_change_email=$pieces[35];
		$influxdb_org=$pieces[36];
		$influxdb_http_type=$pieces[37];
		$paramter_1_name=$pieces[38];
		$paramter_1_notification_threshold=$pieces[39];
		$paramter_2_name=$pieces[40];
		$paramter_2_notification_threshold=$pieces[41];
		$paramter_3_name=$pieces[42];
		$paramter_3_notification_threshold=$pieces[43];
		$paramter_4_name=$pieces[44];
		$paramter_4_notification_threshold=$pieces[45];
		$paramter_5_name=$pieces[46];
		$paramter_5_notification_threshold=$pieces[47];
		$paramter_6_name=$pieces[48];
		$paramter_6_notification_threshold=$pieces[49];
		$paramter_7_name=$pieces[50];
		$paramter_7_notification_threshold=$pieces[51];
		$paramter_8_name=$pieces[52];
		$paramter_8_notification_threshold=$pieces[53];
		$paramter_9_name=$pieces[54];
		$paramter_9_notification_threshold=$pieces[55];
		$paramter_10_name=$pieces[56];
		$paramter_10_notification_threshold=$pieces[57];
		$paramter_1_type=$pieces[58];
		$paramter_2_type=$pieces[59];
		$paramter_3_type=$pieces[60];
		$paramter_4_type=$pieces[61];
		$paramter_5_type=$pieces[62];
		$paramter_6_type=$pieces[63];
		$paramter_7_type=$pieces[64];
		$paramter_8_type=$pieces[65];
		$paramter_9_type=$pieces[66];
		$paramter_10_type=$pieces[67];
		$fortigate_enable_sensor_warning_email=$pieces[68];
		$fortigate_enable_sensor_capture=$pieces[69];
	}else{
		$fortigate_memory_error=88;
		$fortigate_email="admin@admin.com";
		$fortigate_email_interval=60;
		$fortigate_capture_system=0;
		$fortigate_capture_memory=0;
		$fortigate_capture_cpu=0;
		$fortigate_data_transfer=0;
		$fortigate_capture_SSLvpn=0;
		$fortigate_capture_FW_policy=0;
		$fortigate_capture_interval=60;
		$fortigate_nas_url="localhost";
		$fortigate_nas_name="";
		$fortigate_influxdb_host="0.0.0.0";
		$fortigate_influxdb_port=8086;
		$fortigate_influxdb_name="db";
		$fortigate_influxdb_user="admin";
		$fortigate_influxdb_pass="password";
		$fortigate_script_enable=0;
		$fortigate_from_email="admin@admin.com";
		$fortigate_auth_pass="password1";
		$fortigate_priv_pass="password2";
		$snmp_privacy_protocol="DES";
		$snmp_auth_protocol="MD5";
		$snmp_user="user";
		
		$fortigate_capture_disk=0;
		$fortigate_capture_USB=0;
		$fortigate_capture_antivirus=0;
		$fortigate_capture_webfilter=0;
		$fortigate_capture_accesspoint=0;
		$fortigate_capture_accesspoint_list="FAP123ABCDEFGHIJ";
		$fortigate_access_point_user=1;
		$fortigate_enable_access_point_down_email="admin@admin.com";
		$fortigate_capture_ipsec=0;
		$fortigate_enable_disk_space_warning_email=0;
		$fortigate_disk_space_warning_threashold=80;
		$fortigate_enable_USB_port_state_change_email=0;
		$influxdb_org="home";
		$influxdb_http_type="http";
		
		$paramter_1_name="sensor1";
		$paramter_1_notification_threshold="0";
		$paramter_2_name="sensor2";
		$paramter_2_notification_threshold="0";
		$paramter_3_name="sensor3";
		$paramter_3_notification_threshold="0";
		$paramter_4_name="sensor4";
		$paramter_4_notification_threshold="0";
		$paramter_5_name="sensor5";;
		$paramter_5_notification_threshold="0";
		$paramter_6_name="sensor6";
		$paramter_6_notification_threshold="0";
		$paramter_7_name="sensor7";
		$paramter_7_notification_threshold="0";
		$paramter_8_name="sensor8";
		$paramter_8_notification_threshold="0";
		$paramter_9_name="sensor9";
		$paramter_9_notification_threshold="0";
		$paramter_10_name="sensor10";
		$paramter_10_notification_threshold="0";
		$paramter_1_type=">";
		$paramter_2_type=">";
		$paramter_3_type=">";
		$paramter_4_type=">";
		$paramter_5_type=">";
		$paramter_6_type=">";
		$paramter_7_type=">";
		$paramter_8_type=">";
		$paramter_9_type=">";
		$paramter_10_type=">";
		$fortigate_enable_sensor_warning_email=$pieces[68];
		$fortigate_enable_sensor_capture=$pieces[69];
			 
		$put_contents_string="".$fortigate_email.",".$fortigate_email_interval.",".$fortigate_capture_system.",".$fortigate_capture_memory.",".$fortigate_capture_cpu.",".$fortigate_data_transfer.",".$fortigate_capture_SSLvpn.",".$fortigate_capture_FW_policy.",".$fortigate_capture_interval.",".$fortigate_memory_error.",".$fortigate_nas_url.",".$fortigate_nas_name.",".$fortigate_influxdb_host.",".$fortigate_influxdb_port.",".$fortigate_influxdb_name.",".$fortigate_influxdb_user.",".$fortigate_influxdb_pass.",".$fortigate_script_enable.",".$fortigate_from_email.",".$fortigate_auth_pass.",".$fortigate_priv_pass.",".$snmp_privacy_protocol.",".$snmp_auth_protocol.",".$snmp_user.",".$fortigate_capture_disk.",".$fortigate_capture_USB.",".$fortigate_capture_antivirus.",".$fortigate_capture_webfilter.",".$fortigate_capture_accesspoint.",".$fortigate_capture_accesspoint_list.",".$fortigate_access_point_user.",".$fortigate_enable_access_point_down_email.",".$fortigate_capture_ipsec.",".$fortigate_enable_disk_space_warning_email.",".$fortigate_disk_space_warning_threashold.",".$fortigate_enable_USB_port_state_change_email.",".$influxdb_org.",".$influxdb_http_type.",".$paramter_1_name.",".$paramter_1_notification_threshold.",".$paramter_2_name.",".$paramter_2_notification_threshold.",".$paramter_3_name.",".$paramter_3_notification_threshold.",".$paramter_4_name.",".$paramter_4_notification_threshold.",".$paramter_5_name.",".$paramter_5_notification_threshold.",".$paramter_6_name.",".$paramter_6_notification_threshold.",".$paramter_7_name.",".$paramter_7_notification_threshold.",".$paramter_8_name.",".$paramter_8_notification_threshold.",".$paramter_9_name.",".$paramter_9_notification_threshold.",".$paramter_10_name.",".$paramter_10_notification_threshold.",".$paramter_1_type.",".$paramter_2_type.",".$paramter_3_type.",".$paramter_4_type.",".$paramter_5_type.",".$paramter_6_type.",".$paramter_7_type.",".$paramter_8_type.",".$paramter_9_type.",".$paramter_10_type.",".$fortigate_enable_sensor_warning_email.",".$fortigate_enable_sensor_capture."";
		
		file_put_contents("".$config_file."",$put_contents_string );
	}
}
	   
print "
<br>
<fieldset>
	<legend>
		<h3>".$page_title."</h3>
	</legend>
	<table border=\"0\">
		<tr>
			<td>";
		if ($fortigate_script_enable==1){
			print "<font color=\"green\"><h3>Script Status: Active</h3></font>";
		}else{
			print "<font color=\"red\"><h3>Script Status: Inactive</h3></font>";
		}
print "		</td>
		</tr>
		<tr>
			<td align=\"left\">
				<form action=\"".$form_submittal_destination."\" method=\"post\">
					<p><input type=\"checkbox\" name=\"fortigate_script_enable\" value=\"1\" ";
					   if ($fortigate_script_enable==1){
							print "checked";
					   }
 print "				>Enable Entire Script?
					</p>
					<br>
					<b>EMAIL NOTIFICATION SETTINGS</b>
					<p>->Alert Email Recipient: <input type=\"text\" name=\"fortigate_email\" value=".$fortigate_email."> ".$fortigate_email_error."</p>
					<p>->From Email Address: <input type=\"text\" name=\"fortigate_from_email\" value=".$fortigate_from_email."> ".$fortigate_from_email_error."</p>
					<p>->RAM Usage Warning Threshold [%]: <input type=\"text\" name=\"fortigate_memory_error\" value=".$fortigate_memory_error."> ".$fortigate_memory_error_error."</p>
					<p>-><input type=\"checkbox\" name=\"fortigate_enable_access_point_down_email\" value=\"1\" ";
					   if ($fortigate_enable_access_point_down_email==1){
							print "checked";
					   }
 print "				>Enable Notification of Offline Access Point</p>
					<p>-><input type=\"checkbox\" name=\"fortigate_enable_disk_space_warning_email\" value=\"1\" ";
					   if ($fortigate_enable_disk_space_warning_email==1){
							print "checked";
					   }
 print "				>Enable Notification of Excessive Disk Space Usage<font size=\"1\">For units with a disk like 61F, 81F etc</font></p>
					<p>->Used Disk Space Threshold: <input type=\"text\" name=\"fortigate_disk_space_warning_threashold\" value=".$fortigate_disk_space_warning_threashold."> ".$fortigate_disk_space_warning_threashold_error."</p>
					<p>-><input type=\"checkbox\" name=\"fortigate_enable_USB_port_state_change_email\" value=\"1\" ";
					   if ($fortigate_enable_USB_port_state_change_email==1){
							print "checked";
					   }
 print "				>Enable Notification of USB Device Activity</p>
					
					<p>->Email Delay Period [Hours]: <select name=\"fortigate_email_interval\">";
						if ($fortigate_email_interval==60){
							print "<option value=\"60\" selected>1</option>
							<option value=\"120\">2</option>
							<option value=\"180\">3</option>
							<option value=\"240\">4</option>
							<option value=\"300\">5</option>
							<option value=\"360\">6</option>";
						}else if ($fortigate_email_interval==120){
							print "<option value=\"60\">1</option>
							<option value=\"120\" selected>2</option>
							<option value=\"180\">3</option>
							<option value=\"240\">4</option>
							<option value=\"300\">5</option>
							<option value=\"360\">6</option>";
						}else if ($fortigate_email_interval==180){
							print "<option value=\"60\">1</option>
							<option value=\"120\">2</option>
							<option value=\"180\" selected>3</option>
							<option value=\"240\">4</option>
							<option value=\"300\">5</option>
							<option value=\"360\">6</option>";
						}else if ($fortigate_email_interval==240){
							print "<option value=\"60\">1</option>
							<option value=\"120\">2</option>
							<option value=\"180\">3</option>
							<option value=\"240\" selected>4</option>
							<option value=\"300\">5</option>
							<option value=\"360\">6</option>";
						}else if ($fortigate_email_interval==300){
							print "<option value=\"60\">1</option>
							<option value=\"120\">2</option>
							<option value=\"180\">3</option>
							<option value=\"240\">4</option>
							<option value=\"300\" selected>5</option>
							<option value=\"360\">6</option>";
						}else if ($fortigate_email_interval==360){
							print "<option value=\"60\">1</option>
							<option value=\"120\">2</option>
							<option value=\"180\">3</option>
							<option value=\"240\">4</option>
							<option value=\"300\">5</option>
							<option value=\"360\" selected>6</option>";
						}
						print "</select></p>
					
					<b>SENSOR NOTIFICATION SETTINGS</b>
					<p>-><input type=\"checkbox\" name=\"fortigate_enable_sensor_warning_email\" value=\"1\" ";
					   if ($fortigate_enable_sensor_warning_email==1){
							print "checked";
					   }
					   print ">Enable Sensor Notifications? <font size=\"1\">Power Supply, Voltage, Fan Speed, Temperature (Fortigate Model Specific)</font></p>
					<br><i>NOTE: If not using a particular parameter, leave fields at default values</i>
					<br>
					<p>-><b>Sesnor 1</b> <input type=\"text\" name=\"paramter_1_name\" value=".$paramter_1_name."> ".$paramter_1_name_error."
						<select name=\"paramter_1_type\">";
							if ($paramter_1_type==">"){
								print "<option value=\">\" selected>></option>
								<option value=\"<\"><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_1_type=="<"){
								print "<option value=\">\">></option>
								<option value=\"<\" selected><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_1_type=="="){
								print "<option value=\">\">></option>
								<option value=\"<\"><</option>
								<option value=\"=\" selected>=</option>";
							}
					print "</select>
						<input type=\"text\" name=\"paramter_1_notification_threshold\" value=".$paramter_1_notification_threshold."> ".$paramter_1_notification_threshold_error."</p>
					<p>-><b>Sesnor 2</b> <input type=\"text\" name=\"paramter_2_name\" value=".$paramter_2_name."> ".$paramter_2_name_error."
						<select name=\"paramter_2_type\">";
							if ($paramter_2_type==">"){
								print "<option value=\">\" selected>></option>
								<option value=\"<\"><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_2_type=="<"){
								print "<option value=\">\">></option>
								<option value=\"<\" selected><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_2_type=="="){
								print "<option value=\">\">></option>
								<option value=\"<\"><</option>
								<option value=\"=\" selected>=</option>";
							}
					print "</select>
						<input type=\"text\" name=\"paramter_2_notification_threshold\" value=".$paramter_2_notification_threshold."> ".$paramter_2_notification_threshold_error."</p>
					<p>-><b>Sesnor 3</b> <input type=\"text\" name=\"paramter_3_name\" value=".$paramter_3_name."> ".$paramter_3_name_error."
						<select name=\"paramter_3_type\">";
							if ($paramter_3_type==">"){
								print "<option value=\">\" selected>></option>
								<option value=\"<\"><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_3_type=="<"){
								print "<option value=\">\">></option>
								<option value=\"<\" selected><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_3_type=="="){
								print "<option value=\">\">></option>
								<option value=\"<\"><</option>
								<option value=\"=\" selected>=</option>";
							}
					print "</select>
						<input type=\"text\" name=\"paramter_3_notification_threshold\" value=".$paramter_3_notification_threshold."> ".$paramter_3_notification_threshold_error."</p>
					<p>-><b>Sesnor 4</b> <input type=\"text\" name=\"paramter_4_name\" value=".$paramter_4_name."> ".$paramter_4_name_error."
						<select name=\"paramter_4_type\">";
							if ($paramter_4_type==">"){
								print "<option value=\">\" selected>></option>
								<option value=\"<\"><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_4_type=="<"){
								print "<option value=\">\">></option>
								<option value=\"<\" selected><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_4_type=="="){
								print "<option value=\">\">></option>
								<option value=\"<\"><</option>
								<option value=\"=\" selected>=</option>";
							}
					print "</select>
						<input type=\"text\" name=\"paramter_4_notification_threshold\" value=".$paramter_4_notification_threshold."> ".$paramter_4_notification_threshold_error."</p>
					<p>-><b>Sesnor 5</b> <input type=\"text\" name=\"paramter_5_name\" value=".$paramter_5_name."> ".$paramter_5_name_error."
						<select name=\"paramter_5_type\">";
							if ($paramter_5_type==">"){
								print "<option value=\">\" selected>></option>
								<option value=\"<\"><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_5_type=="<"){
								print "<option value=\">\">></option>
								<option value=\"<\" selected><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_5_type=="="){
								print "<option value=\">\">></option>
								<option value=\"<\"><</option>
								<option value=\"=\" selected>=</option>";
							}
					print "</select>
						<input type=\"text\" name=\"paramter_5_notification_threshold\" value=".$paramter_5_notification_threshold."> ".$paramter_5_notification_threshold_error."</p>
					<p>-><b>Sesnor 6</b> <input type=\"text\" name=\"paramter_6_name\" value=".$paramter_6_name."> ".$paramter_6_name_error."
						<select name=\"paramter_6_type\">";
							if ($paramter_6_type==">"){
								print "<option value=\">\" selected>></option>
								<option value=\"<\"><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_6_type=="<"){
								print "<option value=\">\">></option>
								<option value=\"<\" selected><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_6_type=="="){
								print "<option value=\">\">></option>
								<option value=\"<\"><</option>
								<option value=\"=\" selected>=</option>";
							}
					print "</select>
						<input type=\"text\" name=\"paramter_6_notification_threshold\" value=".$paramter_6_notification_threshold."> ".$paramter_6_notification_threshold_error."</p>
					<p>-><b>Sesnor 7</b> <input type=\"text\" name=\"paramter_7_name\" value=".$paramter_7_name."> ".$paramter_7_name_error."
						<select name=\"paramter_7_type\">";
							if ($paramter_7_type==">"){
								print "<option value=\">\" selected>></option>
								<option value=\"<\"><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_7_type=="<"){
								print "<option value=\">\">></option>
								<option value=\"<\" selected><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_7_type=="="){
								print "<option value=\">\">></option>
								<option value=\"<\"><</option>
								<option value=\"=\" selected>=</option>";
							}
					print "</select>
						<input type=\"text\" name=\"paramter_7_notification_threshold\" value=".$paramter_7_notification_threshold."> ".$paramter_7_notification_threshold_error."</p>
					<p>-><b>Sesnor 8</b> <input type=\"text\" name=\"paramter_8_name\" value=".$paramter_8_name."> ".$paramter_8_name_error."
						<select name=\"paramter_8_type\">";
							if ($paramter_8_type==">"){
								print "<option value=\">\" selected>></option>
								<option value=\"<\"><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_8_type=="<"){
								print "<option value=\">\">></option>
								<option value=\"<\" selected><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_8_type=="="){
								print "<option value=\">\">></option>
								<option value=\"<\"><</option>
								<option value=\"=\" selected>=</option>";
							}
					print "</select>
						<input type=\"text\" name=\"paramter_8_notification_threshold\" value=".$paramter_8_notification_threshold."> ".$paramter_8_notification_threshold_error."</p>
					<p>-><b>Sesnor 9</b> <input type=\"text\" name=\"paramter_9_name\" value=".$paramter_9_name."> ".$paramter_9_name_error."
						<select name=\"paramter_9_type\">";
							if ($paramter_9_type==">"){
								print "<option value=\">\" selected>></option>
								<option value=\"<\"><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_9_type=="<"){
								print "<option value=\">\">></option>
								<option value=\"<\" selected><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_9_type=="="){
								print "<option value=\">\">></option>
								<option value=\"<\"><</option>
								<option value=\"=\" selected>=</option>";
							}
					print "</select>
						<input type=\"text\" name=\"paramter_9_notification_threshold\" value=".$paramter_9_notification_threshold."> ".$paramter_9_notification_threshold_error."</p>
					<p>-><b>Sesnor 10</b> <input type=\"text\" name=\"paramter_10_name\" value=".$paramter_10_name."> ".$paramter_10_name_error."
						<select name=\"paramter_10_type\">";
							if ($paramter_10_type==">"){
								print "<option value=\">\" selected>></option>
								<option value=\"<\"><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_10_type=="<"){
								print "<option value=\">\">></option>
								<option value=\"<\" selected><</option>
								<option value=\"=\">=</option>";
							}else if ($paramter_10_type=="="){
								print "<option value=\">\">></option>
								<option value=\"<\"><</option>
								<option value=\"=\" selected>=</option>";
							}
					print "</select><input type=\"text\" name=\"paramter_10_notification_threshold\" value=".$paramter_10_notification_threshold."> ".$paramter_10_notification_threshold_error."</p></p>
					<br>
					<b>CAPTURE SETTINGS</b>
					<p>-><input type=\"checkbox\" name=\"fortigate_capture_system\" value=\"1\" ";
					   if ($fortigate_capture_system==1){
							print "checked";
					   }
						print ">Enable SNMP System Variable Capture? <font size=\"1\">Serial Number, System Version, Up time, Session Count, Antivirus Version, IPS Version, </font></p>
					<p>-><input type=\"checkbox\" name=\"fortigate_capture_memory\" value=\"1\" ";
					   if ($fortigate_capture_memory==1){
							print "checked";
					   }
					   print ">Enable SNMP Memory Variable Capture? <font size=\"1\">Memory Usage and Memory Capacity</font></p>
					<p>-><input type=\"checkbox\" name=\"fortigate_capture_cpu\" value=\"1\" ";
					   if ($fortigate_capture_cpu==1){
							print "checked";
					   }
						print ">Enable SNMP CPU Variable Capture? <font size=\"1\">Total CPU Usage and Usage for System and User</font></p>
					<p>-><input type=\"checkbox\" name=\"fortigate_data_transfer\" value=\"1\" ";
					   if ($fortigate_data_transfer==1){
							print "checked";
					   }
					   print ">Enable SNMP Data Transfer Capture? <font size=\"1\">Capture Data on different Interfaces (WAN, VLANS, LAN etc)</font></p>
					<p>-><input type=\"checkbox\" name=\"fortigate_capture_SSLvpn\" value=\"1\" ";
					   if ($fortigate_capture_SSLvpn==1){
							print "checked";
					   }
					   print ">Enable SNMP SSL VPN Capture? <font size=\"1\">Number of Tunnels, User Names, Source IPs, Assigned IP, SSL Data Transfer, Up time</font></p>
					<p>-><input type=\"checkbox\" name=\"fortigate_capture_FW_policy\" value=\"1\" ";
					   if ($fortigate_capture_FW_policy==1){
							print "checked";
					   }
					   print ">Enable SNMP Firewall Policy Capture? <font size=\"1\">Policy Name, Policy Data Used, Policy Date Last Used</font></p>
					<p>-><input type=\"checkbox\" name=\"fortigate_capture_disk\" value=\"1\" ";
					   if ($fortigate_capture_disk==1){
							print "checked";
					   }
					   print ">Enable SNMP Firewall Storage SSD Disk Capture? <font size=\"1\">Disk Size, Disk Used Space</font></p>	
					<p>-><input type=\"checkbox\" name=\"fortigate_capture_USB\" value=\"1\" ";
					   if ($fortigate_capture_USB==1){
							print "checked";
					   }
					   print ">Enable SNMP Firewall USB Device Capture? <font size=\"1\">USB Device Connected, Device Type</font></p>	
					<p>-><input type=\"checkbox\" name=\"fortigate_capture_antivirus\" value=\"1\" ";
					   if ($fortigate_capture_antivirus==1){
							print "checked";
					   }
					   print ">Enable SNMP Firewall Antivirus Statistics Capture? <font size=\"1\">Number of Virus Detection</font></p>
					<p>-><input type=\"checkbox\" name=\"fortigate_capture_webfilter\" value=\"1\" ";
					   if ($fortigate_capture_webfilter==1){
							print "checked";
					   }
					   print ">Enable SNMP Firewall Web Filter Statistics Capture? <font size=\"1\">HTTP/HTTPS Sessions Blocked, HTTP/HTTPS URLS Blocked, ActiveX Blocked, Cookies Blocked, Applets Blocked</font></p>
					<p>-><input type=\"checkbox\" name=\"fortigate_capture_accesspoint\" value=\"1\" ";
					   if ($fortigate_capture_accesspoint==1){
							print "checked";
					   }
					   print ">Enable SNMP FORTI-AP Capture? <font size=\"1\">Serial Number, CPU Usage, RAM Usage, IP Address, Up-time, Model, Software Version, Bytes Sent/Received</font></p>
					<p>->List of FORTI-AP to Poll: <input type=\"text\" name=\"fortigate_capture_accesspoint_list\" value=".$fortigate_capture_accesspoint_list."> <font size=\"1\">Separate Serial Numbers by a Dash \"-\"</font> ".$fortigate_capture_accesspoint_list_error."</p>
					
					<p>-><input type=\"checkbox\" name=\"fortigate_enable_sensor_capture\" value=\"1\" ";
					   if ($fortigate_enable_sensor_capture==1){
							print "checked";
					   }
					   print ">Enable SNMP Sensor Capture? <font size=\"1\">Voltage, Power Supply, Fan Speed, and Temperature Data (Sensors are Model Specific)</font></p>  
					   
					<p>-><input type=\"checkbox\" name=\"fortigate_capture_ipsec\" value=\"1\" ";
					   if ($fortigate_capture_ipsec==1){
							print "checked";
					   }
					   print ">Enable SNMP IPSEC Firewall Capture?</p>
					
					
					<p>->Data Logging Captures Per Minuet: <select name=\"fortigate_capture_interval\">";
						if ($fortigate_capture_interval==10){
							print "<option value=\"10\" selected>6</option>
							<option value=\"15\">4</option>
							<option value=\"30\">2</option>
							<option value=\"60\">1</option>";
						}else if ($fortigate_capture_interval==15){
							print "<option value=\"10\">6</option>
							<option value=\"15\" selected>4</option>
							<option value=\"30\">2</option>
							<option value=\"60\">1</option>";
						}else if ($fortigate_capture_interval==30){
							print "<option value=\"10\">6</option>
							<option value=\"15\">4</option>
							<option value=\"30\" selected>2</option>
							<option value=\"60\">1</option>";
						}else if ($fortigate_capture_interval==60){
							print "<option value=\"10\">6</option>
							<option value=\"15\">4</option>
							<option value=\"30\">2</option>
							<option value=\"60\" selected>1</option>";
						}
						print "</select></p>
					<br>
					<b>SNMP SETTINGS</b>
					<p>->URL of Fortigate to gather SNMP Information from: <input type=\"text\" name=\"fortigate_nas_url\" value=".$fortigate_nas_url."> ".$fortigate_nas_url_error."</p>
					<p>->Fortigate SNMP user: <input type=\"text\" name=\"snmp_user\" value=".$snmp_user."> ".$snmp_user_error."</p>
					<p>->Fortigate SNMP Authorization Password: <input type=\"text\" name=\"fortigate_auth_pass\" value=".$fortigate_auth_pass."> ".$fortigate_auth_pass_error."</p>
					<p>->Fortigate SNMP Privacy Password: <input type=\"text\" name=\"fortigate_priv_pass\" value=".$fortigate_priv_pass."> ".$fortigate_priv_pass_error."</p>
					<p>->Authorization Protocol: <select name=\"snmp_auth_protocol\">";
					if ($snmp_auth_protocol=="MD5"){
						print "<option value=\"MD5\" selected>MD5</option>
						<option value=\"SHA\">SHA</option>";
					}else if ($snmp_auth_protocol=="SHA"){
						print "<option value=\"MD5\">MD5</option>
						<option value=\"SHA\" selected>SHA</option>";
					}
print "				</select></p>
					<p>->Privacy Protocol: <select name=\"snmp_privacy_protocol\">";
					if ($snmp_privacy_protocol=="AES"){
						print "<option value=\"AES\" selected>AES</option>
						<option value=\"DES\">DES</option>";
					}else if ($snmp_privacy_protocol=="DES"){
						print "<option value=\"AES\">AES</option>
						<option value=\"DES\" selected>DES</option>";
					}
print "				</select></p>
					<br>
					<b>INFLUXDB SETTINGS</b>
					<p>->Name of Fortigate (Leave blank to auto determine name): <input type=\"text\" name=\"fortigate_nas_name\" value=".$fortigate_nas_name."> ".$fortigate_nas_name_error."</p>
					<p>->IP of Influx DB: <input type=\"text\" name=\"fortigate_influxdb_host\" value=".$fortigate_influxdb_host."> ".$fortigate_influxdb_host_error."</p>
					<p>->PORT of Influx DB: <input type=\"text\" name=\"fortigate_influxdb_port\" value=".$fortigate_influxdb_port."> ".$fortigate_influxdb_port_error."</p>
					<p>->Database to use within Influx DB: <input type=\"text\" name=\"fortigate_influxdb_name\" value=".$fortigate_influxdb_name."> ".$fortigate_influxdb_name_error."</p>
					<p>->User Name of Influx DB: <input type=\"text\" name=\"fortigate_influxdb_user\" value=".$fortigate_influxdb_user."> ".$fortigate_influxdb_user_error."</p>
					<p>->Password of Influx DB: <input type=\"text\" name=\"fortigate_influxdb_pass\" value=".$fortigate_influxdb_pass."> ".$fortigate_influxdb_pass_error."</p>
					<p>->Organization Name: <input type=\"text\" name=\"influxdb_org\" value=".$influxdb_org."> ".$influxdb_org_error."</p>
					<p>->HTTP/HTTPS: <select name=\"influxdb_http_type\">";
					if ($influxdb_http_type=="http"){
						print "<option value=\"http\" selected>HTTP</option>
						<option value=\"https\">HTTPS</option>";
					}else if ($influxdb_http_type=="https"){
						print "<option value=\"http\">HTTP</option>
						<option value=\"https\" selected>HTTPS</option>";
					}
print "				</select></p>
					<br>
					<center><input type=\"submit\" name=\"submit_fortigate\" value=\"Submit\" /></center>
				</form>
			</td>
		</tr>
	</table>
</fieldset>";
?>
