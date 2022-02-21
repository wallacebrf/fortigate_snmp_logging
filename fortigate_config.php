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
error_reporting(E_ALL ^ E_NOTICE);
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
  
	$put_contents_string="".$fortigate_email.",".$fortigate_email_interval.",".$fortigate_capture_system.",".$fortigate_capture_memory.",".$fortigate_capture_cpu.",".$fortigate_data_transfer.",".$fortigate_capture_SSLvpn.",".$fortigate_capture_FW_policy.",".$fortigate_capture_interval.",".$fortigate_memory_error.",".$fortigate_nas_url.",".$fortigate_nas_name.",".$fortigate_influxdb_host.",".$fortigate_influxdb_port.",".$fortigate_influxdb_name.",".$fortigate_influxdb_user.",".$fortigate_influxdb_pass.",".$fortigate_script_enable."";
		  
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
				  
		$put_contents_string="".$fortigate_email.",".$fortigate_email_interval.",".$fortigate_capture_system.",".$fortigate_capture_memory.",".$fortigate_capture_cpu.",".$fortigate_data_transfer.",".$fortigate_capture_SSLvpn.",".$fortigate_capture_FW_policy.",".$fortigate_capture_interval.",".$fortigate_memory_error.",".$fortigate_nas_url.",".$fortigate_nas_name.",".$fortigate_influxdb_host.",".$fortigate_influxdb_port.",".$fortigate_influxdb_name.",".$fortigate_influxdb_user.",".$fortigate_influxdb_pass.",".$fortigate_script_enable."";
		
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
					<p>RAM Usage Warning Threshold [%]: <input type=\"text\" name=\"fortigate_memory_error\" value=".$fortigate_memory_error."> ".$fortigate_memory_error_error."</p>
					<p>Alert Email Recipient: <input type=\"text\" name=\"fortigate_email\" value=".$fortigate_email."> ".$fortigate_email_error."</p>
					<p>Email Delay Period [Hours]: <select name=\"fortigate_email_interval\">";
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
					<p><input type=\"checkbox\" name=\"fortigate_capture_system\" value=\"1\" ";
					   if ($fortigate_capture_system==1){
							print "checked";
					   }
						print ">Enable SNMP System Variable Capture? <font size=\"1\">Serial Number, System Version, Up time, Session Count, Antivirus Version, IPS Version, </font></p>
					<p><input type=\"checkbox\" name=\"fortigate_capture_memory\" value=\"1\" ";
					   if ($fortigate_capture_memory==1){
							print "checked";
					   }
					   print ">Enable SNMP Memory Variable Capture? <font size=\"1\">Memory Usage and Memory Capacity</font></p>
					<p><input type=\"checkbox\" name=\"fortigate_capture_cpu\" value=\"1\" ";
					   if ($fortigate_capture_cpu==1){
							print "checked";
					   }
						print ">Enable SNMP CPU Variable Capture? <font size=\"1\">Total CPU Usage and Usage for System and User</font></p>
					<p><input type=\"checkbox\" name=\"fortigate_data_transfer\" value=\"1\" ";
					   if ($fortigate_data_transfer==1){
							print "checked";
					   }
					   print ">Enable SNMP Data Transfer Capture? <font size=\"1\">Capture Data on different Interfaces (WAN, VLANS, LAN etc)</font></p>
					<p><input type=\"checkbox\" name=\"fortigate_capture_SSLvpn\" value=\"1\" ";
					   if ($fortigate_capture_SSLvpn==1){
							print "checked";
					   }
					   print ">Enable SNMP SSL VPN Capture? <font size=\"1\">Number of Tunnels, User Names, Source IPs, Assigned IP, SSL Data Transfer, Up time</font></p>
					<p><input type=\"checkbox\" name=\"fortigate_capture_FW_policy\" value=\"1\" ";
					   if ($fortigate_capture_FW_policy==1){
							print "checked";
					   }
					   print ">Enable SNMP Firewall Policy Capture? <font size=\"1\">Policy Name, Policy Data Used, Policy Date Last Used</font></p>
					<p>Data Logging Captures Per Minuet: <select name=\"fortigate_capture_interval\">";
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
					<p>URL of Fortigate to gather SNMP Information from: <input type=\"text\" name=\"fortigate_nas_url\" value=".$fortigate_nas_url."> ".$fortigate_nas_url_error."</p>
					<p>Name of Fortigate (Leave blank to auto determine name): <input type=\"text\" name=\"fortigate_nas_name\" value=".$fortigate_nas_name."> ".$fortigate_nas_name_error."</p>
					<p>IP of Influx DB: <input type=\"text\" name=\"fortigate_influxdb_host\" value=".$fortigate_influxdb_host."> ".$fortigate_influxdb_host_error."</p>
					<p>PORT of Influx DB: <input type=\"text\" name=\"fortigate_influxdb_port\" value=".$fortigate_influxdb_port."> ".$fortigate_influxdb_port_error."</p>
					<p>Database to use within Influx DB: <input type=\"text\" name=\"fortigate_influxdb_name\" value=".$fortigate_influxdb_name."> ".$fortigate_influxdb_name_error."</p>
					<p>User Name of Influx DB: <input type=\"text\" name=\"fortigate_influxdb_user\" value=".$fortigate_influxdb_user."> ".$fortigate_influxdb_user_error."</p>
					<p>Password of Influx DB: <input type=\"text\" name=\"fortigate_influxdb_pass\" value=".$fortigate_influxdb_pass."> ".$fortigate_influxdb_pass_error."</p>
					<center><input type=\"submit\" name=\"submit_fortigate\" value=\"Submit\" /></center>
				</form>
			</td>
		</tr>
	</table>
</fieldset>";
?>
