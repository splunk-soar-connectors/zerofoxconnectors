[comment]: # "Auto-generated SOAR connector documentation"
# ZeroFox Threat Intelligence

Publisher: ZeroFox  
Connector Version: 1.1.0  
Product Vendor: ZeroFox  
Product Name: ZeroFox Threat Intelligence  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

ZeroFox Threat Intelligence

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a ZeroFox Threat Intelligence asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**zerofox_username** |  optional  | string | ZeroFox CTI Username
**zerofox_password** |  optional  | password | ZeroFox CTI Password
**verify_server_cert** |  optional  | boolean | Verify Sever Certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[lookup domain](#action-lookup-domain) - Check for the presence of a domain in the ZeroFox Threat Intelligence Feed  
[lookup ip](#action-lookup-ip) - Check for the presence of an IP in the ZeroFox Threat Intelligence Feed  
[lookup exploit](#action-lookup-exploit) - Check for the presence of a exploit in the ZeroFox Threat Intelligence Feed  
[lookup hash](#action-lookup-hash) - Check for the presence of a hash in the ZeroFox Threat Intelligence Feed  
[lookup email](#action-lookup-email) - Lookup Email Address  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup domain'
Check for the presence of a domain in the ZeroFox Threat Intelligence Feed

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to lookup | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.domain | string |  `domain`  |  
action_result.data.\*.ip | string |  |  
action_result.data.\*.url | string |  |  
action_result.data.\*.details | string |  |  
action_result.data.\*.created_at | string |  |  
action_result.status | string |  |   success  failed 
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'lookup ip'
Check for the presence of an IP in the ZeroFox Threat Intelligence Feed

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to lookup | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.ip | string |  `ip`  |  
action_result.data.\*.url | string |  |  
action_result.data.\*.threat_type | string |  |  
action_result.data.\*.created_at | string |  |  
action_result.status | string |  |   success  failed 
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'lookup exploit'
Check for the presence of a exploit in the ZeroFox Threat Intelligence Feed

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cve** |  required  | CVE to lookup | string |  `cve` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.cve | string |  `cve`  |  
action_result.data.\*.url | string |  |  
action_result.data.\*.created_at | string |  |  
action_result.status | string |  |   success  failed 
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'lookup hash'
Check for the presence of a hash in the ZeroFox Threat Intelligence Feed

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash to lookup | string |  `sha256`  `sha1`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.hash | string |  `sha256`  `sha1`  `md5`  |  
action_result.data.\*.family | string |  |  
action_result.data.\*.created_at | string |  |  
action_result.status | string |  |   success  failed 
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'lookup email'
Lookup Email Address

Type: **investigate**  
Read only: **False**

Check for the presence of an email address in the ZeroFox Threat Intelligence Feed.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email_address** |  required  | Email Address | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.email_address | string |  |  
action_result.data.\*.domain | string |  |  
action_result.data.\*.breach_name | string |  |  
action_result.data.\*.created_at | string |  |  
action_result.status | string |  |   success  failed 
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  