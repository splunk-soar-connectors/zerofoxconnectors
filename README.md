# ZeroFox

Publisher: ZeroFox <br>
Connector Version: 3.6.3 <br>
Product Vendor: ZeroFox <br>
Product Name: ZeroFox <br>
Minimum Product Version: 6.1.1

ZeroFox Alerts for Splunk SOAR

\[comment\]: # File: README.md
\[comment\]: #
\[comment\]: # Copyright (c) ZeroFox, 2024
\[comment\]: #
\[comment\]: # Licensed under the Apache License, Version 2.0 (the "License");
\[comment\]: # you may not use this file except in compliance with the License.
\[comment\]: # You may obtain a copy of the License at
\[comment\]: #
\[comment\]: # http://www.apache.org/licenses/LICENSE-2.0
\[comment\]: #
\[comment\]: # Unless required by applicable law or agreed to in writing, software distributed under
\[comment\]: # the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
\[comment\]: # either express or implied. See the License for the specific language governing permissions
\[comment\]: # and limitations under the License.

### Configuration variables

This table lists the configuration variables required to operate ZeroFox. These variables are specified when configuring a ZeroFox asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**zerofox_api_token** | required | password | ZeroFox API Token |
**username** | required | string | Your ZeroFOX platform username or email address |
**reviewed** | optional | boolean | Only poll reviewed alerts |
**history_days_interval** | required | string | Initial historical alert poll interval (in days) |
**verify_server_cert** | optional | boolean | Verify Sever Certificate |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration <br>
[on poll](#action-on-poll) - Callback action for the on_poll ingest functionality <br>
[take action](#action-take-action) - Take action on a ZeroFox an alert <br>
[tag alert](#action-tag-alert) - Add or remove a tag to a ZeroFox alert <br>
[threat submission](#action-threat-submission) - Add a manual threat to ZeroFox <br>
[lookup alert](#action-lookup-alert) - Retrieve a single alert and it's details, identified by its unique integer identifier <br>
[modify notes](#action-modify-notes) - Append or replace notes on ZeroFox alert

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'on poll'

Callback action for the on_poll ingest functionality

Type: **ingest** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_id** | optional | Container IDs to limit the ingestion to | string | |
**start_time** | optional | Start of time range, in epoch time (milliseconds) | numeric | |
**end_time** | optional | End of time range, in epoch time (milliseconds) | numeric | |
**container_count** | optional | Maximum number of container records to query for | numeric | |
**artifact_count** | optional | Maximum number of artifact records to query for | numeric | |

#### Action Output

No Output

## action: 'take action'

Take action on a ZeroFox an alert

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ZeroFox Alert ID | numeric | |
**alert_action** | required | The action to take | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_action | string | | |
action_result.parameter.alert_id | numeric | | |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'tag alert'

Add or remove a tag to a ZeroFox alert

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ZeroFox Alert ID | numeric | |
**alert_tag** | required | Tag | string | |
**tag_action** | required | Tag action: add or remove | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_id | numeric | | |
action_result.parameter.alert_tag | string | | |
action_result.parameter.tag_action | string | | |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'threat submission'

Add a manual threat to ZeroFox

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**source** | required | Source URL | string | |
**alert_type** | required | Alert Type | string | |
**violation** | required | Violation | string | |
**asset_id** | required | The ZeroFox Asset ID to associate the threat | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_type | string | | |
action_result.parameter.asset_id | numeric | | |
action_result.parameter.source | string | | |
action_result.parameter.violation | string | | |
action_result.data.\*.alert_id | numeric | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'lookup alert'

Retrieve a single alert and it's details, identified by its unique integer identifier

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ZeroFox Alert ID | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_id | numeric | | |
action_result.data.\*.alert.alert_type | string | | |
action_result.data.\*.alert.network | string | | |
action_result.data.\*.alert.offending_content_url | string | | |
action_result.data.\*.alert.rule_name | string | | |
action_result.data.\*.alert.status | string | | |
action_result.data.\*.alert.timestamp | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'modify notes'

Append or replace notes on ZeroFox alert

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**alert_id** | required | ZeroFox Alert ID | numeric | |
**modify_action** | required | Modify action: append or replace | string | |
**notes** | required | Alert's notes | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.alert_id | numeric | | |
action_result.parameter.notes | string | | |
action_result.parameter.modify_action | string | | |
action_result.data | string | | |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
