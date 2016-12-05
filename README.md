[Device42](http://www.device42.com/) is a comprehensive data center inventory management and IP Address management software
that integrates centralized password management, impact charts and applications mappings with IT asset management.

This repository contains sample script to take Inventory information from a PHPIPAM install and send it to Device42 appliance using the REST APIs.

## Assumptions
-----------------------------
    * The script assumes that you are running PHPIPAM 1.2.1 and above
    * This script works with Device42 10.5.0.1473709546 and above

### Requirements
-----------------------------
    * python 2.7.x
    * netaddr (you can install it with pip install netaddr)
    * pymysql (you can install it with pip install pymysql)
    * requests (you can install it with pip install requests or apt-get install python-requests)
	* allow remote connections to PHPIPAM MySQL port 3306

### Usage
-----------------------------

    * rename conf.sample to conf
    * in conf add D42 URL/credentials
```
# ====== Device42 upload settings ========= #
D42_USER = 'device42 user'
D42_PWD = 'device42 password'
D42_URL = 'https:// device42 server IP address'
```

    * in conf add PHPIPAM DB info/credentials
```
# ====== MySQL Source (PHPIPAM) ====== #
DB_IP = 'phpipam server IP'
DB_PORT = 'phpipam database port'
DB_NAME = 'phpipam database name'
DB_USER = 'phpipam database user'
DB_PWD = 'phpipam database password'
```
	* in conf adjust log settings
```
# ====== Log settings ==================== #
LOGFILE = 'migration.log'
STDOUT = False  # print to STDOUT
DEBUG = True  # write debug log
DEBUG_LOG = 'debug.log'
```


Run the script and enjoy! (`python phpipam2device42.py`)
If you have any questions - feel free to reach out to us at support at device42.com



### Compatibility
-----------------------------
    * Script runs on Linux and Windows


### Gotchas
-----------------------------
    * Understandable device types : 'physical', 'virtual', 'blade', 'cluster', 'other'.
    * Understandable IP types : 'static', 'dhcp', 'reserved'.
    * If type not understandable, 'default' type inserted into D42.
    * Order of function calls in main() function is important. Do not change it!
      For example: subnets must be migrated before IP addresses in order for addresses to join appropriate subnets.


