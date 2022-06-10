PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE `conn_bundle` (
  `id` varchar(512) NOT NULL,
  `sev_version` int(11) DEFAULT NULL,
  `policy` int(11) DEFAULT NULL,
  `fw_api_major` int(11) DEFAULT NULL,
  `fw_api_minor` int(11) DEFAULT NULL,
  `fw_build_id` int(11) DEFAULT NULL,
  `launch_description` varchar(512) DEFAULT NULL,
  `fw_digest` varchar(512) DEFAULT NULL,
  `create_date` datetime DEFAULT NULL,
  `delete_date` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
);
CREATE TABLE `keysets` (
`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
`keysetid` varchar(50) NOT NULL,
`kskeys` longtext,
`polid` int(11) DEFAULT NULL,
UNIQUE(`keysetid`)
);
CREATE TABLE `policy` (
`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
`allowed_digests` longtext,
`allowed_policies` longtext,
`min_fw_api_major` int(11) DEFAULT NULL,
`min_fw_api_minor` int(11) DEFAULT NULL,
`allowed_build_ids` longtext,
`create_date` datetime DEFAULT NULL,
`delete_date` datetime DEFAULT NULL,
`valid` tinyint(1) DEFAULT NULL
);
CREATE TABLE `secrets` (
`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
`secret_id` varchar(1024) DEFAULT NULL,
`secret` varchar(1024) DEFAULT NULL,
`polid` int(11) DEFAULT NULL,
UNIQUE(`secret_id`)
);
CREATE TABLE `report_keypair` (
`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
`key_id` varchar(1024) DEFAULT NULL,
`keypair` varchar(1024) DEFAULT NULL,
`polid` int(11) DEFAULT NULL,
UNIQUE(`key_id`)
);
DELETE FROM sqlite_sequence;
COMMIT;
