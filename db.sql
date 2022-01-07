-- MySQL dump 10.19  Distrib 10.3.28-MariaDB, for Linux (x86_64)
--
-- Host: localhost    Database: sev_attest
-- ------------------------------------------------------
-- Server version	10.3.28-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `conn_bundle`
--

DROP TABLE IF EXISTS `conn_bundle`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policy`
--

DROP TABLE IF EXISTS `policy`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `policy` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `allowed_digests` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `allowed_policies` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `min_fw_api_major` int(11) DEFAULT NULL,
  `min_fw_api_minor` int(11) DEFAULT NULL,
  `allowed_build_ids` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL,
  `create_date` datetime DEFAULT NULL,
  `delete_date` datetime DEFAULT NULL,
  `valid` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `secpol`
--

DROP TABLE IF EXISTS `secpol`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `secpol` (
  `secret` varchar(1024) NOT NULL,
  `polids` int(11) DEFAULT NULL,
  PRIMARY KEY (`secret`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `secrets`
--

DROP TABLE IF EXISTS `secrets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `secrets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `secret_id` varchar(1024) DEFAULT NULL,
  `secret` varchar(1024) DEFAULT NULL,
  `polid` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `secret_id` (`secret_id`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8;

/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2022-02-16 15:05:39
