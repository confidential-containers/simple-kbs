-- POSTGRES sql definition created from MySQL dump 10.19  Distrib 10.3.28-MariaDB, for Linux (x86_64)
--
-- Host: localhost Database: sev_attest
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
-- Table structure for table conn_bundle
--

-- DROP TABLE IF EXISTS conn_bundle;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE conn_bundle (
  id varchar(512) NOT NULL,
  sev_version INT DEFAULT NULL,
  policy INT DEFAULT NULL,
  fw_api_major INT DEFAULT NULL,
  fw_api_minor INT DEFAULT NULL,
  fw_build_id INT DEFAULT NULL,
  launch_description varchar(512) DEFAULT NULL,
  fw_digest varchar(512) DEFAULT NULL,
  symkey varchar(512) DEFAULT NULL,
  create_date TIMESTAMP DEFAULT NULL,
  delete_date TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (id)
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table conn_bundle
--

--
-- Table structure for table keysets
--

-- DROP TABLE IF EXISTS keysets;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE keysets (
  id SERIAL NOT NULL,
  keysetid varchar(50) NOT NULL,
  kskeys TEXT,
  polid INT DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE(keysetid)
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table keysets
--

--
-- Table structure for table policy
--

-- DROP TABLE IF EXISTS policy;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE policy (
  id SERIAL NOT NULL,
  allowed_digests TEXT DEFAULT NULL,
  allowed_policies TEXT DEFAULT NULL,
  min_fw_api_major INT DEFAULT NULL,
  min_fw_api_minor INT DEFAULT NULL,
  allowed_build_ids TEXT DEFAULT NULL,
  create_date TIMESTAMP DEFAULT NULL,
  delete_date TIMESTAMP DEFAULT NULL,
  valid SMALLINT DEFAULT NULL,
  PRIMARY KEY (id)
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table policy
--

--
-- Table structure for table secrets
--

-- DROP TABLE IF EXISTS secrets;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE secrets (
  id SERIAL NOT NULL,
  secret_id varchar(1024) DEFAULT NULL,
  secret varchar(1024) DEFAULT NULL,
  polid BIGINT DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE(secret_id)
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table secrets
--

--
-- Table structure for table report_keypair
--

-- DROP TABLE IF EXISTS report_keypair;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE report_keypair (
  id SERIAL NOT NULL,
  key_id varchar(1024) DEFAULT NULL,
  keypair varchar(1024) DEFAULT NULL,
  polid BIGINT DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE(key_id)
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table report_keypair
--



/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2022-04-21 14:28:39
