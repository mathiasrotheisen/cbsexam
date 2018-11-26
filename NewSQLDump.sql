-- MySQL dump 10.13  Distrib 5.7.17, for macos10.12 (x86_64)
--
-- Host: 127.0.0.1    Database: cbsexam
-- ------------------------------------------------------
-- Server version	5.6.22

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `address`
--

DROP TABLE IF EXISTS `address`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `address` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(45) COLLATE utf8_danish_ci NOT NULL,
  `city` varchar(45) COLLATE utf8_danish_ci NOT NULL,
  `zipcode` varchar(45) COLLATE utf8_danish_ci NOT NULL,
  `street_address` varchar(255) COLLATE utf8_danish_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8 COLLATE=utf8_danish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `address`
--

LOCK TABLES `address` WRITE;
/*!40000 ALTER TABLE `address` DISABLE KEYS */;
INSERT INTO `address` VALUES (1,'Henrik Thorn','København','2200','Amagerbrogade'),(2,'ITK','København','2400','Lygten'),(3,'Henrik Thorn','København','2200','Amagerbrogade'),(4,'ITK','København','2400','Lygten'),(5,'Henrik Thorn','København','2200','Amagerbrogade'),(6,'ITK','København','2400','Lygten'),(7,'Henrik Thorn','København','2200','Amagerbrogade'),(8,'ITK','København','2400','Lygten'),(9,'Henrik Thorn','København','2200','Amagerbrogade'),(10,'ITK','København','2400','Lygten'),(11,'Henrik Thorn','København','2200','Amagerbrogade'),(12,'ITK','København','2400','Lygten');
/*!40000 ALTER TABLE `address` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `line_item`
--

DROP TABLE IF EXISTS `line_item`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `line_item` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `product_id` int(10) unsigned NOT NULL,
  `order_id` int(10) unsigned NOT NULL,
  `price` float NOT NULL,
  `quantity` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8 COLLATE=utf8_danish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `line_item`
--

LOCK TABLES `line_item` WRITE;
/*!40000 ALTER TABLE `line_item` DISABLE KEYS */;
INSERT INTO `line_item` VALUES (1,1,1,20,3),(2,2,1,25,1),(3,0,2,20,3),(4,0,2,25,1),(5,1,3,20,3),(6,2,3,25,1),(7,1,4,20,3),(8,2,4,25,1),(9,1,5,20,3),(10,2,5,25,1),(11,1,6,20,3),(12,2,6,25,1);
/*!40000 ALTER TABLE `line_item` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `orders`
--

DROP TABLE IF EXISTS `orders`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `orders` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(10) unsigned NOT NULL,
  `billing_address_id` int(10) unsigned NOT NULL,
  `shipping_address_id` int(10) unsigned NOT NULL,
  `order_total` float NOT NULL DEFAULT '0',
  `created_at` int(11) NOT NULL,
  `updated_at` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8 COLLATE=utf8_danish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `orders`
--

LOCK TABLES `orders` WRITE;
/*!40000 ALTER TABLE `orders` DISABLE KEYS */;
INSERT INTO `orders` VALUES (1,7,1,2,80,1,1),(2,8,3,4,45,1539277496,1539277496),(3,9,5,6,45,1539277742,1539277742),(4,10,7,8,45,1539277791,1539277791),(5,11,9,10,45,1539277902,1539277902),(6,12,11,12,45,1539335661,1539335661);
/*!40000 ALTER TABLE `orders` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `product`
--

DROP TABLE IF EXISTS `product`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `product` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `product_name` varchar(255) COLLATE utf8_danish_ci NOT NULL,
  `sku` varchar(255) COLLATE utf8_danish_ci NOT NULL,
  `price` float NOT NULL DEFAULT '0',
  `description` varchar(255) COLLATE utf8_danish_ci DEFAULT NULL,
  `stock` int(11) unsigned NOT NULL DEFAULT '0',
  `created_at` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `sku_UNIQUE` (`sku`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8 COLLATE=utf8_danish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `product`
--

LOCK TABLES `product` WRITE;
/*!40000 ALTER TABLE `product` DISABLE KEYS */;
INSERT INTO `product` VALUES (1,'Cola','coke',20,'Coca Cola',100,1),(2,'Fanta','fanta',25,'Fanta',50,2),(3,'Ju','weed',100,'get high',100,1541420029);
/*!40000 ALTER TABLE `product` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `first_name` varchar(255) COLLATE utf8_danish_ci NOT NULL,
  `last_name` varchar(255) COLLATE utf8_danish_ci NOT NULL,
  `password` varchar(255) COLLATE utf8_danish_ci NOT NULL,
  `email` varchar(255) COLLATE utf8_danish_ci NOT NULL,
  `created_at` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8 COLLATE=utf8_danish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES (6,'Henrik','Thorn','900150983cd24fb0d6963f7d28e17f72','henrik@abc.dk',1539260683),(7,'Henrik','Thorn','ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','henrik@abc.dk',1539260935),(8,'Henrik','Thorn','ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','henrik@abc.dk',1539277503),(9,'Henrik','Thorn','ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','henrik@abc.dk',1539277743),(10,'Henrik','Thorn','ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','henrik@abc.dk',1539277791),(11,'Henrik','Thorn','ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','henrik@abc.dk',1539277902),(12,'Henrik','Thorn','ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','henrik@abc.dk',1539335661),(13,'null','null','null','null',1539338689),(14,'Mathias','Rotheisen','0f73daefcdde9b9447e2c5662eb043b72b4eeffefa710ef756e47015f868054d','mathiasrotheisen@abc.dk',1540915153),(15,'Henrik','Thorn','d12c3692b85546787e16102677edc07d9473739b96ebcef8c466934c11f623e0','henrik@abc.dk',1541516812),(16,'Mettemor','Mettemor','89b476039de4ab1041bf7be06ad96064393500dd71105a1198531cb053598917','mettemor@abc.dk',1541517118),(17,'Mettemor','Mettemor','89b476039de4ab1041bf7be06ad96064393500dd71105a1198531cb053598917','mettemor@abc.dk',1541517298),(18,'Mettemor','Mettemor','89b476039de4ab1041bf7be06ad96064393500dd71105a1198531cb053598917','mettemor@abc.dk',1541517329),(19,'Mettemor','Mettemor','89b476039de4ab1041bf7be06ad96064393500dd71105a1198531cb053598917','mettemor@abc.dk',1541517336),(20,'Mettemor','Mettemor','89b476039de4ab1041bf7be06ad96064393500dd71105a1198531cb053598917','mettemor@abc.dk',1541517338),(21,'Mettemor','Mettemor','89b476039de4ab1041bf7be06ad96064393500dd71105a1198531cb053598917','mettemor@abc.dk',1541517339),(22,'lortelortlortlort','lort','20e3e3e2072d975a0055841c7ea8e13b1caca79ad9a789ff117ca2c643b8f0f2','lort@abc.dk',1541517481),(25,'mathimathias','tadsadsdadsa','b2d31634d5c12f85372eaee7a4a36028398c0daab3a2021090ca0fe6c3069433','joergensvend@abc.dk',1542580685);
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-11-26 16:52:21
