-- --------------------------------------------------------
-- Хост:                         upcash.pro
-- Версия сервера:               5.7.16-0ubuntu0.16.04.1 - (Ubuntu)
-- Операционная система:         Linux
-- HeidiSQL Версия:              9.4.0.5125
-- --------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!50503 SET NAMES utf8mb4 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;


-- Дамп структуры базы данных brocash
CREATE DATABASE IF NOT EXISTS `brocash` /*!40100 DEFAULT CHARACTER SET latin1 */;
USE `brocash`;

-- Дамп структуры для таблица brocash.giveaway
CREATE TABLE IF NOT EXISTS `giveaway` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `item_name` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `item_img` varchar(2555) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `item_price` int(11) NOT NULL,
  `players` int(11) NOT NULL,
  `playersAll` int(11) NOT NULL,
  `ticketPrice` int(11) NOT NULL,
  `active` int(11) NOT NULL,
  `start` int(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=152 DEFAULT CHARSET=latin1;

-- Дамп данных таблицы brocash.giveaway: ~62 rows (приблизительно)
/*!40000 ALTER TABLE `giveaway` DISABLE KEYS */;
INSERT INTO `giveaway` (`id`, `item_name`, `item_img`, `item_price`, `players`, `playersAll`, `ticketPrice`, `active`, `start`) VALUES
	(1, '123', '1', 1, 1, 64, 2, 2, 999999999),
	(91, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 2, 2, 2, 2, 1479917528),
	(92, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 2, 2, 2, 2, 1479917869),
	(93, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 2, 2, 2, 2, 1479918125),
	(94, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 2, 2, 2, 2, 1479918266),
	(95, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 2, 2, 2, 2, 1479918355),
	(96, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 2, 2, 2, 2, 1479918525),
	(97, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 2, 2, 2, 2, 1479918563),
	(98, 'Монета "60" рублей', '/templates/site/dist/img/cases/coin-60.svg', 60, 2, 2, 4, 2, 1479918662),
	(99, 'Монета "50" рублей', '/templates/site/dist/img/cases/coin-50.svg', 50, 2, 2, 3, 2, 1479918697),
	(100, 'Монета "15" рублей', '/templates/site/dist/img/cases/coin-15.svg', 15, 3, 3, 1, 2, 1479920944),
	(101, 'Монета "50" рублей', '/templates/site/dist/img/cases/coin-50.svg', 50, 4, 4, 3, 2, 1479921560),
	(102, 'Монета "20" рублей', '/templates/site/dist/img/cases/coin-20.svg', 20, 3, 20, 1, 2, 1479922054),
	(103, 'Монета "30" рублей', '/templates/site/dist/img/cases/coin-30.svg', 30, 1, 20, 2, 2, 1480269622),
	(104, 'Монета "50" рублей', '/templates/site/dist/img/cases/coin-50.svg', 50, 0, 20, 3, 2, 1480288642),
	(105, 'Монета "60" рублей', '/templates/site/dist/img/cases/coin-60.svg', 60, 0, 20, 4, 2, 1480309474),
	(106, 'Монета "20" рублей', '/templates/site/dist/img/cases/coin-20.svg', 20, 0, 20, 1, 2, 1480329795),
	(107, 'Монета "20" рублей', '/templates/site/dist/img/cases/coin-20.svg', 20, 1, 20, 1, 2, 1480347938),
	(108, 'Монета "20" рублей', '/templates/site/dist/img/cases/coin-20.svg', 20, 1, 20, 1, 2, 1480386755),
	(109, 'Монета "60" рублей', '/templates/site/dist/img/cases/coin-60.svg', 60, 1, 20, 4, 2, 1480405485),
	(110, 'Монета "30" рублей', '/templates/site/dist/img/cases/coin-30.svg', 30, 1, 20, 2, 2, 1480423837),
	(111, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 0, 20, 2, 2, 1480447854),
	(112, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 1, 20, 2, 2, 1480470077),
	(113, 'Монета "20" рублей', '/templates/site/dist/img/cases/coin-20.svg', 20, 0, 20, 1, 2, 1480496548),
	(114, 'Монета "15" рублей', '/templates/site/dist/img/cases/coin-15.svg', 15, 1, 20, 1, 2, 1480518202),
	(115, 'Монета "60" рублей', '/templates/site/dist/img/cases/coin-60.svg', 60, 0, 20, 4, 2, 1480538121),
	(116, 'Монета "20" рублей', '/templates/site/dist/img/cases/coin-20.svg', 20, 0, 20, 1, 2, 1480574907),
	(117, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 0, 20, 2, 2, 1480594996),
	(118, 'Монета "30" рублей', '/templates/site/dist/img/cases/coin-30.svg', 30, 0, 20, 2, 2, 1480615959),
	(119, 'Монета "20" рублей', '/templates/site/dist/img/cases/coin-20.svg', 20, 0, 20, 1, 2, 1480643075),
	(120, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 0, 20, 2, 2, 1480663541),
	(121, 'Монета "30" рублей', '/templates/site/dist/img/cases/coin-30.svg', 30, 0, 20, 2, 2, 1480683311),
	(122, 'Монета "50" рублей', '/templates/site/dist/img/cases/coin-50.svg', 50, 0, 20, 3, 2, 1480716558),
	(123, 'Монета "30" рублей', '/templates/site/dist/img/cases/coin-30.svg', 30, 1, 20, 2, 2, 1480767586),
	(124, 'Монета "50" рублей', '/templates/site/dist/img/cases/coin-50.svg', 50, 0, 20, 3, 2, 1480787427),
	(125, 'Монета "30" рублей', '/templates/site/dist/img/cases/coin-30.svg', 30, 0, 20, 2, 2, 1480805545),
	(126, 'Монета "50" рублей', '/templates/site/dist/img/cases/coin-50.svg', 50, 0, 20, 3, 2, 1480826448),
	(127, 'Монета "15" рублей', '/templates/site/dist/img/cases/coin-15.svg', 15, 0, 20, 1, 2, 1480854209),
	(128, 'Монета "20" рублей', '/templates/site/dist/img/cases/coin-20.svg', 20, 0, 20, 1, 2, 1480872683),
	(129, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 0, 20, 2, 2, 1480938723),
	(130, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 0, 20, 2, 2, 1480958355),
	(131, 'Монета "50" рублей', '/templates/site/dist/img/cases/coin-50.svg', 50, 0, 20, 3, 2, 1480977391),
	(132, 'Монета "15" рублей', '/templates/site/dist/img/cases/coin-15.svg', 15, 0, 20, 1, 2, 1480996482),
	(133, 'Монета "20" рублей', '/templates/site/dist/img/cases/coin-20.svg', 20, 0, 20, 1, 2, 1481022367),
	(134, 'Монета "60" рублей', '/templates/site/dist/img/cases/coin-60.svg', 60, 0, 20, 4, 2, 1481040417),
	(135, 'Монета "30" рублей', '/templates/site/dist/img/cases/coin-30.svg', 30, 0, 20, 2, 2, 1481058530),
	(136, 'Монета "50" рублей', '/templates/site/dist/img/cases/coin-50.svg', 50, 0, 20, 3, 2, 1481087451),
	(137, 'Монета "60" рублей', '/templates/site/dist/img/cases/coin-60.svg', 60, 2, 2, 4, 2, 1481105495),
	(138, 'Монета "30" рублей', '/templates/site/dist/img/cases/coin-30.svg', 30, 2, 2, 2, 2, 1481108606),
	(139, 'Монета "30" рублей', '/templates/site/dist/img/cases/coin-30.svg', 30, 1, 1, 2, 2, 1481108653),
	(140, 'Монета "20" рублей', '/templates/site/dist/img/cases/coin-20.svg', 20, 2, 20, 1, 2, 1481108689),
	(141, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 0, 20, 2, 2, 1481126697),
	(142, 'Монета "50" рублей', '/templates/site/dist/img/cases/coin-50.svg', 50, 0, 20, 3, 2, 1481145849),
	(143, 'Монета "60" рублей', '/templates/site/dist/img/cases/coin-60.svg', 60, 0, 20, 4, 2, 1481174995),
	(144, 'Монета "15" рублей', '/templates/site/dist/img/cases/coin-15.svg', 15, 0, 20, 1, 2, 1481196690),
	(145, 'Монета "50" рублей', '/templates/site/dist/img/cases/coin-50.svg', 50, 0, 20, 3, 2, 1481215678),
	(146, 'Монета "60" рублей', '/templates/site/dist/img/cases/coin-60.svg', 60, 0, 20, 4, 2, 1481240242),
	(147, 'Монета "30" рублей', '/templates/site/dist/img/cases/coin-30.svg', 30, 0, 20, 2, 2, 1481266057),
	(148, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 0, 20, 2, 2, 1481290465),
	(149, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 0, 20, 2, 2, 1481310614),
	(150, 'Монета "40" рублей', '/templates/site/dist/img/cases/coin-40.svg', 40, 0, 20, 2, 2, 1481342063),
	(151, 'Монета "60" рублей', '/templates/site/dist/img/cases/coin-60.svg', 60, 0, 20, 4, 1, 1481372865);
/*!40000 ALTER TABLE `giveaway` ENABLE KEYS */;

-- Дамп структуры для таблица brocash.info
CREATE TABLE IF NOT EXISTS `info` (
  `info_key` varchar(255) NOT NULL,
  `info_value` varchar(522) NOT NULL,
  PRIMARY KEY (`info_key`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- Дамп данных таблицы brocash.info: 2 rows
/*!40000 ALTER TABLE `info` DISABLE KEYS */;
INSERT INTO `info` (`info_key`, `info_value`) VALUES
	('ga_nickname', 'Егор Моисеев'),
	('ga_ava', 'https://pp.vk.me/c638420/v638420498/1084e/6g4gKThQDjg.jpg');
/*!40000 ALTER TABLE `info` ENABLE KEYS */;

-- Дамп структуры для таблица brocash.rolls
CREATE TABLE IF NOT EXISTS `rolls` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `prizeid` bigint(20) unsigned NOT NULL,
  `vkid` bigint(20) unsigned NOT NULL DEFAULT '0',
  `userimg` varchar(128) COLLATE utf8_unicode_ci NOT NULL DEFAULT '0',
  `caseid` varchar(32) COLLATE utf8_unicode_ci NOT NULL DEFAULT '0',
  `prize` int(20) unsigned NOT NULL DEFAULT '0',
  `profit` double unsigned NOT NULL,
  `prizeimg` varchar(128) COLLATE utf8_unicode_ci NOT NULL DEFAULT '0',
  `time` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=131 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- Дамп данных таблицы brocash.rolls: ~126 rows (приблизительно)
/*!40000 ALTER TABLE `rolls` DISABLE KEYS */;
INSERT INTO `rolls` (`id`, `prizeid`, `vkid`, `userimg`, `caseid`, `prize`, `profit`, `prizeimg`, `time`) VALUES
	(1, 4, 214391662, '0', '4', 40, 5.1, '0', '1479804834'),
	(2, 2, 214391662, '0', '14', 3000, 2040, '0', '1479804861'),
	(3, 4, 214391662, '0', '14', 5000, 1020, '0', '1479804873'),
	(4, 0, 214391662, '0', '4', 10, 28.05, '0', '1479804915'),
	(5, 0, 214391662, '0', '8', 1, 9.69, '0', '1479888908'),
	(6, 0, 214391662, '0', '8', 1, 9.69, '0', '1479888921'),
	(7, 3, 214391662, '0', '2', 30, 10.2, '0', '1479889141'),
	(8, 4, 214391662, '0', '2', 40, 5.1, '0', '1479889154'),
	(9, 0, 214391662, '0', '1', 1, 9.69, '0', '1479889166'),
	(10, 0, 214391662, '0', '1', 1, 9.69, '0', '1479889177'),
	(11, 1, 214391662, '0', '1', 5, 7.65, '0', '1479889242'),
	(12, 0, 214391662, '0', '1', 1, 9.69, '0', '1479889341'),
	(13, 3, 214391662, '0', '2', 30, 10.2, '0', '1479889711'),
	(14, 4, 214391662, '0', '2', 40, 5.1, '0', '1479891460'),
	(15, 2, 214391662, '0', '2', 20, 15.3, '0', '1479891573'),
	(16, 0, 17044378, '0', '1', 1, 9.69, '0', '1479921211'),
	(17, 0, 354288498, '0', '1', 1, 9.69, '0', '1480270651'),
	(18, 0, 354288498, '0', '1', 1, 9.69, '0', '1480270827'),
	(19, 2, 354288498, '0', '1', 10, 5.1, '0', '1480270838'),
	(20, 1, 354288498, '0', '1', 5, 7.65, '0', '1480270850'),
	(21, 7, 354288498, '0', '1', 35, 0, '0', '1480270863'),
	(22, 0, 120601209, '0', '1', 1, 9.69, '0', '1480353322'),
	(23, 2, 120601209, '0', '1', 10, 5.1, '0', '1480353337'),
	(24, 0, 120601209, '0', '7', 100, 204, '0', '1480353441'),
	(25, 0, 120601209, '0', '7', 100, 211.65, '0', '1480353464'),
	(26, 6, 120601209, '0', '6', 600, 0, '0', '1480353518'),
	(27, 4, 120601209, '0', '6', 400, 7.65, '0', '1480353557'),
	(28, 4, 120601209, '0', '8', 500, 102, '0', '1480354657'),
	(29, 0, 354288498, '0', '2', 10, 20.4, '0', '1480400708'),
	(30, 1, 379808682, '0', '1', 5, 7.65, '0', '1480408634'),
	(31, 2, 379808682, '0', '1', 10, 5.1, '0', '1480408872'),
	(32, 0, 379808682, '0', '1', 1, 9.69, '0', '1480409364'),
	(33, 6, 354288498, '0', '1', 30, 0, '0', '1480415495'),
	(34, 1, 69355820, '0', '2', 15, 17.85, '0', '1480434740'),
	(35, 3, 69355820, '0', '2', 30, 10.2, '0', '1480434755'),
	(36, 0, 354288498, '0', '1', 1, 9.69, '0', '1480435037'),
	(37, 1, 69355820, '0', '1', 5, 7.65, '0', '1480518276'),
	(38, 0, 69355820, '0', '1', 1, 9.69, '0', '1480518289'),
	(39, 0, 69355820, '0', '1', 1, 9.69, '0', '1480518301'),
	(40, 0, 69355820, '0', '1', 1, 17.34, '0', '1480518315'),
	(41, 0, 69355820, '0', '1', 1, 17.34, '0', '1480518327'),
	(42, 0, 69355820, '0', '1', 1, 17.34, '0', '1480518348'),
	(43, 1, 69355820, '0', '1', 5, 7.65, '0', '1480518558'),
	(44, 10, 69355820, '0', '1', 50, 0, '0', '1480518569'),
	(45, 0, 354288498, '0', '1', 1, 9.69, '0', '1480518585'),
	(46, 1, 354288498, '0', '1', 5, 7.65, '0', '1480518597'),
	(47, 7, 69355820, '0', '1', 35, 0, '0', '1480518598'),
	(48, 1, 69355820, '0', '1', 5, 7.65, '0', '1480518609'),
	(49, 1, 354288498, '0', '1', 5, 7.65, '0', '1480518611'),
	(50, 9, 69355820, '0', '1', 45, 0, '0', '1480518621'),
	(51, 3, 354288498, '0', '1', 15, 2.55, '0', '1480518629'),
	(52, 0, 354288498, '0', '1', 1, 9.69, '0', '1480518641'),
	(53, 3, 69355820, '0', '1', 15, 2.55, '0', '1480518644'),
	(54, 1, 354288498, '0', '1', 5, 7.65, '0', '1480518656'),
	(55, 2, 69355820, '0', '1', 10, 5.1, '0', '1480518675'),
	(56, 6, 69355820, '0', '1', 30, 0, '0', '1480518689'),
	(57, 1, 69355820, '0', '2', 15, 17.85, '0', '1480518731'),
	(58, 1, 69355820, '0', '2', 15, 17.85, '0', '1480518762'),
	(59, 0, 69355820, '0', '2', 10, 20.4, '0', '1480518777'),
	(60, 4, 69355820, '0', '2', 40, 5.1, '0', '1480518791'),
	(61, 1, 69355820, '0', '2', 15, 17.85, '0', '1480518878'),
	(62, 0, 69355820, '0', '2', 10, 20.4, '0', '1480518891'),
	(63, 8, 69355820, '0', '2', 80, 0, '0', '1480518908'),
	(64, 5, 69355820, '0', '2', 50, 0, '0', '1480518922'),
	(65, 0, 69355820, '0', '2', 10, 20.4, '0', '1480518934'),
	(66, 6, 69355820, '0', '2', 60, 0, '0', '1480518947'),
	(67, 4, 354288498, '0', '2', 40, 5.1, '0', '1480518991'),
	(68, 3, 354288498, '0', '3', 60, 5.1, '0', '1480519003'),
	(69, 0, 354288498, '0', '4', 30, 35.7, '0', '1480519020'),
	(70, 1, 69355820, '0', '8', 200, 255, '0', '1480519978'),
	(71, 5, 69355820, '0', '8', 600, 51, '0', '1480519989'),
	(72, 0, 69355820, '0', '8', 100, 306, '0', '1480520002'),
	(73, 0, 69355820, '0', '8', 100, 306, '0', '1480520015'),
	(74, 2, 69355820, '0', '8', 300, 204, '0', '1480520026'),
	(75, 2, 69355820, '0', '8', 300, 204, '0', '1480520296'),
	(76, 1, 354288498, '0', '1', 5, 7.65, '0', '1480521319'),
	(77, 0, 354288498, '0', '1', 1, 17.34, '0', '1480719646'),
	(78, 2, 69355820, '0', '3', 50, 10.2, '0', '1480802383'),
	(79, 1, 69355820, '0', '3', 40, 15.3, '0', '1480802396'),
	(80, 0, 69355820, '0', '3', 30, 20.4, '0', '1480802408'),
	(81, 3, 69355820, '0', '3', 60, 5.1, '0', '1480802421'),
	(82, 5, 69355820, '0', '3', 80, 0, '0', '1480802433'),
	(83, 0, 373625183, '0', '4', 30, 35.7, '0', '1480873365'),
	(84, 2, 135073256, '0', '2', 20, 15.3, '0', '1480873378'),
	(85, 0, 354288498, '0', '4', 30, 35.7, '0', '1480873388'),
	(86, 1, 354288498, '0', '4', 100, 0, '0', '1480873400'),
	(87, 2, 135073256, '0', '1', 10, 5.1, '0', '1480873418'),
	(88, 0, 354288498, '0', '4', 30, 35.7, '0', '1480873430'),
	(89, 0, 135073256, '0', '1', 1, 9.69, '0', '1480873431'),
	(90, 5, 373625183, '0', '1', 25, 2.55, '0', '1480873437'),
	(91, 4, 135073256, '0', '1', 20, 0, '0', '1480873443'),
	(92, 2, 354288498, '0', '12', 2500, 2295, '0', '1480873445'),
	(93, 5, 135073256, '0', '1', 25, 0, '0', '1480873456'),
	(94, 2, 354288498, '0', '12', 2500, 2295, '0', '1480873459'),
	(95, 5, 135073256, '0', '1', 25, 0, '0', '1480873470'),
	(96, 5, 135073256, '0', '2', 50, 0, '0', '1480873492'),
	(97, 0, 135073256, '0', '2', 10, 20.4, '0', '1480873505'),
	(98, 4, 354288498, '0', '1', 20, 0, '0', '1480873564'),
	(99, 1, 354288498, '0', '1', 5, 7.65, '0', '1480873576'),
	(100, 5, 161438879, '0', '1', 25, 0, '0', '1480873594'),
	(101, 0, 161438879, '0', '4', 30, 35.7, '0', '1480873701'),
	(102, 7, 373625183, '0', '1', 35, 0, '0', '1480873711'),
	(103, 1, 161438879, '0', '1', 5, 7.65, '0', '1480873738'),
	(104, 10, 373625183, '0', '1', 50, 0, '0', '1480873740'),
	(105, 1, 373625183, '0', '2', 15, 20.4, '0', '1480873793'),
	(106, 7, 74555269, '0', '1', 35, 0, '0', '1481108778'),
	(107, 0, 74555269, '0', '1', 1, 12.24, '0', '1481108836'),
	(108, 0, 354288498, '0', '1', 1, 9.69, '0', '1481138973'),
	(109, 4, 354288498, '0', '1', 20, 0, '0', '1481138985'),
	(110, 3, 354288498, '0', '1', 15, 2.55, '0', '1481138997'),
	(111, 0, 74555269, '0', '1', 1, 9.69, '0', '1481143622'),
	(112, 1, 74555269, '0', '1', 5, 7.65, '0', '1481143639'),
	(113, 4, 74555269, '0', '1', 20, 0, '0', '1481143654'),
	(114, 1, 74555269, '0', '1', 5, 7.65, '0', '1481143672'),
	(115, 6, 74555269, '0', '1', 30, 0, '0', '1481143685'),
	(116, 0, 74555269, '0', '1', 1, 9.69, '0', '1481143699'),
	(117, 6, 74555269, '0', '1', 30, 0, '0', '1481179647'),
	(118, 9, 74555269, '0', '1', 45, 0, '0', '1481179741'),
	(119, 3, 74555269, '0', '1', 15, 2.55, '0', '1481180511'),
	(120, 3, 74555269, '0', '1', 15, 2.55, '0', '1481185831'),
	(121, 7, 305107695, '0', '1', 35, 0, '0', '1481197347'),
	(122, 6, 305107695, '0', '1', 30, 0, '0', '1481197380'),
	(123, 4, 305107695, '0', '1', 20, 7.65, '0', '1481197407'),
	(124, 3, 305107695, '0', '1', 15, 2.55, '0', '1481197425'),
	(125, 1, 305107695, '0', '1', 5, 10.2, '0', '1481197491'),
	(126, 7, 74555269, '0', '1', 35, 0, '0', '1481375614'),
	(127, 8, 261564079, '0', '1', 40, 0, '0', '1481378794'),
	(128, 0, 261564079, '0', '1', 1, 9.69, '0', '1481378817'),
	(129, 4, 261564079, '0', '1', 20, 0, '0', '1481378892'),
	(130, 1, 261564079, '0', '1', 5, 7.65, '0', '1481378948');
/*!40000 ALTER TABLE `rolls` ENABLE KEYS */;

-- Дамп структуры для таблица brocash.transactions
CREATE TABLE IF NOT EXISTS `transactions` (
  `id` int(12) unsigned NOT NULL AUTO_INCREMENT,
  `type` varchar(16) COLLATE utf8_unicode_ci NOT NULL,
  `status` varchar(12) COLLATE utf8_unicode_ci NOT NULL DEFAULT '0',
  `amount` varchar(128) COLLATE utf8_unicode_ci NOT NULL DEFAULT '0',
  `vkid` int(11) NOT NULL,
  `timestamp` varchar(32) COLLATE utf8_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=31 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- Дамп данных таблицы brocash.transactions: ~21 rows (приблизительно)
/*!40000 ALTER TABLE `transactions` DISABLE KEYS */;
INSERT INTO `transactions` (`id`, `type`, `status`, `amount`, `vkid`, `timestamp`) VALUES
	(1, 'deposit', 'waiting', '100', 214391662, '1479887874'),
	(2, 'deposit', 'waiting', '100', 17044378, '1479920756'),
	(3, 'deposit', 'waiting', '100', 354288498, '1480275447'),
	(4, 'deposit', 'waiting', '100', 354288498, '1480275547'),
	(5, 'deposit', 'waiting', '100', 354288498, '1480320219'),
	(6, 'deposit', 'waiting', '100', 354288498, '1480326822'),
	(7, 'deposit', 'waiting', '100', 354288498, '1480331928'),
	(8, 'deposit', 'waiting', '100', 354288498, '1480335498'),
	(9, 'deposit', 'waiting', '100', 354288498, '1480335919'),
	(10, 'withdraw', 'done', '100', 69355820, '1480347288'),
	(11, 'withdraw', 'done', '100', 69355820, '1480347350'),
	(12, 'withdraw', 'done', '800', 69355820, '1480347354'),
	(13, 'deposit', 'done', '10', 69355820, '1480347386'),
	(14, 'deposit', 'waiting', '49', 379808682, '1480408272'),
	(15, 'deposit', 'done', '40', 379808682, '1480408466'),
	(16, 'ref', 'done', '10', 379808682, '1480409288'),
	(17, 'ref', 'done', '10', 217036618, '1480409317'),
	(18, 'withdraw', 'done', '100', 354288498, '1480415368'),
	(19, 'deposit', 'waiting', '100', 354288498, '1480719492'),
	(20, 'deposit', 'waiting', '100', 74555269, '1480966296'),
	(21, 'deposit', 'waiting', '100', 74555269, '1480966411'),
	(22, 'deposit', 'waiting', '10', 193197610, '1481039517'),
	(23, 'deposit', 'waiting', '100', 74555269, '1481053722'),
	(24, 'deposit', 'waiting', '100', 74555269, '1481053757'),
	(25, 'withdraw', 'reject', '100', 354288498, '1481137473'),
	(26, 'deposit', 'done', '20', 305107695, '1481197012'),
	(27, 'deposit', 'waiting', '100', 399858566, '1481211286'),
	(28, 'deposit', 'waiting', '27', 261564079, '1481378350'),
	(29, 'deposit', 'waiting', '27', 261564079, '1481378497'),
	(30, 'deposit', 'done', '24', 261564079, '1481378635');
/*!40000 ALTER TABLE `transactions` ENABLE KEYS */;

-- Дамп структуры для таблица brocash.users
CREATE TABLE IF NOT EXISTS `users` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `vkid` bigint(20) unsigned NOT NULL DEFAULT '0',
  `banned` tinyint(1) NOT NULL DEFAULT '0',
  `username` varchar(64) COLLATE utf8_unicode_ci NOT NULL,
  `userimg` varchar(256) COLLATE utf8_unicode_ci NOT NULL DEFAULT '0',
  `balance` bigint(20) unsigned NOT NULL DEFAULT '0',
  `chance` varchar(50) COLLATE utf8_unicode_ci NOT NULL DEFAULT '0',
  `ref` int(11) unsigned NOT NULL DEFAULT '0',
  `accesstoken` varchar(128) COLLATE utf8_unicode_ci NOT NULL DEFAULT '0',
  `regdate` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
  `ip` varchar(40) COLLATE utf8_unicode_ci NOT NULL,
  `giveawayState` int(2) DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=33 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- Дамп данных таблицы brocash.users: ~31 rows (приблизительно)
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` (`id`, `vkid`, `banned`, `username`, `userimg`, `balance`, `chance`, `ref`, `accesstoken`, `regdate`, `ip`, `giveawayState`) VALUES
	(1, 214391662, 1, 'Кирилл Ярмаков', 'https://pp.vk.me/c604525/v604525662/303fa/Zyb_nKG8mW8.jpg', 11111, '0', 0, 'cc6c79947b0de4edd0eceda5abba4f27e3b865f9e33083ea345a7ef6723c759ada85e9c0105d93735e39c', '1479804687', '37.204.44.57', 0),
	(2, 103659005, 1, 'Евгений Черменев', 'https://pp.vk.me/c11355/u103659005/a_039deb8c.jpg', 0, '0', 0, 'df66f200b1c24c6845cba1e3fb3e8929365eb5541d2a43e49a10dc5ea0e12ced09e4fe1d108a11c35d6ba', '1479804721', '95.55.40.246', 0),
	(3, 354288498, 0, 'Егор Моисеев', 'https://pp.vk.me/c638420/v638420498/1084e/6g4gKThQDjg.jpg', 1202570, '0', 0, '5e5a11334393cbc3c366c39014575fbbe3ede8629f64d71d9fd89269f3a750ed2d9feabccab0e390d6eb2', '1479806381', '37.204.44.57', 0),
	(4, 62796182, 1, 'Артём Полинский', 'https://pp.vk.me/c622126/v622126182/3dcb5/zWh9UGFbe-4.jpg', 0, '0', 0, '3566c3f6c9173eb650f5c594ea0b0eca835df6de9926992fec11704a9ff755effdffe07ac3b080be9dec2', '1479823304', '188.232.45.52', 0),
	(5, 69355820, 0, 'Идрис Магомедов', 'https://pp.vk.me/c633626/v633626820/e601/7RDttSwjfzE.jpg', 1940, '0', 0, '3274103b4462f32393401b13b224a86317dc32dce4f91ca9a336bf66d23d7a801b05fb257ae602e360b96', '1479895002', '128.69.251.64', 0),
	(6, 20556596, 1, 'Илья Самусенков', 'https://pp.vk.me/c637917/v637917596/1bb7d/C-B_K7tN6l4.jpg', 0, '0', 0, '72fd57ae3eb3aae08790015daae8c3c50727e824771e255a5e0248ce51dc30c6162740d29fae83cb3bb4e', '1479908562', '91.79.234.181', 0),
	(7, 17044378, 1, 'Александр Левчук', 'https://pp.vk.me/c604430/v604430378/2543a/c9rEpc6LXLg.jpg', 0, '0', 0, '2c89ae30c9a6dae4f210cfc5271a9f671ba061241acbe710548b79269cd27443463392d582f5ea5e3cbc2', '1479920736', '185.124.230.187', 0),
	(8, 255550535, 0, 'Алексей Ронжин', 'https://pp.vk.me/c629225/v629225535/30299/sNvnYteyKnk.jpg', 0, '0', 0, '898219f42c575d997fd70a8a17f01e74f5b79d9f758b8440e718939518c541cae02b6e9d5aaedbfb59bfb', '1480349847', '217.118.78.103', 0),
	(9, 120601209, 0, 'Владислав Кастрыкин', 'https://pp.vk.me/c636722/v636722209/2e648/V35xV-J1QGw.jpg', 0, '0', 0, '1a41976dc06da38799aedd8dabdebab814a1fd68eaccce9fbf4377cc0690e61a6b7315dd0857959fc4982', '1480353266', '128.69.122.102', 0),
	(10, 379808682, 0, 'Виталя Смоленский', 'https://pp.vk.me/c637630/v637630682/15525/t9rMEHpEuWk.jpg', 6, '0', 217036618, 'fa9ecd3318816ab90ba38f88c9403ff0bd0657ba3bf63c6acaa0a192d07c8de9fef6a02e39768da3633bd', '1480408250', '145.255.21.130', 0),
	(11, 217036618, 0, 'Артём Самойлов', 'https://pp.vk.me/c626228/v626228618/30042/70X5r5pOg-0.jpg', 10, '0', 379808682, 'd14c7d2cb7d3aa9592a53d0155620db4e4b5ddbfb09cbcd3249fa01af0e77bbf5bb5af29fd6dae837556a', '1480409009', '178.44.221.52', 0),
	(12, 165573365, 0, 'Денис Кот', 'https://pp.vk.me/c633120/v633120365/24b94/xzgMBv2s6DQ.jpg', 0, '0', 0, 'b96b0853404d7556de39e3ae191cd022cf4c3838f4816ba827c2aca7e4212662acde9209ee8a1670de112', '1480414041', '188.18.113.205', 0),
	(13, 387446056, 0, 'Alex-Krstofer Dremort', 'https://pp.vk.me/c636829/v636829056/308d0/sayb8BpvnL8.jpg', 0, '0', 0, '53f045570c8a0771a30565b2fa1ae6053b258047db6db36ca5334d0d7e8c3cc2c51ffe6caaf4aa3aaa191', '1480426159', '31.134.129.94', 0),
	(14, 398229170, 0, 'Артём Фрид', 'https://vk.com/images/camera_400.png', 0, '0', 0, '0d0a7a6b00c9a2ed148630d70691ffa3b43663790b8622f613d7edcd430907281318a9566fb7b7cfed785', '1480498100', '178.44.132.252', 0),
	(15, 181201237, 0, 'Мансур Барахов', 'https://pp.vk.me/c637817/v637817237/13fea/Zt4Xc8p5JXU.jpg', 0, '0', 0, '32ebe8dca559a677f8913a2e5456bcadc03e426a51e8718546e0770cdbfe0ea6e45b9b070ca1653bdcdd1', '1480525444', '176.59.212.228', 0),
	(16, 229958066, 0, 'Марк Васильев', 'https://pp.vk.me/c626826/v626826066/38a0b/Wl9Klfxpycs.jpg', 0, '0', 0, '7d947a7079c489a7efaa86c7a00aae2d46de34fcf1ffa4f7ce0e880411cc8434fa9ce8a3bd485c385e9ce', '1480588744', '66.102.9.134', 0),
	(17, 290994786, 0, 'Олег Беляев', 'https://pp.vk.me/c622425/v622425786/578ae/obYjwMHc0r0.jpg', 0, '0', 0, '04ba26c081458f8644dc28ea0ab6f3573051c4855a868d1c885c4bd225624ef288c1ff350cedfbfdc1e3d', '1480675713', '78.25.123.163', 0),
	(18, 394993039, 0, 'Ольга Владимировна', 'https://pp.vk.me/c837722/v837722039/c318/wAKudWQuGXY.jpg', 0, '0', 0, '1d078f1553a6c30f1a19803e66defdf5d82274361cdfacb5f3ff1d0f5584a68d5330a4328ceea1155ea2e', '1480872731', '46.165.11.43', 0),
	(19, 373625183, 0, 'Ваня Руинов', 'https://pp.vk.me/c626820/v626820183/3d4d5/RJzLksGONEo.jpg', 15, '0', 0, '448899d7373656327cad5da9db6121341aa9806ec44f55af6607bb3d65a2e41f79ab62d5772a56951b31a', '1480873294', '178.69.206.173', 0),
	(20, 135073256, 0, 'Даниил Агаев', 'https://pp.vk.me/c626221/v626221256/f465/ZJv0KnrB1Hw.jpg', 11, '0', 0, 'd0d096d200895a0f3eb725b9308a49ba2a13986f18918415601d80da38f7202a8a21550bb59703658155c', '1480873323', '37.215.126.227', 0),
	(21, 161438879, 0, 'Макс Заяць', 'https://pp.vk.me/c630931/v630931879/2a0b4/cgMRuJU0qNI.jpg', 19, '0', 0, '7b9e8a4d22de5302aa7a83e824ea7cbed5010fe3f0c9b53532640d0095262c44c1134fa7f0fd8db099c03', '1480873368', '92.112.126.77', 0),
	(22, 169077948, 0, 'Данил Аринушкин', 'https://pp.vk.me/c604518/v604518948/1f202/kWkP4GSDkNo.jpg', 0, '0', 0, '5600d5b8e3d606c6f7be1e7b64367a7dfd2a889e68eac9e398b45992691888bdf98be8485b14eb527a145', '1480956354', '217.118.90.54', 0),
	(23, 74555269, 0, 'Евгений Петров', 'https://pp.vk.me/c627616/v627616269/3d87a/lmv_4hP99UU.jpg', 127, '0', 0, '374eee29cebd3c7515f069b2dee907804dd4f0afc2fb87fd68e6e90ba4b8f6b3134c39025b9c3c3fb8a2e', '1480966257', '84.18.119.190', 0),
	(24, 174633709, 0, 'Влад Сумской', 'https://pp.vk.me/c837328/v837328709/13db5/VF8egdgWvdQ.jpg', 0, '0', 0, 'd9c1a5a0d0690b2e8ee15f9024a18eaf3a07942869c8ea2412f54fde38682dd97bf38fedbe647d9a6002b', '1481022342', '89.130.78.80', 0),
	(25, 193197610, 0, 'Петр Кот', 'https://pp.vk.me/c623422/v623422610/3a14c/mFZm7HEtslQ.jpg', 0, '0', 0, 'ca6450aee09e825d5a4af4e5fcf3fa34b57167de3baa719c34b6dcc205fa76b32ed52914506ec97503533', '1481037657', '82.145.220.37', 0),
	(26, 366951773, 0, 'Кирилл Патраков', 'https://pp.vk.me/c638725/v638725773/104bf/cmlcyaQWnD8.jpg', 0, '0', 0, '43efe2fc4869c613030b86a921f0bf10706c1c1541717bd84dd10f84e3eb8211f2d0b3e5a55706c3f2a85', '1481183166', '193.31.203.244', 0),
	(27, 305107695, 0, 'Артём Пастухов', 'https://vk.com/images/camera_400.png', 5, '0', 0, '3ddc8e20a810daed9d15357a11a5f821fcd8d704ba35be2698d295c100a06809ec9a9974b4139d972f608', '1481196684', '85.192.168.111', 0),
	(28, 399858566, 0, 'Lait Lait', 'https://vk.com/images/camera_400.png', 0, '0', 0, 'cc5c029eed5baf16b71b24770933ecd63612463c32f8085eddcd5e1156b000dcea75527d81baed7bd2e35', '1481198955', '213.230.103.15', 0),
	(29, 353608733, 0, 'Садриддин Сайдалимов', 'https://pp.vk.me/c604520/v604520733/3711d/k5DfxwqgqFo.jpg', 0, '0', 0, '847bd599500926ea5a5bb351b16b3121b756776da98268c84ad641ca689c7e09fc39cc68dab25f7f467d1', '1481290471', '79.174.55.239', 0),
	(30, 222241064, 0, 'Арсений Тихонов', 'https://pp.vk.me/c638222/v638222064/bad5/NR5OdK-6RYw.jpg', 0, '0', 0, '1b64622c9e80990ccd8070cba3f302147b96d764b73138e71bdcc8f7f7e3b7333c9d3b4234c2dc860606d', '1481293246', '5.164.151.20', 0),
	(31, 315821139, 0, 'Алисхан Картоев', 'https://pp.vk.me/c626122/v626122139/29654/8fT2hu0eaVw.jpg', 0, '0', 0, 'a410851391c32c8c796f715d3b4ee9af84128c9801671cdaaa3ae19d042ded99b6697762fd28227f2cc43', '1481376787', '95.213.218.34', 0),
	(32, 261564079, 0, 'Евгений Пьявчук', 'https://pp.vk.me/c626124/v626124079/1cdf6/mjXtCkJ74fU.jpg', 10, '0', 0, '288f4739bc5585cca2dcf52a474ef7de4260c1802e11c99863098fa644adf9b48a111e2be1d8a4d25480d', '1481378285', '37.21.200.100', 0);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;

-- Дамп структуры для таблица brocash.withdraw
CREATE TABLE IF NOT EXISTS `withdraw` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `status` varchar(12) DEFAULT NULL,
  `amount` int(11) DEFAULT NULL,
  `account` varchar(25) DEFAULT NULL,
  `paysystem` varchar(12) DEFAULT NULL,
  `time` varchar(32) DEFAULT NULL,
  `vkid` int(11) DEFAULT NULL,
  `tid` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `withdraw_id_uindex` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=latin1;

-- Дамп данных таблицы brocash.withdraw: ~5 rows (приблизительно)
/*!40000 ALTER TABLE `withdraw` DISABLE KEYS */;
INSERT INTO `withdraw` (`id`, `status`, `amount`, `account`, `paysystem`, `time`, `vkid`, `tid`) VALUES
	(1, 'done', 100, '+79648899992', 'qiwi', '1480347288', 69355820, 10),
	(2, 'done', 100, '+79648899992', 'qiwi', '1480347350', 69355820, 11),
	(3, 'done', 800, '+79648899992', 'qiwi', '1480347354', 69355820, 12),
	(4, 'done', 100, 'frfrr', 'qiwi', '1480415368', 354288498, 18),
	(5, 'reject', 100, '79176711429', 'qiwi', '1481137473', 354288498, 25);
/*!40000 ALTER TABLE `withdraw` ENABLE KEYS */;

/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IF(@OLD_FOREIGN_KEY_CHECKS IS NULL, 1, @OLD_FOREIGN_KEY_CHECKS) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
