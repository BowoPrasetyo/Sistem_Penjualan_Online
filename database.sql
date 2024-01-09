-- phpMyAdmin SQL Dump
-- version 5.0.2
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Generation Time: Jul 13, 2020 at 11:45 AM
-- Server version: 10.4.11-MariaDB
-- PHP Version: 7.3.16

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `buyer_satu`
--

-- --------------------------------------------------------

--
-- Table structure for table `affiliators_commision`
--

CREATE TABLE `affiliators_commision` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `amount` double NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `categories`
--

CREATE TABLE `categories` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `status` varchar(40) COLLATE utf8mb4_unicode_ci DEFAULT 'draft',
  `name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` text COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `icon` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `image` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `categories`
--

INSERT INTO `categories` (`id`, `status`, `name`, `description`, `icon`, `image`, `created_at`, `updated_at`) VALUES
(1, 'publish', 'Herbal', 'Herbal', NULL, NULL, NULL, NULL),
(2, 'publish', 'Software', 'Kategori ini menjual berbagai macam aplikasi webapp dan desktop app', NULL, NULL, NULL, NULL),
(3, 'draft', 'Fashion', 'Ada Orderan Langsung Kami Layani Dengan Cepat\r\n\r\nNotification \r\nLibur Nasional & Minggu Pengiriman Off \r\nVertifikasi Pembayaran Di Atas Pukul 16.00 Wib Pengiriman Esok Hari\r\nTanya Kan Stok Terlebih Dahulu Sebelum Order Di Karena Kan Stok Terbatas \r\n\r\nMore Info \r\nLangsung Chat Saja Akan Kami Balas Secepat Mungkin \r\n\r\nEkspedisi Via the \r\nJNE, J&T, POS \r\n\r\nSelamat Datang Dan Selamat Berbelanja Ka Ya ^_^', NULL, NULL, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `cities`
--

CREATE TABLE `cities` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `city_id` bigint(20) UNSIGNED NOT NULL,
  `province_id` bigint(20) UNSIGNED NOT NULL,
  `type` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `city_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `postal_code` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `cities`
--

INSERT INTO `cities` (`id`, `city_id`, `province_id`, `type`, `city_name`, `postal_code`, `created_at`, `updated_at`) VALUES
(1, 17, 1, 'Kabupaten', 'Badung', '80351', NULL, NULL),
(2, 32, 1, 'Kabupaten', 'Bangli', '80619', NULL, NULL),
(3, 94, 1, 'Kabupaten', 'Buleleng', '81111', NULL, NULL),
(4, 114, 1, 'Kota', 'Denpasar', '80227', NULL, NULL),
(5, 128, 1, 'Kabupaten', 'Gianyar', '80519', NULL, NULL),
(6, 161, 1, 'Kabupaten', 'Jembrana', '82251', NULL, NULL),
(7, 170, 1, 'Kabupaten', 'Karangasem', '80819', NULL, NULL),
(8, 197, 1, 'Kabupaten', 'Klungkung', '80719', NULL, NULL),
(9, 447, 1, 'Kabupaten', 'Tabanan', '82119', NULL, NULL),
(10, 27, 2, 'Kabupaten', 'Bangka', '33212', NULL, NULL),
(11, 28, 2, 'Kabupaten', 'Bangka Barat', '33315', NULL, NULL),
(12, 29, 2, 'Kabupaten', 'Bangka Selatan', '33719', NULL, NULL),
(13, 30, 2, 'Kabupaten', 'Bangka Tengah', '33613', NULL, NULL),
(14, 56, 2, 'Kabupaten', 'Belitung', '33419', NULL, NULL),
(15, 57, 2, 'Kabupaten', 'Belitung Timur', '33519', NULL, NULL),
(16, 334, 2, 'Kota', 'Pangkal Pinang', '33115', NULL, NULL),
(17, 106, 3, 'Kota', 'Cilegon', '42417', NULL, NULL),
(18, 232, 3, 'Kabupaten', 'Lebak', '42319', NULL, NULL),
(19, 331, 3, 'Kabupaten', 'Pandeglang', '42212', NULL, NULL),
(20, 402, 3, 'Kabupaten', 'Serang', '42182', NULL, NULL),
(21, 403, 3, 'Kota', 'Serang', '42111', NULL, NULL),
(22, 455, 3, 'Kabupaten', 'Tangerang', '15914', NULL, NULL),
(23, 456, 3, 'Kota', 'Tangerang', '15111', NULL, NULL),
(24, 457, 3, 'Kota', 'Tangerang Selatan', '15332', NULL, NULL),
(25, 62, 4, 'Kota', 'Bengkulu', '38229', NULL, NULL),
(26, 63, 4, 'Kabupaten', 'Bengkulu Selatan', '38519', NULL, NULL),
(27, 64, 4, 'Kabupaten', 'Bengkulu Tengah', '38319', NULL, NULL),
(28, 65, 4, 'Kabupaten', 'Bengkulu Utara', '38619', NULL, NULL),
(29, 175, 4, 'Kabupaten', 'Kaur', '38911', NULL, NULL),
(30, 183, 4, 'Kabupaten', 'Kepahiang', '39319', NULL, NULL),
(31, 233, 4, 'Kabupaten', 'Lebong', '39264', NULL, NULL),
(32, 294, 4, 'Kabupaten', 'Muko Muko', '38715', NULL, NULL),
(33, 379, 4, 'Kabupaten', 'Rejang Lebong', '39112', NULL, NULL),
(34, 397, 4, 'Kabupaten', 'Seluma', '38811', NULL, NULL),
(35, 39, 5, 'Kabupaten', 'Bantul', '55715', NULL, NULL),
(36, 135, 5, 'Kabupaten', 'Gunung Kidul', '55812', NULL, NULL),
(37, 210, 5, 'Kabupaten', 'Kulon Progo', '55611', NULL, NULL),
(38, 419, 5, 'Kabupaten', 'Sleman', '55513', NULL, NULL),
(39, 501, 5, 'Kota', 'Yogyakarta', '55111', NULL, NULL),
(40, 151, 6, 'Kota', 'Jakarta Barat', '11220', NULL, NULL),
(41, 152, 6, 'Kota', 'Jakarta Pusat', '10540', NULL, NULL),
(42, 153, 6, 'Kota', 'Jakarta Selatan', '12230', NULL, NULL),
(43, 154, 6, 'Kota', 'Jakarta Timur', '13330', NULL, NULL),
(44, 155, 6, 'Kota', 'Jakarta Utara', '14140', NULL, NULL),
(45, 189, 6, 'Kabupaten', 'Kepulauan Seribu', '14550', NULL, NULL),
(46, 77, 7, 'Kabupaten', 'Boalemo', '96319', NULL, NULL),
(47, 88, 7, 'Kabupaten', 'Bone Bolango', '96511', NULL, NULL),
(48, 129, 7, 'Kabupaten', 'Gorontalo', '96218', NULL, NULL),
(49, 130, 7, 'Kota', 'Gorontalo', '96115', NULL, NULL),
(50, 131, 7, 'Kabupaten', 'Gorontalo Utara', '96611', NULL, NULL),
(51, 361, 7, 'Kabupaten', 'Pohuwato', '96419', NULL, NULL),
(52, 50, 8, 'Kabupaten', 'Batang Hari', '36613', NULL, NULL),
(53, 97, 8, 'Kabupaten', 'Bungo', '37216', NULL, NULL),
(54, 156, 8, 'Kota', 'Jambi', '36111', NULL, NULL),
(55, 194, 8, 'Kabupaten', 'Kerinci', '37167', NULL, NULL),
(56, 280, 8, 'Kabupaten', 'Merangin', '37319', NULL, NULL),
(57, 293, 8, 'Kabupaten', 'Muaro Jambi', '36311', NULL, NULL),
(58, 393, 8, 'Kabupaten', 'Sarolangun', '37419', NULL, NULL),
(59, 442, 8, 'Kota', 'Sungaipenuh', '37113', NULL, NULL),
(60, 460, 8, 'Kabupaten', 'Tanjung Jabung Barat', '36513', NULL, NULL),
(61, 461, 8, 'Kabupaten', 'Tanjung Jabung Timur', '36719', NULL, NULL),
(62, 471, 8, 'Kabupaten', 'Tebo', '37519', NULL, NULL),
(63, 22, 9, 'Kabupaten', 'Bandung', '40311', NULL, NULL),
(64, 23, 9, 'Kota', 'Bandung', '40111', NULL, NULL),
(65, 24, 9, 'Kabupaten', 'Bandung Barat', '40721', NULL, NULL),
(66, 34, 9, 'Kota', 'Banjar', '46311', NULL, NULL),
(67, 54, 9, 'Kabupaten', 'Bekasi', '17837', NULL, NULL),
(68, 55, 9, 'Kota', 'Bekasi', '17121', NULL, NULL),
(69, 78, 9, 'Kabupaten', 'Bogor', '16911', NULL, NULL),
(70, 79, 9, 'Kota', 'Bogor', '16119', NULL, NULL),
(71, 103, 9, 'Kabupaten', 'Ciamis', '46211', NULL, NULL),
(72, 104, 9, 'Kabupaten', 'Cianjur', '43217', NULL, NULL),
(73, 107, 9, 'Kota', 'Cimahi', '40512', NULL, NULL),
(74, 108, 9, 'Kabupaten', 'Cirebon', '45611', NULL, NULL),
(75, 109, 9, 'Kota', 'Cirebon', '45116', NULL, NULL),
(76, 115, 9, 'Kota', 'Depok', '16416', NULL, NULL),
(77, 126, 9, 'Kabupaten', 'Garut', '44126', NULL, NULL),
(78, 149, 9, 'Kabupaten', 'Indramayu', '45214', NULL, NULL),
(79, 171, 9, 'Kabupaten', 'Karawang', '41311', NULL, NULL),
(80, 211, 9, 'Kabupaten', 'Kuningan', '45511', NULL, NULL),
(81, 252, 9, 'Kabupaten', 'Majalengka', '45412', NULL, NULL),
(82, 332, 9, 'Kabupaten', 'Pangandaran', '46511', NULL, NULL),
(83, 376, 9, 'Kabupaten', 'Purwakarta', '41119', NULL, NULL),
(84, 428, 9, 'Kabupaten', 'Subang', '41215', NULL, NULL),
(85, 430, 9, 'Kabupaten', 'Sukabumi', '43311', NULL, NULL),
(86, 431, 9, 'Kota', 'Sukabumi', '43114', NULL, NULL),
(87, 440, 9, 'Kabupaten', 'Sumedang', '45326', NULL, NULL),
(88, 468, 9, 'Kabupaten', 'Tasikmalaya', '46411', NULL, NULL),
(89, 469, 9, 'Kota', 'Tasikmalaya', '46116', NULL, NULL),
(90, 37, 10, 'Kabupaten', 'Banjarnegara', '53419', NULL, NULL),
(91, 41, 10, 'Kabupaten', 'Banyumas', '53114', NULL, NULL),
(92, 49, 10, 'Kabupaten', 'Batang', '51211', NULL, NULL),
(93, 76, 10, 'Kabupaten', 'Blora', '58219', NULL, NULL),
(94, 91, 10, 'Kabupaten', 'Boyolali', '57312', NULL, NULL),
(95, 92, 10, 'Kabupaten', 'Brebes', '52212', NULL, NULL),
(96, 105, 10, 'Kabupaten', 'Cilacap', '53211', NULL, NULL),
(97, 113, 10, 'Kabupaten', 'Demak', '59519', NULL, NULL),
(98, 134, 10, 'Kabupaten', 'Grobogan', '58111', NULL, NULL),
(99, 163, 10, 'Kabupaten', 'Jepara', '59419', NULL, NULL),
(100, 169, 10, 'Kabupaten', 'Karanganyar', '57718', NULL, NULL),
(101, 177, 10, 'Kabupaten', 'Kebumen', '54319', NULL, NULL),
(102, 181, 10, 'Kabupaten', 'Kendal', '51314', NULL, NULL),
(103, 196, 10, 'Kabupaten', 'Klaten', '57411', NULL, NULL),
(104, 209, 10, 'Kabupaten', 'Kudus', '59311', NULL, NULL),
(105, 249, 10, 'Kabupaten', 'Magelang', '56519', NULL, NULL),
(106, 250, 10, 'Kota', 'Magelang', '56133', NULL, NULL),
(107, 344, 10, 'Kabupaten', 'Pati', '59114', NULL, NULL),
(108, 348, 10, 'Kabupaten', 'Pekalongan', '51161', NULL, NULL),
(109, 349, 10, 'Kota', 'Pekalongan', '51122', NULL, NULL),
(110, 352, 10, 'Kabupaten', 'Pemalang', '52319', NULL, NULL),
(111, 375, 10, 'Kabupaten', 'Purbalingga', '53312', NULL, NULL),
(112, 377, 10, 'Kabupaten', 'Purworejo', '54111', NULL, NULL),
(113, 380, 10, 'Kabupaten', 'Rembang', '59219', NULL, NULL),
(114, 386, 10, 'Kota', 'Salatiga', '50711', NULL, NULL),
(115, 398, 10, 'Kabupaten', 'Semarang', '50511', NULL, NULL),
(116, 399, 10, 'Kota', 'Semarang', '50135', NULL, NULL),
(117, 427, 10, 'Kabupaten', 'Sragen', '57211', NULL, NULL),
(118, 433, 10, 'Kabupaten', 'Sukoharjo', '57514', NULL, NULL),
(119, 445, 10, 'Kota', 'Surakarta (Solo)', '57113', NULL, NULL),
(120, 472, 10, 'Kabupaten', 'Tegal', '52419', NULL, NULL),
(121, 473, 10, 'Kota', 'Tegal', '52114', NULL, NULL),
(122, 476, 10, 'Kabupaten', 'Temanggung', '56212', NULL, NULL),
(123, 497, 10, 'Kabupaten', 'Wonogiri', '57619', NULL, NULL),
(124, 498, 10, 'Kabupaten', 'Wonosobo', '56311', NULL, NULL),
(125, 31, 11, 'Kabupaten', 'Bangkalan', '69118', NULL, NULL),
(126, 42, 11, 'Kabupaten', 'Banyuwangi', '68416', NULL, NULL),
(127, 51, 11, 'Kota', 'Batu', '65311', NULL, NULL),
(128, 74, 11, 'Kabupaten', 'Blitar', '66171', NULL, NULL),
(129, 75, 11, 'Kota', 'Blitar', '66124', NULL, NULL),
(130, 80, 11, 'Kabupaten', 'Bojonegoro', '62119', NULL, NULL),
(131, 86, 11, 'Kabupaten', 'Bondowoso', '68219', NULL, NULL),
(132, 133, 11, 'Kabupaten', 'Gresik', '61115', NULL, NULL),
(133, 160, 11, 'Kabupaten', 'Jember', '68113', NULL, NULL),
(134, 164, 11, 'Kabupaten', 'Jombang', '61415', NULL, NULL),
(135, 178, 11, 'Kabupaten', 'Kediri', '64184', NULL, NULL),
(136, 179, 11, 'Kota', 'Kediri', '64125', NULL, NULL),
(137, 222, 11, 'Kabupaten', 'Lamongan', '64125', NULL, NULL),
(138, 243, 11, 'Kabupaten', 'Lumajang', '67319', NULL, NULL),
(139, 247, 11, 'Kabupaten', 'Madiun', '63153', NULL, NULL),
(140, 248, 11, 'Kota', 'Madiun', '63122', NULL, NULL),
(141, 251, 11, 'Kabupaten', 'Magetan', '63314', NULL, NULL),
(142, 256, 11, 'Kota', 'Malang', '65112', NULL, NULL),
(143, 255, 11, 'Kabupaten', 'Malang', '65163', NULL, NULL),
(144, 289, 11, 'Kabupaten', 'Mojokerto', '61382', NULL, NULL),
(145, 290, 11, 'Kota', 'Mojokerto', '61316', NULL, NULL),
(146, 305, 11, 'Kabupaten', 'Nganjuk', '64414', NULL, NULL),
(147, 306, 11, 'Kabupaten', 'Ngawi', '63219', NULL, NULL),
(148, 317, 11, 'Kabupaten', 'Pacitan', '63512', NULL, NULL),
(149, 330, 11, 'Kabupaten', 'Pamekasan', '69319', NULL, NULL),
(150, 342, 11, 'Kabupaten', 'Pasuruan', '67153', NULL, NULL),
(151, 343, 11, 'Kota', 'Pasuruan', '67118', NULL, NULL),
(152, 363, 11, 'Kabupaten', 'Ponorogo', '63411', NULL, NULL),
(153, 369, 11, 'Kabupaten', 'Probolinggo', '67282', NULL, NULL),
(154, 370, 11, 'Kota', 'Probolinggo', '67215', NULL, NULL),
(155, 390, 11, 'Kabupaten', 'Sampang', '69219', NULL, NULL),
(156, 409, 11, 'Kabupaten', 'Sidoarjo', '61219', NULL, NULL),
(157, 418, 11, 'Kabupaten', 'Situbondo', '68316', NULL, NULL),
(158, 441, 11, 'Kabupaten', 'Sumenep', '69413', NULL, NULL),
(159, 444, 11, 'Kota', 'Surabaya', '60119', NULL, NULL),
(160, 487, 11, 'Kabupaten', 'Trenggalek', '66312', NULL, NULL),
(161, 489, 11, 'Kabupaten', 'Tuban', '62319', NULL, NULL),
(162, 492, 11, 'Kabupaten', 'Tulungagung', '66212', NULL, NULL),
(163, 61, 12, 'Kabupaten', 'Bengkayang', '79213', NULL, NULL),
(164, 168, 12, 'Kabupaten', 'Kapuas Hulu', '78719', NULL, NULL),
(165, 176, 12, 'Kabupaten', 'Kayong Utara', '78852', NULL, NULL),
(166, 195, 12, 'Kabupaten', 'Ketapang', '78874', NULL, NULL),
(167, 208, 12, 'Kabupaten', 'Kubu Raya', '78311', NULL, NULL),
(168, 228, 12, 'Kabupaten', 'Landak', '78319', NULL, NULL),
(169, 279, 12, 'Kabupaten', 'Melawi', '78619', NULL, NULL),
(170, 364, 12, 'Kabupaten', 'Pontianak', '78971', NULL, NULL),
(171, 365, 12, 'Kota', 'Pontianak', '78112', NULL, NULL),
(172, 388, 12, 'Kabupaten', 'Sambas', '79453', NULL, NULL),
(173, 391, 12, 'Kabupaten', 'Sanggau', '78557', NULL, NULL),
(174, 395, 12, 'Kabupaten', 'Sekadau', '79583', NULL, NULL),
(175, 415, 12, 'Kota', 'Singkawang', '79117', NULL, NULL),
(176, 417, 12, 'Kabupaten', 'Sintang', '78619', NULL, NULL),
(177, 18, 13, 'Kabupaten', 'Balangan', '71611', NULL, NULL),
(178, 33, 13, 'Kabupaten', 'Banjar', '70619', NULL, NULL),
(179, 35, 13, 'Kota', 'Banjarbaru', '70712', NULL, NULL),
(180, 36, 13, 'Kota', 'Banjarmasin', '70117', NULL, NULL),
(181, 43, 13, 'Kabupaten', 'Barito Kuala', '70511', NULL, NULL),
(182, 143, 13, 'Kabupaten', 'Hulu Sungai Selatan', '71212', NULL, NULL),
(183, 144, 13, 'Kabupaten', 'Hulu Sungai Tengah', '71313', NULL, NULL),
(184, 145, 13, 'Kabupaten', 'Hulu Sungai Utara', '71419', NULL, NULL),
(185, 203, 13, 'Kabupaten', 'Kotabaru', '72119', NULL, NULL),
(186, 446, 13, 'Kabupaten', 'Tabalong', '71513', NULL, NULL),
(187, 452, 13, 'Kabupaten', 'Tanah Bumbu', '72211', NULL, NULL),
(188, 454, 13, 'Kabupaten', 'Tanah Laut', '70811', NULL, NULL),
(189, 466, 13, 'Kabupaten', 'Tapin', '71119', NULL, NULL),
(190, 44, 14, 'Kabupaten', 'Barito Selatan', '73711', NULL, NULL),
(191, 45, 14, 'Kabupaten', 'Barito Timur', '73671', NULL, NULL),
(192, 46, 14, 'Kabupaten', 'Barito Utara', '73881', NULL, NULL),
(193, 136, 14, 'Kabupaten', 'Gunung Mas', '74511', NULL, NULL),
(194, 167, 14, 'Kabupaten', 'Kapuas', '73583', NULL, NULL),
(195, 174, 14, 'Kabupaten', 'Katingan', '74411', NULL, NULL),
(196, 205, 14, 'Kabupaten', 'Kotawaringin Barat', '74119', NULL, NULL),
(197, 206, 14, 'Kabupaten', 'Kotawaringin Timur', '74364', NULL, NULL),
(198, 221, 14, 'Kabupaten', 'Lamandau', '74611', NULL, NULL),
(199, 296, 14, 'Kabupaten', 'Murung Raya', '73911', NULL, NULL),
(200, 326, 14, 'Kota', 'Palangka Raya', '73112', NULL, NULL),
(201, 371, 14, 'Kabupaten', 'Pulang Pisau', '74811', NULL, NULL),
(202, 405, 14, 'Kabupaten', 'Seruyan', '74211', NULL, NULL),
(203, 432, 14, 'Kabupaten', 'Sukamara', '74712', NULL, NULL),
(204, 19, 15, 'Kota', 'Balikpapan', '76111', NULL, NULL),
(205, 66, 15, 'Kabupaten', 'Berau', '77311', NULL, NULL),
(206, 89, 15, 'Kota', 'Bontang', '75313', NULL, NULL),
(207, 214, 15, 'Kabupaten', 'Kutai Barat', '75711', NULL, NULL),
(208, 215, 15, 'Kabupaten', 'Kutai Kartanegara', '75511', NULL, NULL),
(209, 216, 15, 'Kabupaten', 'Kutai Timur', '75611', NULL, NULL),
(210, 341, 15, 'Kabupaten', 'Paser', '76211', NULL, NULL),
(211, 354, 15, 'Kabupaten', 'Penajam Paser Utara', '76311', NULL, NULL),
(212, 387, 15, 'Kota', 'Samarinda', '75133', NULL, NULL),
(213, 96, 16, 'Kabupaten', 'Bulungan (Bulongan)', '77211', NULL, NULL),
(214, 257, 16, 'Kabupaten', 'Malinau', '77511', NULL, NULL),
(215, 311, 16, 'Kabupaten', 'Nunukan', '77421', NULL, NULL),
(216, 450, 16, 'Kabupaten', 'Tana Tidung', '77611', NULL, NULL),
(217, 467, 16, 'Kota', 'Tarakan', '77114', NULL, NULL),
(218, 48, 17, 'Kota', 'Batam', '29413', NULL, NULL),
(219, 71, 17, 'Kabupaten', 'Bintan', '29135', NULL, NULL),
(220, 172, 17, 'Kabupaten', 'Karimun', '29611', NULL, NULL),
(221, 184, 17, 'Kabupaten', 'Kepulauan Anambas', '29991', NULL, NULL),
(222, 237, 17, 'Kabupaten', 'Lingga', '29811', NULL, NULL),
(223, 302, 17, 'Kabupaten', 'Natuna', '29711', NULL, NULL),
(224, 462, 17, 'Kota', 'Tanjung Pinang', '29111', NULL, NULL),
(225, 21, 18, 'Kota', 'Bandar Lampung', '35139', NULL, NULL),
(226, 223, 18, 'Kabupaten', 'Lampung Barat', '34814', NULL, NULL),
(227, 224, 18, 'Kabupaten', 'Lampung Selatan', '35511', NULL, NULL),
(228, 225, 18, 'Kabupaten', 'Lampung Tengah', '34212', NULL, NULL),
(229, 226, 18, 'Kabupaten', 'Lampung Timur', '34319', NULL, NULL),
(230, 227, 18, 'Kabupaten', 'Lampung Utara', '34516', NULL, NULL),
(231, 282, 18, 'Kabupaten', 'Mesuji', '34911', NULL, NULL),
(232, 283, 18, 'Kota', 'Metro', '34111', NULL, NULL),
(233, 355, 18, 'Kabupaten', 'Pesawaran', '35312', NULL, NULL),
(234, 356, 18, 'Kabupaten', 'Pesisir Barat', '35974', NULL, NULL),
(235, 368, 18, 'Kabupaten', 'Pringsewu', '35719', NULL, NULL),
(236, 458, 18, 'Kabupaten', 'Tanggamus', '35619', NULL, NULL),
(237, 490, 18, 'Kabupaten', 'Tulang Bawang', '34613', NULL, NULL),
(238, 491, 18, 'Kabupaten', 'Tulang Bawang Barat', '34419', NULL, NULL),
(239, 496, 18, 'Kabupaten', 'Way Kanan', '34711', NULL, NULL),
(240, 14, 19, 'Kota', 'Ambon', '97222', NULL, NULL),
(241, 99, 19, 'Kabupaten', 'Buru', '97371', NULL, NULL),
(242, 100, 19, 'Kabupaten', 'Buru Selatan', '97351', NULL, NULL),
(243, 185, 19, 'Kabupaten', 'Kepulauan Aru', '97681', NULL, NULL),
(244, 258, 19, 'Kabupaten', 'Maluku Barat Daya', '97451', NULL, NULL),
(245, 259, 19, 'Kabupaten', 'Maluku Tengah', '97513', NULL, NULL),
(246, 260, 19, 'Kabupaten', 'Maluku Tenggara', '97651', NULL, NULL),
(247, 261, 19, 'Kabupaten', 'Maluku Tenggara Barat', '97465', NULL, NULL),
(248, 400, 19, 'Kabupaten', 'Seram Bagian Barat', '97561', NULL, NULL),
(249, 401, 19, 'Kabupaten', 'Seram Bagian Timur', '97581', NULL, NULL),
(250, 488, 19, 'Kota', 'Tual', '97612', NULL, NULL),
(251, 138, 20, 'Kabupaten', 'Halmahera Barat', '97757', NULL, NULL),
(252, 139, 20, 'Kabupaten', 'Halmahera Selatan', '97911', NULL, NULL),
(253, 140, 20, 'Kabupaten', 'Halmahera Tengah', '97853', NULL, NULL),
(254, 141, 20, 'Kabupaten', 'Halmahera Timur', '97862', NULL, NULL),
(255, 142, 20, 'Kabupaten', 'Halmahera Utara', '97762', NULL, NULL),
(256, 191, 20, 'Kabupaten', 'Kepulauan Sula', '97995', NULL, NULL),
(257, 372, 20, 'Kabupaten', 'Pulau Morotai', '97771', NULL, NULL),
(258, 477, 20, 'Kota', 'Ternate', '97714', NULL, NULL),
(259, 478, 20, 'Kota', 'Tidore Kepulauan', '97815', NULL, NULL),
(260, 1, 21, 'Kabupaten', 'Aceh Barat', '23681', NULL, NULL),
(261, 2, 21, 'Kabupaten', 'Aceh Barat Daya', '23764', NULL, NULL),
(262, 3, 21, 'Kabupaten', 'Aceh Besar', '23951', NULL, NULL),
(263, 4, 21, 'Kabupaten', 'Aceh Jaya', '23654', NULL, NULL),
(264, 5, 21, 'Kabupaten', 'Aceh Selatan', '23719', NULL, NULL),
(265, 6, 21, 'Kabupaten', 'Aceh Singkil', '24785', NULL, NULL),
(266, 7, 21, 'Kabupaten', 'Aceh Tamiang', '24476', NULL, NULL),
(267, 8, 21, 'Kabupaten', 'Aceh Tengah', '24511', NULL, NULL),
(268, 9, 21, 'Kabupaten', 'Aceh Tenggara', '24611', NULL, NULL),
(269, 10, 21, 'Kabupaten', 'Aceh Timur', '24454', NULL, NULL),
(270, 11, 21, 'Kabupaten', 'Aceh Utara', '24382', NULL, NULL),
(271, 20, 21, 'Kota', 'Banda Aceh', '23238', NULL, NULL),
(272, 59, 21, 'Kabupaten', 'Bener Meriah', '24581', NULL, NULL),
(273, 72, 21, 'Kabupaten', 'Bireuen', '24219', NULL, NULL),
(274, 127, 21, 'Kabupaten', 'Gayo Lues', '24653', NULL, NULL),
(275, 230, 21, 'Kota', 'Langsa', '24412', NULL, NULL),
(276, 235, 21, 'Kota', 'Lhokseumawe', '24352', NULL, NULL),
(277, 300, 21, 'Kabupaten', 'Nagan Raya', '23674', NULL, NULL),
(278, 358, 21, 'Kabupaten', 'Pidie', '24116', NULL, NULL),
(279, 359, 21, 'Kabupaten', 'Pidie Jaya', '24186', NULL, NULL),
(280, 384, 21, 'Kota', 'Sabang', '23512', NULL, NULL),
(281, 414, 21, 'Kabupaten', 'Simeulue', '23891', NULL, NULL),
(282, 429, 21, 'Kota', 'Subulussalam', '24882', NULL, NULL),
(283, 68, 22, 'Kabupaten', 'Bima', '84171', NULL, NULL),
(284, 69, 22, 'Kota', 'Bima', '84139', NULL, NULL),
(285, 118, 22, 'Kabupaten', 'Dompu', '84217', NULL, NULL),
(286, 238, 22, 'Kabupaten', 'Lombok Barat', '83311', NULL, NULL),
(287, 239, 22, 'Kabupaten', 'Lombok Tengah', '83511', NULL, NULL),
(288, 240, 22, 'Kabupaten', 'Lombok Timur', '83612', NULL, NULL),
(289, 241, 22, 'Kabupaten', 'Lombok Utara', '83711', NULL, NULL),
(290, 276, 22, 'Kota', 'Mataram', '83131', NULL, NULL),
(291, 438, 22, 'Kabupaten', 'Sumbawa', '84315', NULL, NULL),
(292, 439, 22, 'Kabupaten', 'Sumbawa Barat', '84419', NULL, NULL),
(293, 13, 23, 'Kabupaten', 'Alor', '85811', NULL, NULL),
(294, 58, 23, 'Kabupaten', 'Belu', '85711', NULL, NULL),
(295, 122, 23, 'Kabupaten', 'Ende', '86351', NULL, NULL),
(296, 125, 23, 'Kabupaten', 'Flores Timur', '86213', NULL, NULL),
(297, 212, 23, 'Kabupaten', 'Kupang', '85362', NULL, NULL),
(298, 213, 23, 'Kota', 'Kupang', '85119', NULL, NULL),
(299, 234, 23, 'Kabupaten', 'Lembata', '86611', NULL, NULL),
(300, 269, 23, 'Kabupaten', 'Manggarai', '86551', NULL, NULL),
(301, 270, 23, 'Kabupaten', 'Manggarai Barat', '86711', NULL, NULL),
(302, 271, 23, 'Kabupaten', 'Manggarai Timur', '86811', NULL, NULL),
(303, 301, 23, 'Kabupaten', 'Nagekeo', '86911', NULL, NULL),
(304, 304, 23, 'Kabupaten', 'Ngada', '86413', NULL, NULL),
(305, 383, 23, 'Kabupaten', 'Rote Ndao', '85982', NULL, NULL),
(306, 385, 23, 'Kabupaten', 'Sabu Raijua', '85391', NULL, NULL),
(307, 412, 23, 'Kabupaten', 'Sikka', '86121', NULL, NULL),
(308, 434, 23, 'Kabupaten', 'Sumba Barat', '87219', NULL, NULL),
(309, 435, 23, 'Kabupaten', 'Sumba Barat Daya', '87453', NULL, NULL),
(310, 436, 23, 'Kabupaten', 'Sumba Tengah', '87358', NULL, NULL),
(311, 437, 23, 'Kabupaten', 'Sumba Timur', '87112', NULL, NULL),
(312, 479, 23, 'Kabupaten', 'Timor Tengah Selatan', '85562', NULL, NULL),
(313, 480, 23, 'Kabupaten', 'Timor Tengah Utara', '85612', NULL, NULL),
(314, 16, 24, 'Kabupaten', 'Asmat', '99777', NULL, NULL),
(315, 67, 24, 'Kabupaten', 'Biak Numfor', '98119', NULL, NULL),
(316, 90, 24, 'Kabupaten', 'Boven Digoel', '99662', NULL, NULL),
(317, 111, 24, 'Kabupaten', 'Deiyai (Deliyai)', '98784', NULL, NULL),
(318, 117, 24, 'Kabupaten', 'Dogiyai', '98866', NULL, NULL),
(319, 150, 24, 'Kabupaten', 'Intan Jaya', '98771', NULL, NULL),
(320, 157, 24, 'Kabupaten', 'Jayapura', '99352', NULL, NULL),
(321, 158, 24, 'Kota', 'Jayapura', '99114', NULL, NULL),
(322, 159, 24, 'Kabupaten', 'Jayawijaya', '99511', NULL, NULL),
(323, 180, 24, 'Kabupaten', 'Keerom', '99461', NULL, NULL),
(324, 193, 24, 'Kabupaten', 'Kepulauan Yapen (Yapen Waropen)', '98211', NULL, NULL),
(325, 231, 24, 'Kabupaten', 'Lanny Jaya', '99531', NULL, NULL),
(326, 263, 24, 'Kabupaten', 'Mamberamo Raya', '99381', NULL, NULL),
(327, 264, 24, 'Kabupaten', 'Mamberamo Tengah', '99553', NULL, NULL),
(328, 274, 24, 'Kabupaten', 'Mappi', '99853', NULL, NULL),
(329, 281, 24, 'Kabupaten', 'Merauke', '99613', NULL, NULL),
(330, 284, 24, 'Kabupaten', 'Mimika', '99962', NULL, NULL),
(331, 299, 24, 'Kabupaten', 'Nabire', '98816', NULL, NULL),
(332, 303, 24, 'Kabupaten', 'Nduga', '99541', NULL, NULL),
(333, 335, 24, 'Kabupaten', 'Paniai', '98765', NULL, NULL),
(334, 347, 24, 'Kabupaten', 'Pegunungan Bintang', '99573', NULL, NULL),
(335, 373, 24, 'Kabupaten', 'Puncak', '98981', NULL, NULL),
(336, 374, 24, 'Kabupaten', 'Puncak Jaya', '98979', NULL, NULL),
(337, 392, 24, 'Kabupaten', 'Sarmi', '99373', NULL, NULL),
(338, 443, 24, 'Kabupaten', 'Supiori', '98164', NULL, NULL),
(339, 484, 24, 'Kabupaten', 'Tolikara', '99411', NULL, NULL),
(340, 495, 24, 'Kabupaten', 'Waropen', '98269', NULL, NULL),
(341, 499, 24, 'Kabupaten', 'Yahukimo', '99041', NULL, NULL),
(342, 500, 24, 'Kabupaten', 'Yalimo', '99481', NULL, NULL),
(343, 124, 25, 'Kabupaten', 'Fakfak', '98651', NULL, NULL),
(344, 165, 25, 'Kabupaten', 'Kaimana', '98671', NULL, NULL),
(345, 272, 25, 'Kabupaten', 'Manokwari', '98311', NULL, NULL),
(346, 273, 25, 'Kabupaten', 'Manokwari Selatan', '98355', NULL, NULL),
(347, 277, 25, 'Kabupaten', 'Maybrat', '98051', NULL, NULL),
(348, 346, 25, 'Kabupaten', 'Pegunungan Arfak', '98354', NULL, NULL),
(349, 378, 25, 'Kabupaten', 'Raja Ampat', '98489', NULL, NULL),
(350, 424, 25, 'Kabupaten', 'Sorong', '98431', NULL, NULL),
(351, 425, 25, 'Kota', 'Sorong', '98411', NULL, NULL),
(352, 426, 25, 'Kabupaten', 'Sorong Selatan', '98454', NULL, NULL),
(353, 449, 25, 'Kabupaten', 'Tambrauw', '98475', NULL, NULL),
(354, 474, 25, 'Kabupaten', 'Teluk Bintuni', '98551', NULL, NULL),
(355, 475, 25, 'Kabupaten', 'Teluk Wondama', '98591', NULL, NULL),
(356, 60, 26, 'Kabupaten', 'Bengkalis', '28719', NULL, NULL),
(357, 120, 26, 'Kota', 'Dumai', '28811', NULL, NULL),
(358, 147, 26, 'Kabupaten', 'Indragiri Hilir', '29212', NULL, NULL),
(359, 148, 26, 'Kabupaten', 'Indragiri Hulu', '29319', NULL, NULL),
(360, 166, 26, 'Kabupaten', 'Kampar', '28411', NULL, NULL),
(361, 187, 26, 'Kabupaten', 'Kepulauan Meranti', '28791', NULL, NULL),
(362, 207, 26, 'Kabupaten', 'Kuantan Singingi', '29519', NULL, NULL),
(363, 350, 26, 'Kota', 'Pekanbaru', '28112', NULL, NULL),
(364, 351, 26, 'Kabupaten', 'Pelalawan', '28311', NULL, NULL),
(365, 381, 26, 'Kabupaten', 'Rokan Hilir', '28992', NULL, NULL),
(366, 382, 26, 'Kabupaten', 'Rokan Hulu', '28511', NULL, NULL),
(367, 406, 26, 'Kabupaten', 'Siak', '28623', NULL, NULL),
(368, 253, 27, 'Kabupaten', 'Majene', '91411', NULL, NULL),
(369, 262, 27, 'Kabupaten', 'Mamasa', '91362', NULL, NULL),
(370, 265, 27, 'Kabupaten', 'Mamuju', '91519', NULL, NULL),
(371, 266, 27, 'Kabupaten', 'Mamuju Utara', '91571', NULL, NULL),
(372, 362, 27, 'Kabupaten', 'Polewali Mandar', '91311', NULL, NULL),
(373, 38, 28, 'Kabupaten', 'Bantaeng', '92411', NULL, NULL),
(374, 47, 28, 'Kabupaten', 'Barru', '90719', NULL, NULL),
(375, 87, 28, 'Kabupaten', 'Bone', '92713', NULL, NULL),
(376, 95, 28, 'Kabupaten', 'Bulukumba', '92511', NULL, NULL),
(377, 123, 28, 'Kabupaten', 'Enrekang', '91719', NULL, NULL),
(378, 132, 28, 'Kabupaten', 'Gowa', '92111', NULL, NULL),
(379, 162, 28, 'Kabupaten', 'Jeneponto', '92319', NULL, NULL),
(380, 244, 28, 'Kabupaten', 'Luwu', '91994', NULL, NULL),
(381, 245, 28, 'Kabupaten', 'Luwu Timur', '92981', NULL, NULL),
(382, 246, 28, 'Kabupaten', 'Luwu Utara', '92911', NULL, NULL),
(383, 254, 28, 'Kota', 'Makassar', '90111', NULL, NULL),
(384, 275, 28, 'Kabupaten', 'Maros', '90511', NULL, NULL),
(385, 328, 28, 'Kota', 'Palopo', '91911', NULL, NULL),
(386, 333, 28, 'Kabupaten', 'Pangkajene Kepulauan', '90611', NULL, NULL),
(387, 336, 28, 'Kota', 'Parepare', '91123', NULL, NULL),
(388, 360, 28, 'Kabupaten', 'Pinrang', '91251', NULL, NULL),
(389, 396, 28, 'Kabupaten', 'Selayar (Kepulauan Selayar)', '92812', NULL, NULL),
(390, 408, 28, 'Kabupaten', 'Sidenreng Rappang/Rapang', '91613', NULL, NULL),
(391, 416, 28, 'Kabupaten', 'Sinjai', '92615', NULL, NULL),
(392, 423, 28, 'Kabupaten', 'Soppeng', '90812', NULL, NULL),
(393, 448, 28, 'Kabupaten', 'Takalar', '92212', NULL, NULL),
(394, 451, 28, 'Kabupaten', 'Tana Toraja', '91819', NULL, NULL),
(395, 486, 28, 'Kabupaten', 'Toraja Utara', '91831', NULL, NULL),
(396, 493, 28, 'Kabupaten', 'Wajo', '90911', NULL, NULL),
(397, 25, 29, 'Kabupaten', 'Banggai', '94711', NULL, NULL),
(398, 26, 29, 'Kabupaten', 'Banggai Kepulauan', '94881', NULL, NULL),
(399, 98, 29, 'Kabupaten', 'Buol', '94564', NULL, NULL),
(400, 119, 29, 'Kabupaten', 'Donggala', '94341', NULL, NULL),
(401, 291, 29, 'Kabupaten', 'Morowali', '94911', NULL, NULL),
(402, 329, 29, 'Kota', 'Palu', '94111', NULL, NULL),
(403, 338, 29, 'Kabupaten', 'Parigi Moutong', '94411', NULL, NULL),
(404, 366, 29, 'Kabupaten', 'Poso', '94615', NULL, NULL),
(405, 410, 29, 'Kabupaten', 'Sigi', '94364', NULL, NULL),
(406, 482, 29, 'Kabupaten', 'Tojo Una-Una', '94683', NULL, NULL),
(407, 483, 29, 'Kabupaten', 'Toli-Toli', '94542', NULL, NULL),
(408, 53, 30, 'Kota', 'Bau-Bau', '93719', NULL, NULL),
(409, 85, 30, 'Kabupaten', 'Bombana', '93771', NULL, NULL),
(410, 101, 30, 'Kabupaten', 'Buton', '93754', NULL, NULL),
(411, 102, 30, 'Kabupaten', 'Buton Utara', '93745', NULL, NULL),
(412, 182, 30, 'Kota', 'Kendari', '93126', NULL, NULL),
(413, 198, 30, 'Kabupaten', 'Kolaka', '93511', NULL, NULL),
(414, 199, 30, 'Kabupaten', 'Kolaka Utara', '93911', NULL, NULL),
(415, 200, 30, 'Kabupaten', 'Konawe', '93411', NULL, NULL),
(416, 201, 30, 'Kabupaten', 'Konawe Selatan', '93811', NULL, NULL),
(417, 202, 30, 'Kabupaten', 'Konawe Utara', '93311', NULL, NULL),
(418, 295, 30, 'Kabupaten', 'Muna', '93611', NULL, NULL),
(419, 494, 30, 'Kabupaten', 'Wakatobi', '93791', NULL, NULL),
(420, 73, 31, 'Kota', 'Bitung', '95512', NULL, NULL),
(421, 81, 31, 'Kabupaten', 'Bolaang Mongondow (Bolmong)', '95755', NULL, NULL),
(422, 82, 31, 'Kabupaten', 'Bolaang Mongondow Selatan', '95774', NULL, NULL),
(423, 83, 31, 'Kabupaten', 'Bolaang Mongondow Timur', '95783', NULL, NULL),
(424, 84, 31, 'Kabupaten', 'Bolaang Mongondow Utara', '95765', NULL, NULL),
(425, 188, 31, 'Kabupaten', 'Kepulauan Sangihe', '95819', NULL, NULL),
(426, 190, 31, 'Kabupaten', 'Kepulauan Siau Tagulandang Biaro (Sitaro)', '95862', NULL, NULL),
(427, 192, 31, 'Kabupaten', 'Kepulauan Talaud', '95885', NULL, NULL),
(428, 204, 31, 'Kota', 'Kotamobagu', '95711', NULL, NULL),
(429, 267, 31, 'Kota', 'Manado', '95247', NULL, NULL),
(430, 285, 31, 'Kabupaten', 'Minahasa', '95614', NULL, NULL),
(431, 286, 31, 'Kabupaten', 'Minahasa Selatan', '95914', NULL, NULL),
(432, 287, 31, 'Kabupaten', 'Minahasa Tenggara', '95995', NULL, NULL),
(433, 288, 31, 'Kabupaten', 'Minahasa Utara', '95316', NULL, NULL),
(434, 485, 31, 'Kota', 'Tomohon', '95416', NULL, NULL),
(435, 12, 32, 'Kabupaten', 'Agam', '26411', NULL, NULL),
(436, 93, 32, 'Kota', 'Bukittinggi', '26115', NULL, NULL),
(437, 116, 32, 'Kabupaten', 'Dharmasraya', '27612', NULL, NULL),
(438, 186, 32, 'Kabupaten', 'Kepulauan Mentawai', '25771', NULL, NULL),
(439, 236, 32, 'Kabupaten', 'Lima Puluh Koto/Kota', '26671', NULL, NULL),
(440, 318, 32, 'Kota', 'Padang', '25112', NULL, NULL),
(441, 321, 32, 'Kota', 'Padang Panjang', '27122', NULL, NULL),
(442, 322, 32, 'Kabupaten', 'Padang Pariaman', '25583', NULL, NULL),
(443, 337, 32, 'Kota', 'Pariaman', '25511', NULL, NULL),
(444, 339, 32, 'Kabupaten', 'Pasaman', '26318', NULL, NULL),
(445, 340, 32, 'Kabupaten', 'Pasaman Barat', '26511', NULL, NULL),
(446, 345, 32, 'Kota', 'Payakumbuh', '26213', NULL, NULL),
(447, 357, 32, 'Kabupaten', 'Pesisir Selatan', '25611', NULL, NULL),
(448, 394, 32, 'Kota', 'Sawah Lunto', '27416', NULL, NULL),
(449, 411, 32, 'Kabupaten', 'Sijunjung (Sawah Lunto Sijunjung)', '27511', NULL, NULL),
(450, 420, 32, 'Kabupaten', 'Solok', '27365', NULL, NULL),
(451, 421, 32, 'Kota', 'Solok', '27315', NULL, NULL),
(452, 422, 32, 'Kabupaten', 'Solok Selatan', '27779', NULL, NULL),
(453, 453, 32, 'Kabupaten', 'Tanah Datar', '27211', NULL, NULL),
(454, 40, 33, 'Kabupaten', 'Banyuasin', '30911', NULL, NULL),
(455, 121, 33, 'Kabupaten', 'Empat Lawang', '31811', NULL, NULL),
(456, 220, 33, 'Kabupaten', 'Lahat', '31419', NULL, NULL),
(457, 242, 33, 'Kota', 'Lubuk Linggau', '31614', NULL, NULL),
(458, 292, 33, 'Kabupaten', 'Muara Enim', '31315', NULL, NULL),
(459, 297, 33, 'Kabupaten', 'Musi Banyuasin', '30719', NULL, NULL),
(460, 298, 33, 'Kabupaten', 'Musi Rawas', '31661', NULL, NULL),
(461, 312, 33, 'Kabupaten', 'Ogan Ilir', '30811', NULL, NULL),
(462, 313, 33, 'Kabupaten', 'Ogan Komering Ilir', '30618', NULL, NULL),
(463, 314, 33, 'Kabupaten', 'Ogan Komering Ulu', '32112', NULL, NULL),
(464, 315, 33, 'Kabupaten', 'Ogan Komering Ulu Selatan', '32211', NULL, NULL),
(465, 316, 33, 'Kabupaten', 'Ogan Komering Ulu Timur', '32312', NULL, NULL),
(466, 324, 33, 'Kota', 'Pagar Alam', '31512', NULL, NULL),
(467, 327, 33, 'Kota', 'Palembang', '30111', NULL, NULL),
(468, 367, 33, 'Kota', 'Prabumulih', '31121', NULL, NULL),
(469, 15, 34, 'Kabupaten', 'Asahan', '21214', NULL, NULL),
(470, 52, 34, 'Kabupaten', 'Batu Bara', '21655', NULL, NULL),
(471, 70, 34, 'Kota', 'Binjai', '20712', NULL, NULL),
(472, 110, 34, 'Kabupaten', 'Dairi', '22211', NULL, NULL),
(473, 112, 34, 'Kabupaten', 'Deli Serdang', '20511', NULL, NULL),
(474, 137, 34, 'Kota', 'Gunungsitoli', '22813', NULL, NULL),
(475, 146, 34, 'Kabupaten', 'Humbang Hasundutan', '22457', NULL, NULL),
(476, 173, 34, 'Kabupaten', 'Karo', '22119', NULL, NULL),
(477, 217, 34, 'Kabupaten', 'Labuhan Batu', '21412', NULL, NULL),
(478, 218, 34, 'Kabupaten', 'Labuhan Batu Selatan', '21511', NULL, NULL),
(479, 219, 34, 'Kabupaten', 'Labuhan Batu Utara', '21711', NULL, NULL),
(480, 229, 34, 'Kabupaten', 'Langkat', '20811', NULL, NULL),
(481, 268, 34, 'Kabupaten', 'Mandailing Natal', '22916', NULL, NULL),
(482, 278, 34, 'Kota', 'Medan', '20228', NULL, NULL),
(483, 307, 34, 'Kabupaten', 'Nias', '22876', NULL, NULL),
(484, 308, 34, 'Kabupaten', 'Nias Barat', '22895', NULL, NULL),
(485, 309, 34, 'Kabupaten', 'Nias Selatan', '22865', NULL, NULL),
(486, 310, 34, 'Kabupaten', 'Nias Utara', '22856', NULL, NULL),
(487, 319, 34, 'Kabupaten', 'Padang Lawas', '22763', NULL, NULL),
(488, 320, 34, 'Kabupaten', 'Padang Lawas Utara', '22753', NULL, NULL),
(489, 323, 34, 'Kota', 'Padang Sidempuan', '22727', NULL, NULL),
(490, 325, 34, 'Kabupaten', 'Pakpak Bharat', '22272', NULL, NULL),
(491, 353, 34, 'Kota', 'Pematang Siantar', '21126', NULL, NULL),
(492, 389, 34, 'Kabupaten', 'Samosir', '22392', NULL, NULL),
(493, 404, 34, 'Kabupaten', 'Serdang Bedagai', '20915', NULL, NULL),
(494, 407, 34, 'Kota', 'Sibolga', '22522', NULL, NULL),
(495, 413, 34, 'Kabupaten', 'Simalungun', '21162', NULL, NULL),
(496, 459, 34, 'Kota', 'Tanjung Balai', '21321', NULL, NULL),
(497, 463, 34, 'Kabupaten', 'Tapanuli Selatan', '22742', NULL, NULL),
(498, 464, 34, 'Kabupaten', 'Tapanuli Tengah', '22611', NULL, NULL),
(499, 465, 34, 'Kabupaten', 'Tapanuli Utara', '22414', NULL, NULL),
(500, 470, 34, 'Kota', 'Tebing Tinggi', '20632', NULL, NULL),
(501, 481, 34, 'Kabupaten', 'Toba Samosir', '22316', NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `cs_commision`
--

CREATE TABLE `cs_commision` (
  `amount` double NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `leaders_commision`
--

CREATE TABLE `leaders_commision` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `amount` double NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `maintenance_commision`
--

CREATE TABLE `maintenance_commision` (
  `amount` double NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `mediator_commision`
--

CREATE TABLE `mediator_commision` (
  `amount` double NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `midtrans_settings`
--

CREATE TABLE `midtrans_settings` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `migrations`
--

CREATE TABLE `migrations` (
  `id` int(10) UNSIGNED NOT NULL,
  `migration` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `batch` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `migrations`
--

INSERT INTO `migrations` (`id`, `migration`, `batch`) VALUES
(1, '2019_11_07_060809_create_users_table', 1),
(2, '2019_11_07_060932_create_categories_table', 1),
(3, '2019_11_07_060955_create_products_table', 1),
(4, '2019_11_07_061011_create_transctions_table', 1),
(5, '2019_11_07_061755_create_product_discussions_table', 1),
(6, '2019_11_08_041606_create_midtrans_settings_table', 1),
(7, '2019_11_08_072217_create_transaction_details_table', 1),
(8, '2019_11_08_083301_create_transactions_shipping_table', 1),
(9, '2019_11_09_002420_add_column_role_to_users_table', 1),
(10, '2019_11_09_002545_add_column_courier_to_transaction_shippings_table', 1),
(11, '2019_11_09_015623_add_column_no_receipt_to_transactions_table', 1),
(12, '2020_03_03_152556_create_product_images_table', 1),
(13, '2020_03_03_152807_create_product_reviews_table', 1),
(14, '2020_03_04_093252_create_settings_table', 2),
(15, '2020_03_04_093515_create_user_bank_account_table', 2),
(16, '2020_03_04_093611_create_withdraw_affiliate_table', 2),
(17, '2020_03_04_140621_create_provinces_table', 3),
(18, '2020_03_04_140639_create_cities_table', 3),
(19, '2020_03_04_140655_create_subdistricts_table', 3),
(20, '2020_03_05_061838_add_token_to_product_images_table', 4),
(21, '2020_03_06_010600_add_service_to_transaction_shippings_table', 5),
(22, '2020_03_06_115118_add_column_affiliate_id_to_transaction_details_table', 6),
(23, '2020_03_06_115207_add_column_referral_to_users_table', 6),
(24, '2020_03_06_140751_add_column_commision_to_product_table', 7),
(25, '2020_03_06_141333_add_column_commision_to_transaction_details_table', 8),
(26, '2020_03_06_150715_create_affiliators_commision_table', 9),
(27, '2020_03_06_155939_add_trigger_kurangi_stock_product', 10),
(30, '2020_03_07_023307_create_maintenance_commision_table', 11),
(31, '2020_03_07_023326_create_provider_commision_table', 11),
(32, '2020_03_07_031049_add_is_share_commision_to_transactions', 12),
(33, '2020_03_08_232331_create_notifications_table', 13),
(34, '2020_03_09_062657_add_column_bank_to_users_table', 14),
(35, '2020_03_09_133655_add_parent_id_to_product_discussions_table', 15),
(36, '2020_03_10_054054_add_district_to_transaction_shippings_table', 16),
(37, '2020_03_10_054645_add_product_to_transaction_detail_table', 17),
(38, '2020_03_12_133315_add_status_to_products_table', 18),
(39, '2020_03_12_144638_add_status_to_categories_table', 19),
(40, '2020_03_12_144715_create_sliders_table', 19),
(41, '2020_03_13_230343_add_referer_host_to_transactions_table', 20),
(42, '2020_03_14_071333_create_withdraw_provider_maintenance_table', 21),
(43, '2020_03_14_124733_add_unique_to_transactions_table', 22),
(44, '2020_03_20_141813_add_commision_mediator_to_transaction_details_table', 23),
(45, '2020_03_21_025216_create_mediator_commision_table', 23),
(46, '2020_03_21_025241_create_cs_commision_table', 23),
(47, '2020_03_21_025254_create_leaders_commision_table', 23),
(48, '2020_03_21_025329_add_leader_id_to_users_table', 23),
(49, '2020_03_21_030035_add_mediator_commision_to_products_table', 24);

-- --------------------------------------------------------

--
-- Table structure for table `notifications`
--

CREATE TABLE `notifications` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `content` text COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_read` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `products`
--

CREATE TABLE `products` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `category_id` bigint(20) UNSIGNED NOT NULL,
  `status` varchar(40) COLLATE utf8mb4_unicode_ci DEFAULT 'draft',
  `product_ref` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `title` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `slug` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` text COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `image` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `video` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `weight` int(11) DEFAULT NULL,
  `long` int(11) DEFAULT NULL,
  `width` int(11) DEFAULT NULL,
  `height` int(11) DEFAULT NULL,
  `price` bigint(20) DEFAULT NULL,
  `stock` bigint(20) DEFAULT NULL,
  `view` bigint(20) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `commision_maintenance` double NOT NULL DEFAULT 0,
  `commision_affiliator` double NOT NULL DEFAULT 0,
  `commision_provider` double NOT NULL DEFAULT 0,
  `commision_mediator` double NOT NULL DEFAULT 0,
  `commision_leader` double NOT NULL DEFAULT 0,
  `commision_cs` double NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `products`
--

INSERT INTO `products` (`id`, `category_id`, `status`, `product_ref`, `title`, `slug`, `description`, `image`, `video`, `weight`, `long`, `width`, `height`, `price`, `stock`, `view`, `created_at`, `updated_at`, `commision_maintenance`, `commision_affiliator`, `commision_provider`, `commision_mediator`, `commision_leader`, `commision_cs`) VALUES
(1, 1, 'publish', '', 'Test Produk', 'test-produk', '<p>Test</p>', NULL, NULL, 10, 0, 0, NULL, 0, -1, 0, '2020-03-17 02:31:21', '2020-03-17 02:34:11', 0, 0, 0, 0, 0, 0),
(2, 1, 'draft', NULL, 'Untitled 1584438716', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, '2020-03-17 02:51:56', NULL, 0, 0, 0, 0, 0, 0),
(3, 1, 'publish', '30681592190517', 'Madu Magatri Asli', 'madu-magatri-asli', '<p>Madu Magatri Asli</p>', NULL, NULL, 400, 0, 0, NULL, 240000, 9908, 0, '2020-03-17 02:55:18', '2020-06-17 10:37:11', 20000, 20000, 40000, 5000, 0, 5000),
(4, 1, 'draft', NULL, 'Untitled 1584689647', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, '2020-03-20 00:34:07', NULL, 0, 0, 0, 0, 0, 0),
(5, 1, 'draft', NULL, 'Untitled 1585094925', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, '2020-03-25 00:08:45', NULL, 0, 0, 0, 0, 0, 0),
(6, 1, 'draft', NULL, 'Untitled 1585152778', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, '2020-03-25 16:12:58', NULL, 0, 0, 0, 0, 0, 0),
(7, 1, 'draft', NULL, 'Untitled 1585181696', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, '2020-03-26 00:14:56', NULL, 0, 0, 0, 0, 0, 0),
(8, 1, 'draft', NULL, 'Untitled 1587757883', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, '2020-04-24 19:51:23', NULL, 0, 0, 0, 0, 0, 0),
(9, 2, 'draft', '', 'Bulk Whatsapp Sender Pro', 'bulk-whatsapp-sender', '<h3 style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 22px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; color: rgb(34, 34, 34); font-weight: 700; line-height: 1.35; font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Fitur Support Kirim Pesan WhatsApp Massal<span class=\"ez-toc-section-end\" style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word;\"></span></h3><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Maksimalkan pengiriman pesan whatsapp massal anda dengan beberapa fitur penunjang yang memang sudah disediakan. Fitur ini sebelumnya sudah di riset oleh pihak developer, sehingga pastinya anda sangat membutuhkannya.</p><h4 style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 18px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; color: rgb(34, 34, 34); font-weight: 700; line-height: 1.35; font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\"><span class=\"ez-toc-section\" id=\"Fitur_Mencari_Database\" style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word;\"></span>Fitur Mencari Database<span class=\"ez-toc-section-end\" style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word;\"></span></h4><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Kendala terbesar dari mengirim pesan secara massal adalah stok database nomor whatsapp terbatas.Tapi dengan aplikasi ini anda bisa dipastikan tidak akan pernah kehabisan database nomor whatsapp. Anda bisa mencari dan mengumpulkan nomor database kapanpun anda mau dan berapa banyak jumlahnya.</p><ul style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\"><li style=\"margin: 0px 0px 10px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; list-style: none;\"><span style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; font-weight: 700;\">Mengambil (Scrape) Nomor di Google Maps, Facebook, Linkeld, Instagram, dll</span></li></ul><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Fitur ini memudahkan anda untuk mencari data bisnis beserta nomor whatsapp yang mereka lampirkan di google map. Saat ini hampir setiap usaha dipastikan memiliki google bisnis untuk menandai lokasi mereka di google maps.</p><ul style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\"><li style=\"margin: 0px 0px 10px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; list-style: none;\"><span style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; font-weight: 700;\">Generate Nomor WhatsaApp</span></li></ul><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Anda bisa melakukan generate nomor handphone berdasarkan prefix kota berapapun yang anda inginkan. Fitur ini membuat anda tidak akan pernah kehabisan database.</p><ul style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\"><li style=\"margin: 0px 0px 10px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; list-style: none;\"><span style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; font-weight: 700;\">Grab Kontak Group WhatsApp</span></li></ul><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Anda bisa mengambil dengan mudah semua kontak group whatsapp anda hanya dengan sekali klik.</p><ul style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\"><li style=\"margin: 0px 0px 10px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; list-style: none;\"><span style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; font-weight: 700;\">Grab Chat List WhatsApp</span></li></ul><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Fitur ini berfungsi untuk menarik semua nomor whatsapp yang berada pada chat list whatsapp anda</p><ul style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\"><li style=\"margin: 0px 0px 10px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; list-style: none;\"><span style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; font-weight: 700;\">Scrape group WhatApp dengan menggunakan kata kunci</span></li></ul><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Gunakan fitur ini untuk mencari group-group whatsapp berdasarkan kata kunci, sehingga target market anda jauh lebih spesifik.</p><ul style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\"><li style=\"margin: 0px 0px 10px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; list-style: none;\"><span style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; font-weight: 700;\">Bulk Join Group Hasil Scrape</span></li></ul><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Ketika sudah menemukan group yang anda cari berdasarkan kata kunci, maka gunakan fitur ini untuk join ke group-group tersebut dengan sekali klik. Setelah itu scrape semua nomor mereka dan kemudian keluar lagi, saat ini anda menjadi gudangnya database.</p><h3 style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 22px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; color: rgb(34, 34, 34); font-weight: 700; line-height: 1.35; font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\"><span class=\"ez-toc-section\" id=\"Fitur_WhatsApp_Anti_Blokir\" style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word;\"></span>Fitur WhatsApp Anti Blokir<span class=\"ez-toc-section-end\" style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word;\"></span></h3><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Seperti yang anda ketahui bahwa aplikasi whatsapp blast itu adalah aplikasi pihak ketiga. Sehingga sangat rentan nomor terblokir karena kirim pesan massal. Untungnya aplikasi ini tidak memodifikasi sama sekali produk dari whatsapp, aplikasi ini memanfaatkan&nbsp;<a href=\"https://web.whatsapp.com/\" style=\"background: 0px 0px rgb(255, 255, 255); margin: 0px; padding: 0px; vertical-align: baseline; color: rgb(235, 84, 36);\">whatsapp web.</a>&nbsp;Memang saat ini tidak ada aplikasi blast yang aman 100 persen dari banned whatsapp, tapi setidaknya WBS Pro ini punya 4 fitur filter yang dapat meminimalisir banned.</p><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\"><span style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; font-weight: 700;\">Random Delay Time</span></p><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Aplikasi ini akan mengirim pesan anda secara random dalam delay waktu tertentu, sehingga dapat meminimalisir banned whatsapp, pesan terlihat natural, bukan robot.</p><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\"><span style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; font-weight: 700;\">Random Akun Multi WhatsApp Pengirim</span></p><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Ada bisa mengirim pesan ke database anda dengan menggunakan banyak nomor sekaligus, sehingga akan semakin membingungkan pihak whatsapp memblokir nomor anda.</p><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\"><span style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; font-weight: 700;\">Fitur Akun Familiar</span></p><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Akun familiar akan membuat pesan anda terlihat original dan bukan menggunakan tools, karena nomor akan mengirim ke beberapa nomor yang memang sering berinteraksi dengan anda.</p><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\"><span style=\"margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: baseline; background: 0px 0px; overflow-wrap: break-word; font-weight: 700;\">Personalisasi Dinamis</span></p><p style=\"margin-right: 0px; margin-bottom: 25px; margin-left: 0px; padding: 0px; border: 0px; outline: 0px; font-size: 14px; vertical-align: baseline; background-image: initial; background-position: 0px 0px; background-size: initial; background-repeat: initial; background-attachment: initial; background-origin: initial; background-clip: initial; overflow-wrap: break-word; line-height: 1.8em; color: rgb(65, 65, 65); font-family: &quot;Open Sans&quot;, &quot;Helvetica Neue&quot;, Helvetica, Arial, sans-serif;\">Bahkan whatsapp official tidak bisa menyebut nama pelanggan yang dituju, namun fitur ini bisa melakukannya, sehingga anda bisa terhindar dari blokir langsung pengguna.</p>', NULL, NULL, 100, 10, 10, NULL, 500000, 1000, 0, '2020-04-26 18:44:15', '2020-04-26 18:51:21', 25000, 25000, 25000, 50000, 25000, 25000),
(10, 1, 'draft', '85451591422402', 'Untitled 1591422402', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, '2020-06-06 05:46:42', NULL, 0, 0, 0, 0, 0, 0),
(11, 1, 'draft', '10671592390187', 'Untitled 1592390187', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, '2020-06-17 10:36:27', NULL, 0, 0, 0, 0, 0, 0);

-- --------------------------------------------------------

--
-- Table structure for table `product_discussions`
--

CREATE TABLE `product_discussions` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `parent_id` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `product_id` bigint(20) UNSIGNED NOT NULL,
  `content` text COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `product_images`
--

CREATE TABLE `product_images` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `product_ref` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `image` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_thumbnail` tinyint(1) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `token` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `type` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `product_reviews`
--

CREATE TABLE `product_reviews` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `product_id` bigint(20) UNSIGNED NOT NULL,
  `star` int(11) NOT NULL DEFAULT 0,
  `content` text COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `provider_commision`
--

CREATE TABLE `provider_commision` (
  `amount` double NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `provinces`
--

CREATE TABLE `provinces` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `province_id` bigint(20) UNSIGNED NOT NULL,
  `province` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `settings`
--

CREATE TABLE `settings` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `value` text COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `settings`
--

INSERT INTO `settings` (`id`, `name`, `value`, `created_at`, `updated_at`) VALUES
(1, 'website_title', 'Magatri Herbal', NULL, NULL),
(2, 'website_top_headline', 'Selamat datang di Magatri Herbal  - Buka : Senin-Sabtu, 10.00-20.00 WIB', NULL, NULL),
(3, 'website_description', 'Magatri Herbal', NULL, NULL),
(4, 'website_search_placeholder', 'Mau belanja apa hari ini?', NULL, NULL),
(5, 'website_logo', '', NULL, NULL),
(6, 'website_shipping_courier', 'jne,jnt', NULL, NULL),
(7, 'midtrans_client_key', '', NULL, NULL),
(8, 'midtrans_server_key', '', NULL, NULL),
(9, 'can_withdraw', 'false', NULL, NULL),
(10, 'maintenance_mode', 'false', NULL, NULL),
(11, 'rajaongkir_account_type', 'api', NULL, NULL),
(12, 'rajaongkir_api_key', 'ab093838b7365c96fb5a6d8683a8b32d', NULL, NULL),
(13, 'sender_district', '1396', NULL, NULL),
(14, 'sender_summary', '{\"city\":\"103\",\"province\":\"2\"}', NULL, NULL),
(15, 'midtrans_client_key_dev', '', NULL, NULL),
(16, 'midtrans_server_key_dev', '', NULL, NULL),
(17, 'midtrans_mode', 'dev', NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `sliders`
--

CREATE TABLE `sliders` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `title` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `link` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `image` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_display` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `subdistricts`
--

CREATE TABLE `subdistricts` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `subdistrict_id` bigint(20) UNSIGNED NOT NULL,
  `city_id` bigint(20) UNSIGNED NOT NULL,
  `subdistrict_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `transactions`
--

CREATE TABLE `transactions` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `cash_on_delivery` tinyint(1) DEFAULT 0,
  `cash_on_delivery_markup` double DEFAULT 0,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `affiliate_id` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `leader_id` int(11) DEFAULT NULL,
  `snap_token` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `transaction_time` datetime DEFAULT NULL,
  `transaction_status` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `status_message` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `status_code` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `signature_key` text COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `settlement_time` datetime DEFAULT NULL,
  `payment_type` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `order_id` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `amount` bigint(20) DEFAULT NULL,
  `fraud_status` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `approval_code` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `description` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `va_numbers` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `payment_amounts` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `pdf_url` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `finish_redirect_url` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `expired_time` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `item_status` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT 'waiting_transfer',
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `no_receipt` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_share_commision` tinyint(1) NOT NULL DEFAULT 0,
  `referer_host` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `unique` varchar(5) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `transaction_details`
--

CREATE TABLE `transaction_details` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `transaction_id` bigint(20) UNSIGNED NOT NULL,
  `product_id` bigint(20) UNSIGNED NOT NULL,
  `price` bigint(20) DEFAULT NULL,
  `quantity` bigint(20) DEFAULT NULL,
  `product` text COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `delivery_status` enum('pending','process','courier') COLLATE utf8mb4_unicode_ci DEFAULT 'pending',
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `affiliate_id` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `total_commision_maintenance` double NOT NULL DEFAULT 0,
  `total_commision_affiliator` double NOT NULL DEFAULT 0,
  `total_commision_provider` double NOT NULL DEFAULT 0,
  `total_commision_mediator` double NOT NULL DEFAULT 0 COMMENT 'Penghasilan Mediator',
  `total_commision_leader` double NOT NULL DEFAULT 0 COMMENT 'Penghasilan Team Leader',
  `total_commision_cs` double NOT NULL DEFAULT 0 COMMENT 'Penghasilan Cust. Service'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Triggers `transaction_details`
--
DELIMITER $$
CREATE TRIGGER `kurangi_stock_product` AFTER INSERT ON `transaction_details` FOR EACH ROW BEGIN UPDATE products SET products.stock = products.stock - New.quantity WHERE products.id = New.product_id; END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `transaction_shippings`
--

CREATE TABLE `transaction_shippings` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `transaction_id` bigint(20) UNSIGNED NOT NULL,
  `first_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `last_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `phone` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `city_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `district_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `district_id` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `city_id` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `province` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `province_id` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `postal_code` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `address` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `cost` bigint(20) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `courier` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `courier_desc` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `service` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `courier_json` text COLLATE utf8mb4_unicode_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `transfer_confirmations`
--

CREATE TABLE `transfer_confirmations` (
  `id` int(11) NOT NULL,
  `order_id` bigint(20) DEFAULT NULL,
  `amount` bigint(20) DEFAULT NULL,
  `bank_name` varchar(150) DEFAULT NULL,
  `bank_number` varchar(150) DEFAULT NULL,
  `account_name` varchar(150) DEFAULT NULL,
  `status` tinyint(1) DEFAULT 0,
  `file` varchar(150) DEFAULT NULL,
  `created_at` datetime DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `leader_id` bigint(20) UNSIGNED NOT NULL DEFAULT 0,
  `affiliator_id` bigint(20) DEFAULT 0,
  `first_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `last_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `email` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `phone` varchar(15) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `account_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `account_number` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `bank_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `token` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `token_expired` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `role` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `referral` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT '0'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `leader_id`, `affiliator_id`, `first_name`, `last_name`, `email`, `phone`, `account_name`, `account_number`, `bank_name`, `password`, `token`, `token_expired`, `created_at`, `updated_at`, `role`, `referral`) VALUES
(4, 0, 0, 'Asep', 'Yayat', 'admin@admin.com', NULL, NULL, NULL, NULL, '$2y$10$RtP.DQhsUo.zryXZxmg53ub1HE1cVkviFa8q5TxMwyc4fKPTE209S', '$2y$10$v55e6yVgvJpXv3KEfjNUJeC9SdVG1XGxDPTemMNSBVzgLXOwyjKRm', '956623535400', NULL, NULL, 'admin', '0');

-- --------------------------------------------------------

--
-- Table structure for table `user_bank_accounts`
--

CREATE TABLE `user_bank_accounts` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `account_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `account_number` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `bank_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_primary` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `withdraw_affiliates`
--

CREATE TABLE `withdraw_affiliates` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `user_id` bigint(20) UNSIGNED NOT NULL,
  `bank_id` bigint(20) UNSIGNED NOT NULL,
  `amount` double NOT NULL DEFAULT 0,
  `status` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'pending',
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Table structure for table `withdraw_provider_maintenance`
--

CREATE TABLE `withdraw_provider_maintenance` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `amount` double NOT NULL DEFAULT 0,
  `type` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `affiliators_commision`
--
ALTER TABLE `affiliators_commision`
  ADD PRIMARY KEY (`id`),
  ADD KEY `affiliators_commision_user_id_foreign` (`user_id`);

--
-- Indexes for table `categories`
--
ALTER TABLE `categories`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `cities`
--
ALTER TABLE `cities`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `leaders_commision`
--
ALTER TABLE `leaders_commision`
  ADD PRIMARY KEY (`id`),
  ADD KEY `leaders_commision_user_id_foreign` (`user_id`);

--
-- Indexes for table `midtrans_settings`
--
ALTER TABLE `midtrans_settings`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `migrations`
--
ALTER TABLE `migrations`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `notifications`
--
ALTER TABLE `notifications`
  ADD PRIMARY KEY (`id`),
  ADD KEY `notifications_user_id_foreign` (`user_id`);

--
-- Indexes for table `products`
--
ALTER TABLE `products`
  ADD PRIMARY KEY (`id`),
  ADD KEY `products_category_id_foreign` (`category_id`);

--
-- Indexes for table `product_discussions`
--
ALTER TABLE `product_discussions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `product_discussions_user_id_foreign` (`user_id`),
  ADD KEY `product_discussions_product_id_foreign` (`product_id`);

--
-- Indexes for table `product_images`
--
ALTER TABLE `product_images`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `product_reviews`
--
ALTER TABLE `product_reviews`
  ADD PRIMARY KEY (`id`),
  ADD KEY `product_reviews_user_id_foreign` (`user_id`),
  ADD KEY `product_reviews_product_id_foreign` (`product_id`);

--
-- Indexes for table `provinces`
--
ALTER TABLE `provinces`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `settings`
--
ALTER TABLE `settings`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `sliders`
--
ALTER TABLE `sliders`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `subdistricts`
--
ALTER TABLE `subdistricts`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `transactions`
--
ALTER TABLE `transactions`
  ADD PRIMARY KEY (`id`),
  ADD KEY `transactions_user_id_foreign` (`user_id`);

--
-- Indexes for table `transaction_details`
--
ALTER TABLE `transaction_details`
  ADD PRIMARY KEY (`id`),
  ADD KEY `transaction_details_product_id_foreign` (`product_id`),
  ADD KEY `transaction_details_transaction_id_foreign` (`transaction_id`);

--
-- Indexes for table `transaction_shippings`
--
ALTER TABLE `transaction_shippings`
  ADD PRIMARY KEY (`id`),
  ADD KEY `transaction_shippings_transaction_id_foreign` (`transaction_id`);

--
-- Indexes for table `transfer_confirmations`
--
ALTER TABLE `transfer_confirmations`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `user_bank_accounts`
--
ALTER TABLE `user_bank_accounts`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_bank_accounts_user_id_foreign` (`user_id`);

--
-- Indexes for table `withdraw_affiliates`
--
ALTER TABLE `withdraw_affiliates`
  ADD PRIMARY KEY (`id`),
  ADD KEY `withdraw_affiliates_user_id_foreign` (`user_id`);

--
-- Indexes for table `withdraw_provider_maintenance`
--
ALTER TABLE `withdraw_provider_maintenance`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `affiliators_commision`
--
ALTER TABLE `affiliators_commision`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `categories`
--
ALTER TABLE `categories`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `cities`
--
ALTER TABLE `cities`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=502;

--
-- AUTO_INCREMENT for table `leaders_commision`
--
ALTER TABLE `leaders_commision`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `midtrans_settings`
--
ALTER TABLE `midtrans_settings`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `migrations`
--
ALTER TABLE `migrations`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=50;

--
-- AUTO_INCREMENT for table `notifications`
--
ALTER TABLE `notifications`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `products`
--
ALTER TABLE `products`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- AUTO_INCREMENT for table `product_discussions`
--
ALTER TABLE `product_discussions`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `product_images`
--
ALTER TABLE `product_images`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `product_reviews`
--
ALTER TABLE `product_reviews`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `provinces`
--
ALTER TABLE `provinces`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `settings`
--
ALTER TABLE `settings`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- AUTO_INCREMENT for table `sliders`
--
ALTER TABLE `sliders`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `subdistricts`
--
ALTER TABLE `subdistricts`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `transactions`
--
ALTER TABLE `transactions`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `transaction_details`
--
ALTER TABLE `transaction_details`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `transaction_shippings`
--
ALTER TABLE `transaction_shippings`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `transfer_confirmations`
--
ALTER TABLE `transfer_confirmations`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=210;

--
-- AUTO_INCREMENT for table `user_bank_accounts`
--
ALTER TABLE `user_bank_accounts`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `withdraw_affiliates`
--
ALTER TABLE `withdraw_affiliates`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `withdraw_provider_maintenance`
--
ALTER TABLE `withdraw_provider_maintenance`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `affiliators_commision`
--
ALTER TABLE `affiliators_commision`
  ADD CONSTRAINT `affiliators_commision_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `leaders_commision`
--
ALTER TABLE `leaders_commision`
  ADD CONSTRAINT `leaders_commision_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `notifications`
--
ALTER TABLE `notifications`
  ADD CONSTRAINT `notifications_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `products`
--
ALTER TABLE `products`
  ADD CONSTRAINT `products_category_id_foreign` FOREIGN KEY (`category_id`) REFERENCES `categories` (`id`);

--
-- Constraints for table `product_discussions`
--
ALTER TABLE `product_discussions`
  ADD CONSTRAINT `product_discussions_product_id_foreign` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`),
  ADD CONSTRAINT `product_discussions_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `product_reviews`
--
ALTER TABLE `product_reviews`
  ADD CONSTRAINT `product_reviews_product_id_foreign` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`),
  ADD CONSTRAINT `product_reviews_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

--
-- Constraints for table `transaction_details`
--
ALTER TABLE `transaction_details`
  ADD CONSTRAINT `transaction_details_product_id_foreign` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`),
  ADD CONSTRAINT `transaction_details_transaction_id_foreign` FOREIGN KEY (`transaction_id`) REFERENCES `transactions` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
