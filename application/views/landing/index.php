
<!DOCTYPE html>
<html lang="en">

  <head>

    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="Template Mo">
    <link href="https://fonts.googleapis.com/css?family=Roboto:100,300,400,500,700,900" rel="stylesheet">

    <title><?=$setting_website_title;?></title>
<!--

ART FACTORY

https://templatemo.com/tm-537-art-factory

-->
    <!-- Additional CSS Files -->
    <link rel="stylesheet" type="text/css" href="<?=resource_url();?>landingpage/assets/css/bootstrap.min.css">
    <link rel="stylesheet" type="text/css" href="<?=resource_url();?>landingpage/assets/css/font-awesome.css">
    <link rel="stylesheet" type="text/css" href="<?=resource_url();?>landingpage/assets/css/templatemo-art-factory.css">
    <link rel="stylesheet" type="text/css" href="<?=resource_url();?>landingpage/assets/css/owl-carousel.css">

    </head>
    
    <body>
    
        <!-- ***** Preloader Start ***** -->
        <div id="preloader">
        <div class="jumper">
            <div></div>
            <div></div>
            <div></div>
        </div>
    </div>  
    <!-- ***** Preloader End ***** -->
    
    
    <!-- ***** Header Area Start ***** -->
    <header class="header-area header-sticky">
        <div class="container">
            <div class="row">
                <div class="col-12">
                    <nav class="main-nav">
                        <!-- ***** Logo Start ***** -->
                        <a href="#" class="logo"><?=$setting_website_title;?></a>
                        <!-- ***** Logo End ***** -->
                        <!-- ***** Menu Start ***** -->
                        <ul class="nav">
                            <?php if(!$this->data['is_login']):?>
                              <li class="scroll-to-section"><a href="<?=base_url('auth/login?redirect=' . current_url());?>">Masuk</a></li>
                              <li class="scroll-to-section"><a href="<?=base_url('auth/register?redirect=' . current_url());?>">Daftar</a></li>
                            <?php else:?>
                              <li class="scroll-to-section"><a href="<?=base_url('member/my_profile');?>">Profil</a></li>
                              <?php if($this->data['user']->role == 'affiliate'):?>
                                <li class="scroll-to-section"><a href="<?=base_url('member/my_earning');?>">Penghasilan</a></li>
                              <?php endif;?>
                              <li class="scroll-to-section"><a href="<?=base_url('auth/logout');?>">Keluar</a></li>
                            <?php endif;?>
                        </ul>
                        <a class='menu-trigger'>
                            <span>Menu</span>
                        </a>
                        <!-- ***** Menu End ***** -->
                    </nav>
                </div>
            </div>
        </div>
    </header>
    <!-- ***** Header Area End ***** -->
    <!-- ***** Welcome Area Start ***** -->
    <div class="welcome-area" id="welcome">

        <!-- ***** Header Text Start ***** -->
        <div class="header-text">
            <div class="container">
                <div class="row">
                    <div class="left-text col-lg-6 col-md-6 col-sm-12 col-xs-12" data-scroll-reveal="enter left move 30px over 0.6s after 0.4s">
                        <h1>Madu Asli Herbal <strong>untuk Anda</strong></h1>
                        <p>Adalah madu pahit dari madu murni yang diramu dengan bahan herbal pilihan yaitu Madu hitam hutan, garlic, dan gamat(tripang)  yang telah teruji memiliki berbagai khasiat. Sehingga bisa diandalkan untuk pengobatan berbagai macam penyakit, mulai dari penyakit ringan sampai penyakit berat.</p>
                        <a href="#about" class="main-button-slider">Beli Sekarang</a>
                    </div>
                    <div class="d-none d-sm-block col-lg-6 col-md-6 col-sm-12 col-xs-12" data-scroll-reveal="enter right move 30px over 0.6s after 0.4s">
                        <img src="<?=resource_url();?>landingpage/assets/images/madu.jpeg" class="rounded img-fluid d-block mx-auto" alt="First Vector Graphic">
                    </div>
                </div>
            </div>
        </div>
        <!-- ***** Header Text End ***** -->
    </div>
    <!-- ***** Welcome Area End ***** -->


    <!-- ***** Features Big Item Start ***** -->
    <section class="section" id="about">
        <div class="container">
            <div class="row">
                <div class="col-lg-7 col-md-12 col-sm-12" data-scroll-reveal="enter left move 30px over 0.6s after 0.4s">
                    <img src="<?=resource_url();?>landingpage/assets/images/herbal.jpg" class="rounded img-fluid d-block mx-auto" alt="App">
                </div>
                <div class="right-text col-lg-5 col-md-12 col-sm-12 mobile-top-fix">
                    <div class="left-heading">
                        <h5>LAYANAN BISA BAYAR DI TEMPAT</h5>
                    </div>
                    <div class="left-text">
                       <p><strong>Magatri.com</strong> merupakan website resmi dari Magatri indonesia yang menyediakan informasi dan solusi untuk masalah kesehatan dengan menggunakan salah satu metode pengobatan Tibbunnabawi (pengobatan cara Rosulullah. SAW). Salah satu metode pengobatan cara Rosulullah SAW adalah dengan memanfaatkan obat-obatan herbal alami. </p>
                       <p>Magatri menyediakan berbagai macam produk herbal yang berkwalitas, 100% alami, Halal, Aman dan tanpa efek samping sama sekali. Semua produk telah bersertifikat HALAL dari MUI (Majelis Ulama Indonesia).</p>
                       <a href="#about2" class="main-button-slider">Beli Sekarang</a>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-lg-12">
                    <div class="hr"></div>
                </div>
            </div>
        </div>
    </section>
    <!-- ***** Features Big Item End ***** -->


    <section id="about2">
        <div class="container">
            <div class="row">
                <div class="col-md-12 mx-auto">
                    <h3 class="text-center"><strong>MENGAPA HARUS DENGAN HERBAL</strong></h3>
                    <div class="mt-5">
                        <p>
                            Kalau berbicara mengenai obat sudah pasti ada obat kimia dan ada obat herbal. Obat kimia memang dikenal sangat ampuh mengobati penyakit yang kita rasakan. Tapi obat yang harus diminum sesuai anjuran dokter ini menyimpan efek samping jangka panjang yang berbahaya bagi tubuh. Kita pasti tidak mau sembuh dari suatu penyakit dan diserang penyakit lain akibat dari efek samping obat kimia.
                        </p>
                        <h4 class="text-center text-danger mt-5"><strong>BAHAYANYA OBAT KIMIA</strong></h4>
                        <ul class="mt-4">
                            <li>
                                <img src="<?=resource_url();?>landingpage/assets/images/check-mark.svg" alt="" width="50">
                                <div class="text">
                                    <span>
                                        <strong>Infeksi</strong>. Penggunaan antibiotik dalam jangka panjang atau tidak sesuai aturan bisa menimbulkan resisten hingga infeksi yang berbalik menyerang tubuh
                                    </span>
                                </div>
                            </li>
                            <div class="clearfix mb-2 mt-3"></div>
                            <li>
                                <img src="<?=resource_url();?>landingpage/assets/images/check-mark.svg" alt="" width="50">
                                <div class="text">
                                    <span>
                                        <strong>Komplikasi</strong>. Tujuannya mengobati salah satu organ, tetapi menjadi racun bagi organ yang lain.
                                    </span>
                                </div>
                            </li>
                            <div class="clearfix mb-2 mt-3"></div>
                            <li>
                                <img src="<?=resource_url();?>landingpage/assets/images/check-mark.svg" alt="" width="50">
                                <div class="text">
                                    <span>
                                        <strong>Kerusakan Jantung</strong>. Penggunaan obat penguat jantung dan obat anti hipertensi dan diuretik dapat menurunkan fungsi jantung di kemudian hari.
                                    </span>
                                </div>
                            </li>
                            <div class="clearfix mb-2 mt-3"></div>
                            <li>
                                <img src="<?=resource_url();?>landingpage/assets/images/check-mark.svg" alt="" width="50">
                                <div class="text">
                                    <span>
                                        <strong>Sistem Imun Berkurang</strong>. Obat adalah racun, perlahan tapi pasti sistem imun terus terganggu dan perlahan berkurang efektivitasnya dalam menangkal zat asing, karena banyaknya racun di dalam tubuh
                                    </span>
                                </div>
                            </li>
                            <div class="clearfix mb-2 mt-3"></div>
                            <li>
                                <img src="<?=resource_url();?>landingpage/assets/images/check-mark.svg" alt="" width="50">
                                <div class="text">
                                    <span>
                                        <strong>Sistem Imun Berkurang</strong>. Obat adalah racun, perlahan tapi pasti sistem imun terus terganggu dan perlahan berkurang efektivitasnya dalam menangkal zat asing, karena banyaknya racun di dalam tubuh.
                                    </span>
                                </div>
                            </li>
                        </ul>
                        <h4 class="text-center text-success mt-5"><strong>KELEBIHAN OBAT HERBAL</strong></h4>
                            <ul class="mt-4">
                                <li>
                                    <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="50">
                                    <div class="text">
                                        <span>
                                            <strong>Tanpa Efek Samping</strong>. Karena bersifat alami, tidak mengandung racun alias toksin, sehingga tidak menimbulkan efek samping
                                        </span>
                                    </div>
                                </li>
                                <div class="clearfix mb-2 mt-3"></div>
                                <li>
                                    <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="50">
                                    <div class="text">
                                        <span>
                                            <strong>Efektif</strong>. Sangat efektif untuk mengobati penyakit yang sulit disembuhkan secara medis
                                        </span>
                                    </div>
                                </li>
                                <div class="clearfix mb-2 mt-3"></div>
                                <li>
                                    <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="50">
                                    <div class="text">
                                        <span>
                                            <strong>Kuratif</strong>. Bukan menyembuhkan gejala penyakit, namun mengobati langsung ke sumber penyakit
                                        </span>
                                    </div>
                                </li>
                                <div class="clearfix mb-2 mt-3"></div>
                                <li>
                                    <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="50">
                                    <div class="text">
                                        <span>
                                            <strong>Multi Khasiat</strong>. Banyak menyimpan khasiat (mampu menyembuhkan banyak penyakit dalam sekali pengobatan )
                                        </span>
                                    </div>
                                </li>
                                <div class="clearfix mb-2 mt-3"></div>
                                <li>
                                    <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="50">
                                    <div class="text">
                                        <span>
                                            <strong>Bersifat Konstruktif</strong>. Walaupun reaksinya lambat, namun bersifat konstruktif (memperbaiki organ-organ tubuh yang terkena penyakit tanpa menimbulkan penyakit ke organ tubuh yang lain).
                                        </span>
                                    </div>
                                </li>
                                <div class="clearfix mb-2 mt-3"></div>
                            </ul>
                    </div>
                    <h3 class="text-center mt-3"><strong>PRODUK <strong>Magatri.com</strong></strong></h3>
                    <div class="row mt-5">
                        <div class="col-lg-7 col-md-12 col-sm-12" data-scroll-reveal="enter left move 30px over 0.6s after 0.4s">
                            <img src="<?=resource_url();?>landingpage/assets/images/madu.jpeg" class="rounded img-fluid d-block mx-auto" alt="App">
                        </div>
                        <div class="right-text col-lg-5 col-md-12 col-sm-12 mobile-top-fix">    
                            <div class="left-text">
                               <p>Adalah madu pahit dari madu murni yang diramu dengan bahan herbal pilihan yaitu Madu hitam hutan, garlic, dan gamat(tripang)  yang telah teruji memiliki berbagai khasiat. Sehingga bisa diandalkan untuk pengobatan berbagai macam penyakit, mulai dari penyakit ringan sampai penyakit berat.</p>
                                <ul class="mt-4">
                                    <li>
                                        <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25">
                                        <div class="text ml-0 pl-5">
                                            <span>
                                                Menormalkan gula darah (Diabetes)
                                            </span>
                                        </div>
                                    </li>
                                    <div class="clearfix"></div>
                                    <li>
                                        <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25">
                                        <div class="text ml-0 pl-5">
                                            <span>
                                                Mengatasi Maag Kronis
                                            </span>
                                        </div>
                                    </li>
                                    <div class="clearfix"></div>
                                    <li>
                                        <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25">
                                        <div class="text ml-0 pl-5">
                                            <span>
                                                Mengatasi Asma
                                            </span>
                                        </div>
                                    </li>
                                    <div class="clearfix"></div>
                                    <li>
                                        <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25">
                                        <div class="text ml-0 pl-5">
                                            <span>
                                                Mengatasi Darah Tinggi
                                            </span>
                                        </div>
                                    </li>
                                    <div class="clearfix"></div>
                                    <li>
                                        <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25">
                                        <div class="text ml-0 pl-5">
                                            <span>
                                                Mengatasi Asam Urat
                                            </span>
                                        </div>
                                    </li>
                                    <div class="clearfix"></div>
                                    <li>
                                        <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25">
                                        <div class="text ml-0 pl-5">
                                            <span>
                                                Mengatasi Radang
                                            </span>
                                        </div>
                                    </li>
                                    <div class="clearfix"></div>
                                    <li>
                                        <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25">
                                        <div class="text ml-0 pl-5">
                                            <span>
                                                Membuang Racun dari Dalam Tubuh (detoks)
                                            </span>
                                        </div>
                                    </li>
                                    <div class="clearfix"></div>
                                    <li>
                                        <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25">
                                        <div class="text ml-0 pl-5">
                                            <span>
                                                Meningkatkan Stamina Pria
                                            </span>
                                        </div>
                                    </li>
                                    <div class="clearfix"></div>
                                    <li>
                                        <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25">
                                        <div class="text ml-0 pl-5">
                                            <span>
                                                Mengatasi Ginjal
                                            </span>
                                        </div>
                                    </li>
                                    <div class="clearfix"></div>
                                    <li>
                                        <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25">
                                        <div class="text ml-0 pl-5">
                                            <span>
                                                Mengatasi tipes
                                            </span>
                                        </div>
                                    </li>
                                    <div class="clearfix"></div>
                                    <li>
                                        <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25">
                                        <div class="text ml-0 pl-5">
                                            <span>
                                                Mengatasi Jantung
                                            </span>
                                        </div>
                                    </li>
                                    <div class="clearfix"></div>
                                    <li>
                                        <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25">
                                        <div class="text ml-0 pl-5">
                                            <span>
                                                Dan masih banyak lagi
                                            </span>
                                        </div>
                                    </li>
                                </ul>
                            </div>
                            <div class="clearfix"></div>
                            <div class="mt-2">
                                <a href="#services" class="main-button-slider">Beli Sekarang</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- ***** Features Small Start ***** -->
    <section class="section" id="services">
        <div class="container">
            <div class="row">
                <div class="col-md-12">
                    <h3 class="text-center text-white mb-5"><strong>KEUNTUNGAN BELANJA DI WEBSITE <strong>Magatri.com</strong></strong></h3>
                </div>
                <div class="owl-carousel owl-theme">
                    <div class="item service-item">
                        <div class="icon">
                            <i><img src="<?=resource_url();?>landingpage/assets/images/service-icon-01.png" alt=""></i>
                        </div>
                        <h3 class="service-titsle">Anti Penipuan</h3>
                        <p>Disediakan dua cara pembayaran, yaitu bisa bayar duluan, atau BARANG SAMPAI BARU BAYAR (maksimal 25 botol).</p>
                    </div>
                    <div class="item service-item">
                        <div class="icon">
                            <i><img src="<?=resource_url();?>landingpage/assets/images/service-icon-01.png" alt=""></i>
                        </div>
                        <h3 class="service-titsle">Produk Asli</h3>
                        <p>Produk 100% ASLI. Jaminan uang kembali, jika produk terbukti palsu. Dan sudah terdaftar di departemen kesehatan RI.</p>
                    </div>
                    <div class="item service-item">
                        <div class="icon">
                            <i><img src="<?=resource_url();?>landingpage/assets/images/service-icon-01.png" alt=""></i>
                        </div>
                        <h3 class="service-titsle">Respon Cepat</h3>
                        <p>Kepuasan Anda adalah jaminan kami. Customer Service kami akan melayani anda dengan cepat. <br/> <br/></p>
                    </div>
                    <div class="item service-item">
                        <div class="icon">
                            <i><img src="<?=resource_url();?>landingpage/assets/images/service-icon-01.png" alt=""></i>
                        </div>
                        <h3 class="service-titsle">Harga Murah</h3>
                        <p>Anda akan mendapatkan harga paling murah di website ini. Silahkan bandingkan dg barang sejenis di tempat lain.</p>
                    </div>
                </div>
            </div>
        </div>
    </section>
    <!-- ***** Features Small End ***** -->


    <!-- ***** Frequently Question Start ***** -->
    <section class="section" id="frequently-question">
        <div class="container">
            <!-- ***** Section Title Start ***** -->
            <div class="row">
                <div class="col-lg-12">
                    <div class="section-heading">
                        <h3 class="text-center mb-5"><strong>RAHASIA MENGAPA MAGATRI SANGAT MANJUR</strong></h3>
                    </div>
                </div>
                <div class="col-lg-12 text-center">
                    <p>Rahasia MAGATRI sangat manjur untuk menangani berbagai penyakit, karena produk ini berbahan dasar Madu murni. Madu merupakan herbal hewani yang sangat terkenal sejak dulu, digunakan untuk mengobati berbagai macam penyakit, dari penyakit ringan sampai penyakit berat.</p>
                    <div class="mt-3 mb-3"></div>
                    <p>Bahkan di dalam kitab suci Al-Quran , Alloh SWT berfirman :</p>
                    <div class="mt-3 mb-3"></div>
                    <p style="text-align: center;"><strong><span style="color: #339966;">ثُمَّ كُلِي مِنْ كُلِّ الثَّمَرَاتِ فَاسْلُكِي سُبُلَ رَبِّكِ ذُلُلًا ۚ يَخْرُجُ مِنْ بُطُونِهَا شَرَابٌ مُخْتَلِفٌ أَلْوَانُهُ فِيهِ شِفَاءٌ لِلنَّاسِ ۗ إِنَّ فِي ذَٰلِكَ لَآيَةً لِقَوْمٍ يَتَفَكَّرُونَ</span></strong></p>
                    <div class="mt-3 mb-3"></div>
                    <p style="text-align: center;"><em>“Kemudian makanlah dari tiap-tiap (macam) buah-buahan dan tempuhlah jalan Tuhanmu yang telah dimudahkan (bagimu). Dari perut lebah itu ke luar minuman (madu) yang bermacam-macam warnanya, di dalamnya terdapat obat yang menyembuhkan bagi manusia. Sesungguhnya pada yang demikian itu benar-benar terdapat tanda (kebesaran Tuhan) bagi orang-orang yang memikirkan.”</em></p>
                    <div class="mt-3 mb-3"></div>
                    <p style="text-align: center;"><em>(QS : An-Nahl : 69)</em></p>
                </div>
            </div>

            <div class="row mt-5">
                <div class="col-lg-12">
                    <div class="section-heading">
                        <h3 class="text-center mb-5"><strong>KHASIAT MAGATRI MENURUT PARA AHLI</strong></h3>
                    </div>
                </div>
                <div class="col-lg-12">
                    <ul class="mt-4">
                        <li>
                            <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25" class="float-left">
                            <div class="text ml-0 pl-5">
                                <strong class="text-danger">
                                    Para peneliti dari Puslitbang Bogor 
                                </strong>
                                <p>Mereka menyatakan anak-anak yang mengkonsumsi madu setiap hari lebih jarang terserang demam & pilek, serta meningkatkan nafsu makannya. Hal ini disebabkan madu merupakan makanan yang mengandung aneka gizi seperti asam amino, karbohidrat, vitamin (B, C & E), mineral ( Kalium, natrium, zat besi dll) dan terkandung senyawa yang bersifat membunuh bakteri.</p>
                            </div>
                        </li>
                        <div class="clearfix"></div>
                        <div class="mb-3"></div>
                        <li>
                            <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25" class="float-left">
                            <div class="text ml-0 pl-5">
                                <strong class="text-danger">
                                    Komaruddin (1997) peneliti dari Departement of Biochemistry , Faculty of Medicine , University of Malaya
                                </strong>
                                <p>Di dalam madu terkandung zat anti mikrobial, yang dapat menghambat penyakit. Beberapa penyakit infeksi oleh berbagai patogen yang dapat dicegah dan disembuhkan dengan minum madu secara teratur diantaranya : Infeksi saluran pernafasan atas (ISPA), batuk, demam, penyakit luka tukak lambung, infeksi saluran pencernaan , penyakit kulit. </p>
                            </div>
                        </li>
                        <div class="clearfix"></div>
                        <div class="mb-3"></div>
                        <li>
                            <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25" class="float-left">
                            <div class="text ml-0 pl-5">
                                <strong class="text-danger">
                                    Dr. Dixon dalam majalah Dis Lancet Infect pada bulan Februari 2003
                                </strong>
                                <p>Mengeaskan adanya kekuatan besar dalam madu yang mampu mengalahkan bakteri dimana bakteri-bakteri tersebut tidak mampu bertahan hidup dalam madu. Dianjurkan untuk menggunakan madu dalam mengobati berbagai jenis luka termasuk luka bakar.</p>
                            </div>
                        </li>
                        <div class="clearfix"></div>
                        <div class="mb-3"></div>
                        <li>
                            <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25" class="float-left">
                            <div class="text ml-0 pl-5">
                                <strong class="text-danger">
                                    Peter C Molan ( 1992 ). Peneliti dari Departement of Biological Sciences, University of Waikoto , Selandia Baru
                                </strong>
                                <p>DSalah satu keunikan madu adalah karena madu mengandung zat antibiotik . Menurutnya hasil penelitinnya Madu terbukti mengandung zat antibiotik yang aktif melawan serangan berbagai kuman patogen penyebab timbulnya penyakit.</p>
                            </div>
                        </li>
                        <div class="clearfix"></div>
                        <div class="mb-3"></div>
                        <li>
                            <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25" class="float-left">
                            <div class="text ml-0 pl-5">
                                <strong class="text-danger">
                                    Pliny. Cendikiawan Romawi, dalam buku Natural History
                                </strong>
                                <p>Banyak manfaat propolis bagi kesehatan. Para tenaga kesehatan masa kini menggunakan propolis sebagai obat karena ia mengeluarkan sengat serta segala macam racun yang tertanam dalam daging, mengurangi bengkak, melembutkan kepalan, melegakan nyeri pada otot dan menyembuhkan kudis yang sangat sukar untuk diobati.</p>
                            </div>
                        </li>
                        <div class="clearfix"></div>
                        <div class="mb-3"></div>
                        <li>
                            <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25" class="float-left">
                            <div class="text ml-0 pl-5">
                                <strong class="text-danger">
                                    Komaruddin (1997) peneliti dari Departement of Biochemistry , Faculty of Medicine , University of Malaya
                                </strong>
                                <p>Di dalam madu terkandung zat anti mikrobial, yang dapat menghambat penyakit. Beberapa penyakit infeksi oleh berbagai patogen yang dapat dicegah dan disembuhkan dengan minum madu secara teratur diantaranya : Infeksi saluran pernafasan atas (ISPA), batuk, demam, penyakit luka tukak lambung, infeksi saluran pencernaan , penyakit kulit. </p>
                            </div>
                        </li>
                        <div class="clearfix"></div>
                        <div class="mb-3"></div>
                        <li>
                            <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25" class="float-left">
                            <div class="text ml-0 pl-5">
                                <strong class="text-danger">
                                    Komaruddin (1997) peneliti dari Departement of Biochemistry , Faculty of Medicine , University of Malaya
                                </strong>
                                <p>Di dalam madu terkandung zat anti mikrobial, yang dapat menghambat penyakit. Beberapa penyakit infeksi oleh berbagai patogen yang dapat dicegah dan disembuhkan dengan minum madu secara teratur diantaranya : Infeksi saluran pernafasan atas (ISPA), batuk, demam, penyakit luka tukak lambung, infeksi saluran pencernaan , penyakit kulit. </p>
                            </div>
                        </li>
                        <div class="clearfix"></div>
                        <div class="mb-3"></div>
                        <li>
                            <img src="<?=resource_url();?>landingpage/assets/images/check-mark-done.svg" alt="" width="25" class="float-left">
                            <div class="text ml-0 pl-5">
                                <strong class="text-danger">
                                    Komaruddin (1997) peneliti dari Departement of Biochemistry , Faculty of Medicine , University of Malaya
                                </strong>
                                <p>Di dalam madu terkandung zat anti mikrobial, yang dapat menghambat penyakit. Beberapa penyakit infeksi oleh berbagai patogen yang dapat dicegah dan disembuhkan dengan minum madu secara teratur diantaranya : Infeksi saluran pernafasan atas (ISPA), batuk, demam, penyakit luka tukak lambung, infeksi saluran pencernaan , penyakit kulit. </p>
                            </div>
                        </li>
                        <div class="clearfix"></div>
                        <div class="mb-3"></div>
                    </ul>
                    <div class="mt-3">
                        <div class="row">
                            <div class="col-md-5 mx-auto">
                                <a href="<?=count($products) > 0 ? base_url('product-detail/' . $products[0]['slug']) : '#'?>" class="main-button-slider btn-block text-center">Beli Sekarang</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
    <!-- ***** Frequently Question End ***** -->
    
    <!-- jQuery -->
    <script src="<?=resource_url();?>landingpage/assets/js/jquery-2.1.0.min.js"></script>

    <!-- Bootstrap -->
    <script src="<?=resource_url();?>landingpage/assets/js/popper.js"></script>
    <script src="<?=resource_url();?>landingpage/assets/js/bootstrap.min.js"></script>

    <!-- Plugins -->
    <script src="<?=resource_url();?>landingpage/assets/js/owl-carousel.js"></script>
    <script src="<?=resource_url();?>landingpage/assets/js/scrollreveal.min.js"></script>
    <script src="<?=resource_url();?>landingpage/assets/js/waypoints.min.js"></script>
    <script src="<?=resource_url();?>landingpage/assets/js/jquery.counterup.min.js"></script>
    <script src="<?=resource_url();?>landingpage/assets/js/imgfix.min.js"></script> 
    
    <!-- Global Init -->
    <script src="<?=resource_url();?>landingpage/assets/js/custom.js"></script>

  </body>
</html>