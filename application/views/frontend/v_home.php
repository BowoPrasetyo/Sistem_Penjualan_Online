<div class="clearfix"></div>
<div class="mt-4"></div>

<div id="slider">
  <div class="container d-none">
    <div class="row">
      <div class="col-md-12">
        <h5>Promo & Informasi</h5>
        <div class="promotion-slider center slider">
          <div>
            <img class="d-block w-100" src="https://via.placeholder.com/768x300" alt="First slide">
          </div>
          <div>
            <img class="d-block w-100" src="https://via.placeholder.com/768x300" alt="First slide">
          </div>
          <div>
            <img class="d-block w-100" src="https://via.placeholder.com/768x300" alt="First slide">
          </div>
          <div>
            <img class="d-block w-100" src="https://via.placeholder.com/768x300" alt="First slide">
          </div>
        </div>
        <!-- <div id="carouselExampleIndicators" class="carousel slide" data-ride="carousel">
          <ol class="carousel-indicators">
            <li data-target="#carouselExampleIndicators" data-slide-to="0" class="active"></li>
            <li data-target="#carouselExampleIndicators" data-slide-to="1"></li>
            <li data-target="#carouselExampleIndicators" data-slide-to="2"></li>
          </ol>
          <div class="carousel-inner">
            <div class="carousel-item active">
              <img class="d-block w-100" src="https://via.placeholder.com/768x300" alt="First slide">
              <div class="carousel-caption d-none d-md-block">
                <h5>...</h5>
                <p>...</p>
              </div>
            </div>
            <div class="carousel-item">
              <img class="d-block w-100" src="https://via.placeholder.com/768x300" alt="First slide">
              <div class="carousel-caption d-none d-md-block">
                <h5>...</h5>
                <p>...</p>
              </div>
            </div>
            <div class="carousel-item">
              <img class="d-block w-100" src="https://via.placeholder.com/768x300" alt="First slide">
              <div class="carousel-caption d-none d-md-block">
                <h5>...</h5>
                <p>...</p>
              </div>
            </div>
          </div>
          <a class="carousel-control-prev" href="#carouselExampleIndicators" role="button" data-slide="prev">
            <span class="carousel-control-prev-icon" aria-hidden="true"></span>
            <span class="sr-only">Previous</span>
          </a>
          <a class="carousel-control-next" href="#carouselExampleIndicators" role="button" data-slide="next">
            <span class="carousel-control-next-icon" aria-hidden="true"></span>
            <span class="sr-only">Next</span>
          </a>
        </div> -->
      </div>
    </div>
  </div>
</div>

<div class="mt-4"></div>

<!-- Start -->
<div id="category">
  <div class="container">
    <div class="row">
      <div class="col-md-12">
        <div class="bg-white p-3 border-radius-5">
          <h5>Kategori</h5>
          <hr class="bg-theme"/>

          <!-- Row -->
          <div class="row">
            <div class="col-md-12">
              <?php if(count($categories) > 0):?>
                <div class="category-slider">
                <?php foreach($categories as $key => $category):?>
                  <div>
                    <a href="<?=base_url('home/search?q=&c=' . $category['id']);?>">
                      <div class="wrapper-category text-center border p-5 align-self-center border-radius-10 mr-3">
                        <div class="caption-category">
						<img src="<?=$category['image'] ? check_image('upload/img', $category['image']) : 'https://via.placeholder.com/468';?>" class="img-fluid" alt="">
                          <h6 class="text-dark"><?=$category['name'];?></h6>
                        </div>
                      </div>
                    </a>
                  </div>
                <?php endforeach;?>
                </div>
              <?php endif;?>
            </div>
            <!-- <div class="col-lg-2 col-6">
              <div class="wrapper-category text-center">
                <div class="image-category">
                  <img src="<?=resource_url();?>img/notebook.png" class="img-fluid" alt="">
                </div>
                <div class="caption-category">
                  <h6>Komputer / Laptop</h6>
                  <span class="text-secondary">Cari Produk</span>
                </div>
              </div>
            </div>

            <div class="col-lg-2 col-6">
              <div class="wrapper-category text-center">
                <div class="image-category">
                  <img src="<?=resource_url();?>img/notebook.png" class="img-fluid" alt="">
                </div>
                <div class="caption-category">
                  <h6>Komputer / Laptop</h6>
                  <span class="text-secondary">Cari Produk</span>
                </div>
              </div>
            </div>

            <div class="col-lg-2 col-6">
              <div class="wrapper-category text-center">
                <div class="image-category">
                  <img src="<?=resource_url();?>img/notebook.png" class="img-fluid" alt="">
                </div>
                <div class="caption-category">
                  <h6>Komputer / Laptop</h6>
                  <span class="text-secondary">Cari Produk</span>
                </div>
              </div>
            </div>

            <div class="col-lg-2 col-6">
              <div class="wrapper-category text-center">
                <div class="image-category">
                  <img src="<?=resource_url();?>img/notebook.png" class="img-fluid" alt="">
                </div>
                <div class="caption-category">
                  <h6>Komputer / Laptop</h6>
                  <span class="text-secondary">Cari Produk</span>
                </div>
              </div>
            </div>

            <div class="col-lg-2 col-6">
              <div class="wrapper-category text-center">
                <div class="image-category">
                  <img src="<?=resource_url();?>img/notebook.png" class="img-fluid" alt="">
                </div>
                <div class="caption-category">
                  <h6>Komputer / Laptop</h6>
                  <span class="text-secondary">Cari Produk</span>
                </div>
              </div>
            </div>

            <div class="col-lg-2 col-6">
              <div class="wrapper-category text-center">
                <div class="image-category">
                  <img src="<?=resource_url();?>img/notebook.png" class="img-fluid" alt="">
                </div>
                <div class="caption-category">
                  <h6>Komputer / Laptop</h6>
                  <span class="text-secondary">Cari Produk</span>
                </div>
              </div>
            </div> -->

          </div>
          <!-- End Row -->

          <!-- <div class="row mt-4">
            <div class="col-md-12">
              <div class="text-center">
                <button class="btn btn-info">Selengkapnya</button>
              </div>
            </div>
          </div> -->

        </div>
      </div>
    </div>
  </div>
</div>
<!-- End -->

<div class="cleafix"></div>
<div class="mt-4"></div>

<!-- Start -->
<div id="product">
  <div class="container">
    <div class="row">
      <div class="col-md-12">
        <h4 class="mb-3">Produk</h4>
      </div>
      <?php if(count($products) > 0):?>
        <?php foreach($products as $key => $product):?>
          <div class="col-6 col-sm-6 col-md-4 col-lg-3 mb-3">
            <div class="wrapper-category text-center bg-white " style="overflow: hidden">
              <div class="image-category mb-2">
                <img class="img-250 mx-auto" src="<?=$product['image'] ? check_image('upload/img', $product['image']) : 'https://via.placeholder.com/468';?>" class="img-fluid" alt="">
              </div>
              <div class="caption-category text-left p-3">
                <h6>
                  <a class="text-dark" href="<?=base_url() . 'product-detail/' . $product['slug'];?>"><?=$product['title'];?></a>
                </h6>
                <span class="text-secondary"><?=currency($product['price']);?></span>
                <hr/>
                <a href="<?=base_url() . 'product-detail/' . $product['slug'];?>" class="btn btn-theme btn-block btn-theme-gradient">Beli</a>
              </div>
            </div>
          </div>
        <?php endforeach;?>
      <?php endif;?>
    </div>
  </div>
</div>
<!-- End -->  
<script>
  $(function() {
    $('.promotion-slider').slick({
      centerMode: true,
      centerPadding: '60px',
      slidesToShow: 1,
      responsive: [
        {
          breakpoint: 768,
          settings: {
            arrows: false,
            centerMode: true,
            centerPadding: '40px',
            slidesToShow: 1
          }
        },
        {
          breakpoint: 480,
          settings: {
            arrows: false,
            centerMode: true,
            centerPadding: '40px',
            slidesToShow: 1
          }
        }
      ]
    });
    $('.brand-slider').slick({
      centerMode: true,
      centerPadding: 0,
      slidesToShow: 6,
      responsive: [
        {
          breakpoint: 768,
          settings: {
            arrows: false,
            centerMode: true,
            centerPadding: '40px',
            slidesToShow: 2
          }
        },
        {
          breakpoint: 480,
          settings: {
            arrows: false,
            centerMode: true,
            centerPadding: '40px',
            slidesToShow: 2
          }
        }
      ]
    });
    $('.category-slider').slick({
      centerMode: false,
      centerPadding: '0',
      slidesToShow: 6,
      responsive: [
        {
          breakpoint: 768,
          settings: {
            arrows: false,
            centerMode: true,
            centerPadding: '40px',
            slidesToShow: 2
          }
        },
        {
          breakpoint: 480,
          settings: {
            arrows: false,
            centerMode: true,
            centerPadding: '40px',
            slidesToShow: 2
          }
        }
      ]
    });
  })
</script>