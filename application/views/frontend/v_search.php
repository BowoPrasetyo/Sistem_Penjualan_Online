<div class="clearfix"></div>
<div class="mt-4"></div>

<!-- Start -->
<div id="category">
    <div class="container">
      <div class="row">
        <div class="col-md-4">
          <div class="row sticky">

            <div class="col-md-12">
              <div class="bg-white border-radius-5">
                <div class="pl-3 pt-3 pr-3">
                  <h5>Kategori</h5>
                </div>
                <!-- Content -->
                <div class="content-sidebar">
                  <hr class="bg-info"/>

                  <div class="pl-3 pb-3 pr-3">
                    <div class="item-side-category mb-2">
                      <a href="<?=base_url('home/search?q=&c=');?>" class="text-info text-bold">
                        <div class="d-flex justify-content-between">
                          <div>Semua Kategori</div>
                          <!-- <div>200</div> -->
                        </div>
                      </a>
                    </div>

                    <?php foreach($categories as $category):?>
                    <div class="item-side-category mb-2">
                      <a href="<?=base_url('home/search?q=' . $this->input->get('q') . '&c=' .$category['id']);?>" class="text-dark">
                        <div class="d-flex justify-content-between">
                          <div><?=$category['name'];?></div>
                          <div><?=$category['total_products'];?></div>
                        </div>
                      </a>
                    </div>
                    <?php endforeach;?>

                  </div>
                </div>
                <!-- End Content -->
                
              </div>
            </div>

          </div>
        </div>
        <div class="col-md-8">
          <div class="row">
            <div class="col-md-12">
              <h5>Hasil Pencarian:</h5>
              <div class="mb-3"></div>
            </div>
          </div>
          <div class="row">
            
            <?php foreach($products as $key => $product):?>
            <div class="col-6 col-lg-4 mb-4">
              <a href="<?=base_url() . 'product-detail/' . $product['slug'];?>">
                <div class="wrapper-category text-center">
                  <div class="image-category mb-2">
                    <img class="img-250 mx-auto" src="<?=$product['image'] ? check_image('upload/img', $product['image']) : 'https://via.placeholder.com/468';?>" class="img-fluid" alt="">
                  </div>
                  <div class="caption-category text-left">
                    <h6 class="text-dark"><?=$product['title'];?></h6>
                    <span class="text-secondary"><?=currency($product['price']);?></span>
                  </div>
                </div>
              </a>
            </div>
            <?php endforeach;?>

            <?php if(count($products) <= 0):?>
              <div class="col-md-12">
                <div class="alert alert-info">
                  Produk tidak ditemukan.
                </div>
              </div>
            <?php endif;?>

          </div>
      </div>
    </div>
  </div>
  <!-- End -->