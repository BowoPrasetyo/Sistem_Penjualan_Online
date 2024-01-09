<div id="product-header">
  <section class="bg-info-gradient breadcrumb-area">
    <div class="container">
      <div class="row">
        <div class="col-md-12 breadcrumb-contents">
          <div class="pt-5 pb-5">
            <h2 class="page-title">
              <span class="badge badge-warning d-none d-md-inline-block"><?=$product->category_name;?></span>
              <?=$product->title;?>
            </h2>
          </div>
        </div>
        <!-- end /.col-md-12 -->
      </div>
      <!-- end /.row -->
    </div>
    <!-- end /.container -->
  </section>
</div>
<div class="clearfix"></div>
<div class="mt-5"></div>
<section id="product-detail">
  <div class="container">
    <div class="row">
      
      <div class="col-md-12">

        <div class="row">
          <!-- Content -->
          <div class="col-md-12">
            <div class="bg-white border-left border-right border-top border-bottom">
              <div class="row">
                <div class="col-lg-5">
                  <div class="product-images">
                    
                    <?php if(count($product_images) > 0):?>
                      <?php foreach($product_images as $image):?>
                        <div>
                        <a class="example-image-link" href="<?=$image->image ? check_image('upload/img', $image->image) : 'https://via.placeholder.com/468';?>" data-lightbox="example-set" data-title="">
                          <img src="<?=$image->image ? check_image('upload/img', $image->image) : 'https://via.placeholder.com/468';?>" class="img-fluid mx-auto d-block" alt="">
                        </a>
                        </div>
                      <?php endforeach;?>
                    <?php else:?>
                    <div>
                      <img src="https://via.placeholder.com/468" class="img-fluid mx-auto d-block" alt="">
                    </div>
                    <?php endif;?>
                  </div>
                </div>
                <div class="col-lg-7">
                  <div class="p-3">
                    <h3><?=$product->title;?></h3>
                    <hr/>
                    <div class="row mb-4 mt-4">
                      <div class="col-lg-2">
                        <h6>Harga</h6>
                      </div>
                      <div class="col-lg-10">
                        <h4 class="text-info"><?=currency($product->price);?></h4>
                      </div>
                    </div>
                    <hr/>
                    <div class="row mb-4 mt-4">
                      <div class="col-lg-2">
                        <h6>Stok</h6>
                      </div>
                      <div class="col-lg-10">
                        <?php if($product->stock > 0):?>
                          <div class="mb-2">
                            <span>Tersedia <?=$product->stock;?></span>
                          </div>
                          <div class="form-group">
                            <div class="d-flex">
                              <div class="w-10">
                                <button class="btn bg-white border btn-block border-radius-none border-radius-top-left-5 border-radius-bottom-left-5 btn-jumlah" id="btn-decrement">-</button>
                              </div>
                              <div class="w-80">
                                <input type="number" min="1" max="<?=$product->stock;?>" value="1" id="jumlah-barang" class="form-jumlah form-control border-right-none border-left-none border-radius-none">
                              </div>
                              <div class="w-10">
                                <button class="btn bg-white border btn-block border-radius-none border-radius-top-right-5 border-radius-bottom-right-5 btn-jumlah" id="btn-increment">+</button>
                              </div>
                            </div>
                          </div>
                        <?php else:?>
                          <span class="text-danger">Stok Kosong</span>
                        <?php endif;?>
                        
                      </div>
                    </div>
                    <hr/>
                    <div class="row mb-4 mt-4">
                      <div class="col-lg-2">
                        <h6>Info Produk</h6>
                      </div>
                      <div class="col-lg-10">
                        <div class="d-flex">
                          <div class="pb-2 pt-2 pr-4">
                            <span class="text-secondary">Berat</span>
                            <h6><?=$product->weight .'gr' ?? '';?></h6>
                          </div>
                          <div class="pb-2 pt-2 pr-4">
                            <span class="text-secondary">Panjang</span>
                            <h6><?=$product->long ?? '-';?></h6>
                          </div>
                          <div class="pb-2 pt-2 pr-4">
                            <span class="text-secondary">Lebar</span>
                            <h6><?=$product->width ?? '-';?></h6>
                          </div>
                        </div>
                      </div>
                    </div>
                    <hr/>
                    <div class="row mb-4 mt-4">
                      <div class="col-lg-2">
                        <h6>Total Harga</h6>
                      </div>
                      <div class="col-lg-10">
                        <h4 class="text-info" id="total-harga"><?=currency($product->price);?></h4>
                      </div>
                    </div>
                    
                    <div class="row mb-4 mt-4">
                      <?php if($product->stock > 0):?>
                      <?php if(is_login_member()):?>
                        <div class="col-md-6">
                          <button <?=$product->stock <= 0 ? "disabled" : "";?> class="btn btn-block btn-outline-info btn-outline-info-gradient mb-2" id="btn-beli">Beli</button>
                        </div>
                        <div class="col-md-6">
                          <button <?=$product->stock <= 0 ? "disabled" : "";?> class="btn btn-block btn-info btn-info-gradient" id="btn-keranjang">Tambah ke Keranjang</button>
                        </div>
                      <?php else:?>
                        <div class="col-md-12">
                          <div class="alert alert-warning">
                            Silahkan <a href="<?=base_url('auth/login?redirect=' . current_url());?>">Masuk</a> atau <a href="<?=base_url('auth/register?redirect=' . current_url());?>">Daftar</a> untuk membeli produk ini.
                          </div>
                        </div>
                      <?php endif;?>
                      <?php else:?>
                      <div class="col-md-12">
                        <div class="alert alert-danger">Mohon maaf, stok produk sedang kosong.</div>
                      </div>
                      <?php endif;?>
                    </div>

                  </div>
                </div>
              </div>
              <div >
                <!-- Box Information -->
                <!-- <div class="row text-center">
                  <div class="col-md-4">
                    <div class="border p-3">
                      Ulasan
                      <h5 class="text-bold text-info">5.0</h5>
                    </div>
                  </div>
                  <div class="col-md-4">
                    <div class="border p-3">
                      Terjual
                      <h5>20</h5>
                    </div>
                  </div>
                </div> -->
                <!-- Box -->
              </div>
            </div>
          </div>
          <!-- End -->
          <!-- Review -->
          <div class="col-lg-12 mt-3">
            <div class="bg-white border-left border-right border-top border-bottom " id="tabs">
              <nav>
                <div class="nav nav-tabs nav-fill" id="nav-tab" role="tablist">
                  <a class="nav-item nav-link active" id="nav-description-tab" data-toggle="tab" href="#nav-description" role="tab" aria-controls="nav-description" aria-selected="true">Deskripsi</a>
                  <!-- <a class="nav-item nav-link" id="nav-ulasan-tab" data-toggle="tab" href="#nav-ulasan" role="tab" aria-controls="nav-ulasan" aria-selected="false">Ulasan</a> -->
                  <!-- <a class="nav-item nav-link" id="nav-diskusi-tab" data-toggle="tab" href="#nav-diskusi" role="tab" aria-controls="nav-diskusi" aria-selected="false">Diskusi</a> -->
                </div>
              </nav>
              <div class="p-3">
                <div class="tab-content" id="nav-tabContent">
                  <!-- Deskripsi -->
                  <div class="tab-pane fade show active" id="nav-description" role="tabpanel" aria-labelledby="nav-description-tab">
                    <?=$product->description;?>
                  </div>
                  <div class="tab-pane fade show" id="nav-ulasan" role="tabpanel" aria-labelledby="nav-ulasan-tab">
                    <div class="row">
                      <div class="col-md-12">
                        <h4>Asep Yayat</h4>
                        <h6 class="text-muted">20 jan 2020</h6>
                        <p>Saya sangat puas membeli madu di sini, harganya sesuai dengan khasiat yang terkandung. Pokoknya mantap</p>
                        <hr/>
                      </div>
                      <div class="col-md-12">
                        <h4>Asep Yayat</h4>
                        <h6>20 jan 2020</h6>
                        <p>Saya sangat puas membeli madu di sini, harganya sesuai dengan khasiat yang terkandung. Pokoknya mantap</p>
                      </div>
                    </div>
                  </div>
                  <div class="tab-pane fade show" id="nav-diskusi" role="tabpanel" aria-labelledby="nav-diskusi-tab">
                    <div class="row">
                      <div class="col-md-12">
                        <form action="<?=base_url('home/add_discussion');?>" method="post">
                          <div class="form-group">
                            <input type="hidden" name="parent" value="0">
                            <input type="hidden" name="product_id" value="<?=$product->id;?>">
                            <textarea required class="form-control border border-radius-10" name="content" rows="5" placeholder="Masukan pertanyaan Anda"></textarea>
                          </div>
                          <div class="form-group">
                            <button type="submit" class="btn btn-info btn-info-gradient float-right">Kirim</button>
                          </div>
                        </form>
                        <div class="clearfix"></div>
                      </div>
                      
                      <?php foreach($discussions as $discussion):?>
                      <div class="col-md-12 mb-3">
                        <h4>Asep Yayat</h4>
                        <h6 class="text-muted"><?=date('d F Y', strtotime($discussion['created_at']));?></h6>
                        <p><?=$discussion['content'];?></p>

                        <?php if(count($discussion['childrens']) > 0):?>
                        <div class="row">
                          <div class="col-md-1"></div>
                          <div class="col-md-11">
                            <div class="row">
                            <?php foreach($discussion['childrens'] as $children):?>
                              <div class="col-md-12">
                                <h6>Asep Yayat</h6>
                                <h6 class="text-muted"><?=date('d F Y', strtotime($children['created_at']));?></h6>
                                <p><?=$children['content'];?></p>
                              </div>
                              <?php endforeach;?>
                            </div>
                          </div>
                        </div>
                        <?php endif;?>
                        
                        <form action="<?=base_url('home/add_discussion');?>" method="post">
                          <div class="form-group">
                            <input type="hidden" name="parent" value="<?=$discussion['id'];?>">
                            <input type="hidden" name="product_id" value="<?=$product->id;?>">
                            <textarea required name="content" class="form-control border border-radius-10" rows="2" placeholder="Masukan balasan Anda"></textarea>
                          </div>
                          <div class="form-group">
                            <button type="submit" class="btn btn-info btn-info-gradient float-right">Balas</button>
                          </div>
                        </form>
                        <div class="clearfix"></div>
                        <hr/>
                      </div>
                      <?php endforeach;?>

                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <!-- End Review -->
        </div>

      </div>

    </div>
  </div>
</section>
<link href="<?=resource_url();?>plugins/lightbox/dist/css/lightbox.min.css" rel="stylesheet" />
<script src="<?=resource_url();?>plugins/lightbox/dist/js/lightbox.min.js"></script>
<script>
  let productImages = null;
  <?php if(count($product_images) > 0):?>
    productImages = '<?=base_url();?>resources/upload/img/<?=$product_images[0]->image;?>'
  <?php endif;?>
  let productDetail = JSON.parse('<?=json_encode($product);?>')
  let jumlahBarang = $('#jumlah-barang');

  function updateTotalHarga(jumlah) {
    $('#total-harga').html(currency(jumlah * parseInt(productDetail.price)))
  }

  $(function() {
    $('.product-images').slick();

    $('#btn-increment').click(function() {
      if(parseInt(jumlahBarang.val()) + 1 > parseInt(productDetail.stock)) {
        jumlahBarang.val(parseInt(productDetail.stock))
        return updateTotalHarga(parseInt(productDetail.stock))
      }

      jumlahBarang.val(parseInt(jumlahBarang.val()) + 1)
      updateTotalHarga(parseInt(jumlahBarang.val()))
    })

    $('#btn-decrement').click(function() {
      if(parseInt(jumlahBarang.val()) < 2) return;
      
      jumlahBarang.val(parseInt(jumlahBarang.val()) - 1)
      updateTotalHarga(parseInt(jumlahBarang.val()))
    })

    $('#jumlah-barang').keyup(function() {

      if($(this).val() == '' || $(this).val() == null) {
        jumlahBarang.val(parseInt(1))
        return updateTotalHarga(parseInt(1))
      }

      if(parseInt($(this).val()) > parseInt(productDetail.stock)) {
        jumlahBarang.val(parseInt(productDetail.stock))
        return updateTotalHarga(parseInt(productDetail.stock))
      }
      updateTotalHarga(parseInt($(this).val()))
    })
  })
</script>
<script src="<?=resource_url();?>js/app-product.js"></script>