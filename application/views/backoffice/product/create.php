<div class="container-fluid">
  <div class="row">
    <div class="col-md-12" id="tabs">
      <div class="bg-white border-radius-10 border">
        <div class="">
          <nav>
            <div class="nav nav-tabs nav-fill" id="nav-tab" role="tablist">
              <a class="nav-item nav-link active" id="nav-product-tab" data-toggle="tab" href="#nav-product" role="tab" aria-controls="nav-product" aria-selected="true">
                <i class="fas fa-info"></i> Informasi Produk
              </a>
              <a class="nav-item nav-link" id="nav-image-tab" data-toggle="tab" href="#nav-image" role="tab" aria-controls="nav-image" aria-selected="false">
                <i class="fas fa-image"></i> Gambar Produk
              </a>
            </div>
          </nav>
          <div class="tab-content py-3 px-3 px-sm-0" id="nav-tabContent">
            <div class="tab-pane fade show active p-3" id="nav-product" role="tabpanel" aria-labelledby="nav-product-tab">
            <?php if($this->session->flashdata('success')){ ?>
              <div class="alert alert-success">
                <?php echo $this->session->flashdata('success'); ?>
              </div>
            <?php }else if($this->session->flashdata('err')){  ?>
              <div class="alert alert-danger">
                <?php echo $this->session->flashdata('err'); ?>
              </div>
            <?php }else if($this->session->flashdata('warning')){  ?>
              <div class="alert alert-warning">
                <?php echo $this->session->flashdata('warning'); ?>
              </div>
            <?php }else if($this->session->flashdata('info')){  ?>
              <div class="alert alert-info">
                <?php echo $this->session->flashdata('info'); ?>
              </div>
            <?php } ?>
              <form action="<?=$edit ? base_url('backoffice/product/update/' . $edit['id']) : base_url('backoffice/product/store');?>" method="post" id="product-form">
                <input autocomplete="off" type="hidden" id="product_ref" name="product_ref" value="<?=$edit ? $edit['product_ref'] : rand(1000, 9000) . time();?>">
                <input autocomplete="off" type="hidden" id="id" name="id" value="<?=$edit ? $edit['id'] : null?>">
                <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
                <div class="form-group">        
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">Nama Produk</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="title" name="title" class="form-control form-control-lg form-search" placeholder="Nama Produk" value="<?=$edit ? $edit['title'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">        
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">SEO</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="slug" name="slug" class="form-control form-control-lg form-search" placeholder="Slug" value="<?=$edit ? $edit['slug'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                     <label for="">Kategori Produk</label>
                    </div>
                    <div class="col-md-10">
                      <select class="form-control select2" id="category_id" name="category_id" style="width: 100%;">
                        <option>Pilih Kategory</option>
                        <?php foreach($categories as $category):?>
                          <option <?=$edit['category_id'] == $category['id'] ? 'selected' : ''?> value="<?=$category['id'];?>"><?=$category['name'];?></option>
                        <?php endforeach;?>
                      </select>
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                     <label for="">Status Produk</label>
                    </div>
                    <div class="col-md-10">
                      <select class="form-control select2" id="status" name="status" style="width: 100%;">
                        <option>Pilih Status</option>
                          <option <?=$edit['status'] == 'draft' ? 'selected' : ''?> value="draft">Draft</option>
                          <option <?=$edit['status'] == 'publish' ? 'selected' : ''?> value="publish">Publish</option>
                      </select>
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">Stok</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="stock" name="stock" class="form-control form-control-lg form-search" placeholder="Stok Produk" value="<?=$edit ? $edit['stock'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">Harga</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="price" name="price" class="form-control form-control-lg form-search" placeholder="Harga produk" value="<?=$edit ? $edit['price'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">Komisi Mediator</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="commision_mediator" name="commision_mediator" class="form-control form-control-lg form-search" placeholder="Komisi Mediator" value="<?=$edit ? $edit['commision_mediator'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">Komisi Penyedia</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="commision_provider" name="commision_provider" class="form-control form-control-lg form-search" placeholder="HKomisi Penyedia" value="<?=$edit ? $edit['commision_provider'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">Komisi Leader</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="commision_leader" name="commision_leader" class="form-control form-control-lg form-search" placeholder="Komisi Leader" value="<?=$edit ? $edit['commision_leader'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">Komisi Referral</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="commision_affiliator" name="commision_affiliator" class="form-control form-control-lg form-search" placeholder="Komisi Referral" value="<?=$edit ? $edit['commision_affiliator'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">Komisi CS</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="commision_cs" name="commision_cs" class="form-control form-control-lg form-search" placeholder="Komisi CS" value="<?=$edit ? $edit['commision_cs'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">Fee maintenance</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="commision_maintenance" name="commision_maintenance" class="form-control form-control-lg form-search" placeholder="Fee maintenance" value="<?=$edit ? $edit['commision_maintenance'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">Berat Produk (gr)</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="weight" name="weight" class="form-control form-control-lg form-search" placeholder="Berat Produk" value="<?=$edit ? $edit['weight'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">Panjang Produk</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="long" name="long" class="form-control form-control-lg form-search" placeholder="Panjang Produk" value="<?=$edit ? $edit['long'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                      <label for="">Lebar Produk</label>
                    </div>
                    <div class="col-md-10">
                      <input autocomplete="off" type="text" id="width" name="width" class="form-control form-control-lg form-search" placeholder="Lebar Produk" value="<?=$edit ? $edit['width'] : '';?>">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2 text-md-right">
                    <label for="">Deskripsi Produk</label>
                    </div>
                    <div class="col-md-10">
                      <textarea class="textarea" rows="8" id="description" name="description" class="form-control form-control-lg form-search" placeholder="Deskripsi produk"><?=$edit ? $edit['description'] : '';?></textarea>
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-2"></div>
                    <div class="col-md-10">
                      <button type="submit" id="save-btn" disabled class="btn btn-info-gradient btn-block btn-info btn-lg"><?=$edit ? 'Update Produk' : 'Tambah Produk'?></button>
                    </div>
                  </div>
                </div>
              </form>
            </div>
            <div class="tab-pane fade p-3" id="nav-image" role="tabpanel" aria-labelledby="nav-image-tab">
              <h4 class="text-bold text-secondary">Upload Gambar</h4>
              <hr class="bg-info"/>
              <div class="add-list-media-wrap mb-4">
                  <div class="fuzone">
                      <div class="dropzone border border-radius-10" style="background-color: #f0f0f0!important">
                        <div class="dz-message">
                          <h4 class="text-secondary">Klik atau Seret gambar kesini</h4>
                        </div>
                      </div>
                  </div>
              </div>
              <h4 class="text-bold text-secondary">Daftar Gambar</h4>
              <hr class="bg-info"/>
              <div id="image-lists"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
<link rel="stylesheet" href="<?=resource_url();?>plugins/adminlte/plugins/dropzone/dist/min/dropzone.min.css">
<script src="<?=resource_url();?>plugins/adminlte/plugins/dropzone/dist/min/dropzone.min.js"></script>
<script src="<?=resource_url();?>js/be-product.js"></script>
<script>
$(function () {
  // Summernote
  $('.textarea').summernote({
    height: 100,
  })

  $("input").change(function() {
    autosave_change()
  });

  $("select").change(function() {
    autosave_change()
  });
  
  chcekSlug()

  $('#slug').keyup(function() {
    var Text = $(this).val();
    Text = Text.toLowerCase();
    var regExp = /\s+/g;
    Text = Text.replace(regExp,'-');
    $("#slug").val(Text);   
    chcekSlug()
  })

  $('#slug').change(function() {  
    chcekSlug()
  })

  function convertToSlug(Text) {
      return Text
          .toLowerCase()
          .replace(/[^\w ]+/g,'')
          .replace(/ +/g,'-')
          ;
  }

  function chcekSlug() {
    if($('#slug').val() == '') {
      var Text = $('#title').val();
      Text = Text.toLowerCase();
      var regExp = /\s+/g;
      Text = Text.replace(regExp,'-');
      $("#slug").val(Text); 
    }
  }

  let timeout;
  function autosave_change() {
    timeout = setTimeout(function() {
      $.ajax({
        type: 'POST',
        data: $("#product-form").serialize(),
        url: BASE_URL + 'backoffice/product/update_ajax/' + $('#id').val(),
        success: function(res) {
        },
        error: function(err) {
        }
      })
    }, 1000)
  }
})  
</script>
