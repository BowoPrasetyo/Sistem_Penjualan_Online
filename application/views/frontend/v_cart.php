<div id="product-header">
  <section class="bg-theme-gradient breadcrumb-area">
    <div class="container">
      <div class="row">
        <div class="col-md-12 breadcrumb-contents">
          <div class="pt-5 pb-5">
            <h2 class="page-title">
              Keranjang Belanjaan
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
          <?php if(count($this->cart->contents()) > 0):?>
            <div class="bg-white border border-radius-10">
              <div class="row">
                <div class="col-lg-12">
                  <div class="p-3">
                    <div class="table-responsive">
                      <table class="table table-striped table-borderless">
                        <thead>
                          <tr>
                            <th></th>
                            <th>Produk</th>
                            <th class="text-center">Jumlah</th>
                            <th class="text-right">Harga</th>
                            <th></th>
                          </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($this->cart->contents() as $items): ?>
                          <tr id="<?=$items['rowid'];?>">
                            <td>
                              <img src="<?=$items['image'] ?? 'https://dummyimage.com/50x50/55595c/fff';?>" class="img-fluid img-50" />
                            </td>
                            <td><?=$items['name'];?></td>
                            <td>
                              <div class="form-group">
                                <div class="d-flex">
                                  <div class="w-100">
                                    <input type="number" min="1" value="<?=$items['qty'];?>" id="jumlah-barang" class="form-jumlah form-control border-right-none border-left-none border-radius-none" onchange="update_qty('<?=$items['rowid'];?>', this)">
                                  </div>
                                </div>
                              </div>
                            </td>
                            <td class="text-right text-theme text-bold"><?=currency($items['subtotal']);?></td>
                            <td class="text-right"><button onclick="delete_cart('<?=$items['rowid'];?>')" class="btn btn-sm btn-danger">&times;</button> </td>
                          </tr>
                        <?php endforeach;?>
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </div>
              <div >
            </div>
            </div>
            <?php else:?>
            <div class="alert alert-warning">
              Kamu belum memasukan barang belanjaan. <a href="<?=base_url();?>">Belanja sekarang</a>
            </div>
          <?php endif;?>
          </div>
          <!-- End -->
          <?php if(count($this->cart->contents()) > 0):?>
          <div class="col-md-12 mt-2">
            <div class="d-flex justify-content-end">
              <div class="w-25 pr-2">
                <a href="<?=base_url();?>" class="btn btn-outline-theme btn-block">Belanja</a>
              </div>
              <div class="w-25">
                <a href="<?=base_url();?>home/checkout" class="btn btn-theme btn-theme-gradient btn-block">Bayar</a>
              </div>
            </div>
          </div>
          <?php endif;?>

        </div>

      </div>

    </div>
  </div>
</section>
<script src="<?=resource_url();?>js/app-product.js"></script>
<script>

function delete_cart(rowid) {
  $("#body-wrapper").loading();
    
  let formData = new FormData();
  formData.append("rowid", rowid)
  formData.append(INITSTATE[0], INITSTATE[1])

  $.ajax({
    url: BASE_URL + 'cart/delete_cart',
    processData: false,
    contentType: false,
    data: formData,
    type: 'POST',
    success: function(data){    
      $("#body-wrapper").loading("stop");
      if(data.success) {
        $(`#${rowid}`).remove();
      }
    },
    error: function(data){    
      $("#body-wrapper").loading("stop");
    }
  })  
}
function update_qty(rowid, context) {
  $("#body-wrapper").loading();
  let qty = context.value;

  let formData = new FormData();
  formData.append("rowid", rowid)
  formData.append("qty", qty)
  formData.append(INITSTATE[0], INITSTATE[1])

  $.ajax({
    url: BASE_URL + 'cart/update_qty',
    processData: false,
    contentType: false,
    data: formData,
    type: 'POST',
    success: function(data){    
      $("#body-wrapper").loading("stop");
      if(data.success) {
        if(parseInt(qty) == 0) {
          $(`#${rowid}`).remove();
        }
      }
    },
    error: function(data){    
      $("#body-wrapper").loading("stop");
    }
  })
}
</script>