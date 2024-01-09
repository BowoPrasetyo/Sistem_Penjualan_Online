<div id="product-header">
  <section class="bg-info-gradient breadcrumb-area">
    <div class="container">
      <div class="row">
        <div class="col-md-12 breadcrumb-contents">
          <div class="pt-5 pb-5">
            <h2 class="page-title">
              Detail Transaksi
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
<div class="container">
  <div class="row">

    <div class="col-md-8 mb-3">
      <div class="card">
        <div class="card-header">
          <strong>Daftar Pembelian</strong>
        </div>
        <div class="card-body">
          <div class="border">

            <div class="p-3">
              <div class="d-flex flex-column">
                <div>
                  <small class="text-muted">CATATAN</small>
                </div>
                <div>
                  <?php if($detail['transaction']->cash_on_delivery == 1):?>
                    <div class="alert alert-info">
                      Untuk Jenis Pembayaran COD total yang di bayarkan adalah pada informasi <strong>TOTAL PEMBAYARAN</strong>. Karena ada biaya layanan COD rata-rata sebesar Rp. 5.000,-.
                    </div>
                  <?php else:?>
                    -
                  <?php endif;?>
                </div>
              </div>
            </div>
            <div class="border-bottom"></div>
            <div class="p-3">
              <?php foreach($detail['product'] as $product):?>
              <?php
                $productJson = json_decode($product->product)  
              ?>
              <div class="d-flex flex-column flex-md-row mb-2">
                <div class="w-15 pr-3 d-none d-md-block w-xs-100 w-sm-100">
                  <img class="img-100 mx-auto" src="<?=$productJson->image ? base_url($productJson->image) : 'https://via.placeholder.com/150';?>" alt="">
                </div>
                <div class="pl-3 pr-3 w-50 w-xs-100 w-sm-100 mt-3 mb-3 mt-lg-0 mb-lg-0">
                  <div class="d-flex flex-column justify-content-start">
                    <div>
                      <span><?=$productJson->title;?></span>
                    </div>
                    <div>
                      <small class="text-muted">Jumlah: <?=$product->quantity;?></small>
                    </div>
                    <!-- <div>
                      <small class="text-muted">Berat: <?=$product->weight ?? 0;?></small>
                    </div> -->
                  </div>
                </div>
                <div class="w-35 w-xs-100 w-sm-100 text-left text-md-right">
                  <?=currency((int) $product->price * (int) $product->quantity);?>
                </div>
              </div>
              <?php endforeach;?>
              <div class="d-flex flex-column flex-md-row mb-2">
                <div class="w-15 pr-3 d-none d-md-block w-xs-100 w-sm-100">
                </div>
                <div class="pl-3 pr-3 w-50 w-xs-100 w-sm-100 mt-3 mb-3 mt-lg-0 mb-lg-0">
                  <div class="d-flex flex-column justify-content-start">
                    <div>
                      <span>Ongkos Kirim</span>
                    </div>
                  </div>
                </div>
                <div class="w-35 w-xs-100 w-sm-100 text-left text-md-right">
                  <?=currency($detail['shipping']->cost);?>
                </div>
              </div>
              <div class="d-flex flex-column flex-md-row mb-2">
                <div class="w-15 pr-3 d-none d-md-block w-xs-100 w-sm-100">
                </div>
                <div class="pl-3 pr-3 w-50 w-xs-100 w-sm-100 mt-3 mb-3 mt-lg-0 mb-lg-0">
                  <div class="d-flex flex-column justify-content-start">
                    <div>
                      <span>Biaya COD</span>
                    </div>
                  </div>
                </div>
                <div class="w-35 w-xs-100 w-sm-100 text-left text-md-right">
                  <?=currency($detail['transaction']->cash_on_delivery_markup);?>
                </div>
              </div>
              <div class="d-flex flex-column flex-md-row mb-2">
                <div class="w-15 pr-3 d-none d-md-block w-xs-100 w-sm-100">
                </div>
                <div class="pl-3 pr-3 w-50 w-xs-100 w-sm-100 mt-3 mb-3 mt-lg-0 mb-lg-0">
                  <div class="d-flex flex-column justify-content-start">
                    <div>
                      <span>Total</span>
                    </div>
                  </div>
                </div>
                <div class="w-35 w-xs-100 w-sm-100 text-left text-md-right">
                  <strong><?=currency($detail['transaction']->amount + $detail['transaction']->cash_on_delivery_markup);?></strong>
                </div>
              </div>
            </div>
            <div class="border-bottom"></div>
            <div class="p-3">
              <div class="d-flex flex-column">
                <div>
                  <small class="text-muted">STATUS PEMBELIAN</small>
                </div>
                <div class="mb-3">
                <ol class="progtrckr" data-progtrckr-steps="3">
                  <?php
                    $classProgress = ['todo', 'todo', 'todo'];
                    $progress = ['Diproses', 'Dikirim', 'Selesai'];

                    switch($detail['transaction']->item_status) {
                      case 'process':
                        $classProgress[0] = 'done';
                        break;
                      case 'send':
                        $classProgress[0] = 'done';
                        $classProgress[1] = 'done';
                        break;  
                      case 'complete':
                        $classProgress[0] = 'done';
                        $classProgress[1] = 'done';
                        $classProgress[2] = 'done';
                        break;    
                    }

                    foreach($progress as $k => $p) {
                      echo '<li class="progtrckr-'.$classProgress[$k].'">'.$p.'</li>';
                    }
                  ?>
                </ol>
                </div>
              </div>
            </div>
            <div class="border-bottom"></div>
            <div class="p-3">
              <div class="d-flex flex-column flex-md-row">
                <div class="w-35 w-xs-100 mb-3 mb-sm-0">
                  <div class="d-flex flex-column">
                    <div>
                      <small class="text-muted">JASA PENGIRIMAN</small>
                    </div>
                    <div>
                    <?=strtoupper($detail['shipping']->courier . ' ' . $detail['shipping']->service);?>
                    </div>
                  </div>
                </div>
                <div class="w-35 w-xs-100 mb-3 mb-sm-0">
                  <div class="d-flex flex-column">
                    <div>
                      <small class="text-muted">NO. RESI</small>
                    </div>
                    <div>
                      <?=$detail['transaction']->no_receipt ?? '-';?>
                    </div>
                  </div>
                </div>
                <div class="w-30 w-xs-100 align-self-center mb-3 mb-sm-0">
                  <?php if(is_payment($detail['transaction']->item_status)):?>
                  <a href="#" onclick="check_waybill('<?=$detail['transaction']->no_receipt;?>','<?=$detail['shipping']->courier;?>')" data-toggle="modal" data-target="#exampleModalLong">Cek Histori</a>
                  <?php endif;?>
                </div>
              </div>
            </div>
            <div class="border-bottom"></div>
            <div class="p-3">
              <div class="d-flex flex-column">
                <div>
                  <small class="text-muted">ESTIMASI BARANG SAMPAI</small>
                </div>
                <div>
                  2 hari
                </div>
              </div>
            </div>
            
          </div>
        </div>
      </div>
    </div>

    <div class="col-md-4">
      <?php if($detail['transaction']->item_status == 'send'):?>
        <a href="" class="btn btn-info btn-info-gradient btn-block mb-2">Barang Sudah Diterima</a>
      <?php endif;?>
      <div class="bg-white border">
        <div class="p-3">
          
          <div class="d-flex flex-column">
            <div>
              <small class="text-muted">NO. TRANSAKSI</small>
            </div>
            <div><?=$detail['transaction']->order_id;?></div>
          </div>
          <div class="dropdown-divider"></div>
          <div class="d-flex flex-column">
            <div>
              <small class="text-muted">STATUS PEMBAYARAN</small>
            </div>
            <div>
            <?php if(is_payment($detail['transaction']->item_status)):?>
              Sudah Dibayar
            <?php else:?>
              Menunggu Pembayaran
            <?php endif;?>
            </div>
          </div>
          <div class="dropdown-divider"></div>
          <div class="d-flex flex-column">
            <div>
              <small class="text-muted">METODE PEMBAYARAN</small>
            </div>
            <div>Transfer Virtual Account</div>
          </div>
          <div class="dropdown-divider"></div>
          <div class="d-flex flex-column">
            <div>
              <small class="text-muted">JENIS PEMBAYARAN</small>
            </div>
            <div> <?=$detail['transaction']->cash_on_delivery == 1 ? 'COD' : 'Transfer';?></div>
          </div>
          <div class="dropdown-divider"></div>
          <div class="d-flex flex-column">
            <div>
              <small class="text-muted">TOTAL PEMBAYARAN</small>
            </div>
            <div><?=currency($detail['transaction']->amount + $detail['transaction']->cash_on_delivery_markup);?></div>
          </div>
          <div class="dropdown-divider"></div>
          <div class="d-flex flex-column">
            <div>
              <small class="text-muted">ALAMAT PENGIRIMAN</small>
            </div>
            <div>
              <strong><?=$detail['shipping']->first_name;?></strong><br/>
              <span><?=$detail['shipping']->address;?></span><br/>
              <span><?=$detail['shipping']->district_name;?>, <?=$detail['shipping']->province;?></span><br/>
              <span><?=$detail['shipping']->city_name;?>, <?=$detail['shipping']->postal_code;?></span><br/>
              <span>Indonesia</span><br/>
              <span>Tlp./No. Hp: <?=$detail['shipping']->phone;?></span>
            </div>
          </div>

        </div>
      </div>
    </div>
  </div>
</div>
<!-- Modal -->
<div class="modal animated zoomIn" id="exampleModalLong" tabindex="-1" role="dialog" aria-labelledby="exampleModalLongTitle" aria-hidden="true">
  <div class="vertical-alignment-helper">
  <div class="modal-dialog vertical-align-center modal-lg" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="exampleModalLongTitle">History Pengiriman</h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <div class="modal-body">
        <div id="history-delivery"></div>
		<!-- Variable History Pengiriman -->
		1. SHIPMENT RECEIVED BY COUNTER OFFICER.  <br>
		2. SHIPMENT PICKED UP BY COURIER. <br>
    3. RECEIVED AT SORTING. <br>
    4. PROCESSED AT SORTING. <br>
    5. RECEIVED AT ORIGIN GATEWAY. <br>
    6. RECEIVED AT WEREHOUSE. <br>
    7. WITH DELIVERY COURIER. <br>
    8. FINISH. 
      </div>
    </div>
  </div>
  </div>
  
</div>

<script>
  function check_waybill(walbill, courier) {
    $('#history-delivery').

    $.ajax({
      url: BASE_URL + `rajaongkirapi/waybill/${walbill}/${courier}`,
      type: 'get',
      success: function(res) {
        if(res.success) {
          let history = `<ul class="timeline">`

          if(res.data.rajaongkir.result.delivery_status.status == 'DELIVERED') {
            history += `<li class="complete">
              <span class="text-muted">${res.data.rajaongkir.result.delivery_status.pod_date}</span>
              <p>
                <strong>Diterima oleh Penerima Paket (${res.data.rajaongkir.result.delivery_status.pod_receiver}) ${res.data.rajaongkir.result.delivery_status.pod_time}</strong>
              </p>
            </li>`
          }

          res.data.rajaongkir.result.manifest.reverse().map(m => {
            history += `<li>
              <span class="text-muted">${m.manifest_date}</span>
              <p>
                ${m.manifest_description} - ${m.city_name} ${m.manifest_time}
              </p>
            </li>`
          })
          history += `</ul>`

          $('#history-delivery').html(history)
        }
      }
    })
  }
</script>