<div class="container-fluid">
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
                  -
                </div>
              </div>
            </div>
            <div class="border-bottom"></div>
            <div class="p-3">
              <?php
                $totalPendapatan = 0;
                $totalKomisiPenyedia = 0;
                $totalKomisiAfiliator = 0;
                $totalKomisiMediator = 0;
                $totalKomisiLeader = 0;
                $totalKomisiCs = 0;
                $totalFeeMaintenance = 0;
              ?>
              <?php foreach($detail['product'] as $product):?>
                <?php
                  $productJson = json_decode($product->product)  
                ?>
              <div class="d-flex flex-column flex-md-row mb-3">
                <div class="w-15 pr-5 d-none d-md-block w-xs-100 w-sm-100">
                <img class="img-150 mx-auto" src="<?=$productJson->image ? base_url($productJson->image) : 'https://via.placeholder.com/150';?>" alt="">
                </div>
                <div class="pl-3 pr-3 w-50 w-xs-100 w-sm-100 mt-3 mb-3 mt-lg-0 mb-lg-0">
                  <div class="d-flex flex-column justify-content-start">
                    <div>
                      <span><?=$productJson->title;?></span>
                    </div>
                    <div>
                      <small class="text-muted">Total Pembelian: <?=$product->quantity;?></small>
                    </div>
                    <!-- <div>
                      <small class="text-muted">Berat: <?=$product->weight ?? 0;?> gram</small>
                    </div> -->
                    <?php
                      $komisiPenyedia = (int) $product->total_commision_provider;
                      $komisiAfiliator = (int) $product->total_commision_affiliator;
                      $komisiMediator = (int) $product->total_commision_mediator;
                      $komisiLeader = (int) $product->total_commision_leader;
                      $komisiCs = (int) $product->total_commision_cs;
                      $feeMaintenance = (int) $product->total_commision_maintenance;

                      $pendapatanBersih = $product->price * (int) $product->quantity - $komisiPenyedia - $komisiAfiliator - $feeMaintenance - $komisiMediator - $komisiLeader - $komisiCs;

                      $totalPendapatan = $totalPendapatan + $pendapatanBersih;
                      $totalKomisiPenyedia = $totalKomisiPenyedia + $komisiPenyedia;
                      $totalKomisiAfiliator = $totalKomisiAfiliator + $komisiAfiliator;
                      $totalKomisiMediator = $totalKomisiMediator + $komisiMediator;
                      $totalKomisiLeader = $totalKomisiLeader + $komisiLeader;
                      $totalKomisiCs = $totalKomisiCs + $komisiCs;
                      $totalFeeMaintenance = $totalFeeMaintenance + $feeMaintenance;
                    ?>
                    <?php if($detail['transaction']->item_status != 'waiting_transfer'):?>
                    <div>
                      <small class="text-muted">Pendapatan Bersih : <?=currency($pendapatanBersih);?></small>
                    </div>
                    <div>
                      <small class="text-muted">Komisi Mediator : <?=currency($komisiMediator);?></small>
                    </div>
                    <div>
                      <small class="text-muted">Komisi CS : <?=currency($komisiCs);?></small>
                    </div>
                    <div>
                      <small class="text-muted">Komisi Penyedia : <?=currency($komisiPenyedia);?></small>
                    </div>
                    <div>
                      <small class="text-muted">Komisi Leader : <?=currency($komisiLeader);?></small>
                    </div>
                    <div>
                      <small class="text-muted">Komisi Afiliator : <?=currency($komisiAfiliator);?></small>
                    </div>
                    <div>
                      <small class="text-muted">Fee Maintenance : <?=currency($feeMaintenance);?></small>
                    </div>
                    <?php endif;?>
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
                <div class="pr-3 pl-3 w-50 w-xs-100 w-sm-100 mt-3 mb-3 mt-lg-0 mb-lg-0">
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
                <div class="pr-3 pl-3 w-50 w-xs-100 w-sm-100 mt-3 mb-3 mt-lg-0 mb-lg-0">
                  <div class="d-flex flex-column justify-content-start">
                    <div>
                      <span>Kode Unik</span>
                    </div>
                  </div>
                </div>
                <div class="w-35 w-xs-100 w-sm-100 text-left text-md-right">
                  <strong><?=currency($detail['transaction']->unique);?></strong>
                </div>
              </div>
              <div class="d-flex flex-column flex-md-row mb-2">
                <div class="w-15 pr-3 d-none d-md-block w-xs-100 w-sm-100">
                </div>
                <div class="pr-3 pl-3 w-50 w-xs-100 w-sm-100 mt-3 mb-3 mt-lg-0 mb-lg-0">
                  <div class="d-flex flex-column justify-content-start">
                    <div>
                      <span>Biaya COD</span>
                    </div>
                  </div>
                </div>
                <div class="w-35 w-xs-100 w-sm-100 text-left text-md-right">
                  <strong><?=currency($detail['transaction']->cash_on_delivery_markup);?></strong>
                </div>
              </div>
              <div class="d-flex flex-column flex-md-row mb-2">
                <div class="w-15 pr-3 d-none d-md-block w-xs-100 w-sm-100">
                </div>
                <div class="pr-3 pl-3 w-50 w-xs-100 w-sm-100 mt-3 mb-3 mt-lg-0 mb-lg-0">
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
            <?php if($detail['transaction']->item_status != 'waiting_transfer'):?>
            <div class="border-bottom"></div>
            <div class="p-3">
              <div class="d-flex justify-content-end mb-2">
                <div class="mr-2">
                  Pendapatan Bersih
                </div>
                <div>
                  <strong><?=currency($totalPendapatan);?></strong>
                </div>
              </div>

              <div class="d-flex justify-content-end mb-2">
                <div class="mr-2">
                  Pendapatan Penyedia
                </div>
                <div>
                  <strong><?=currency($totalKomisiPenyedia);?></strong>
                </div>
              </div>
              
              <div class="d-flex justify-content-end mb-2">
                <div class="mr-2">
                  Pendapatan Mediator
                </div>
                <div>
                  <strong><?=currency($totalKomisiMediator);?></strong>
                </div>
              </div>

              <div class="d-flex justify-content-end mb-2">
                <div class="mr-2">
                  Pendapatan CS
                </div>
                <div>
                  <strong><?=currency($totalKomisiCs);?></strong>
                </div>
              </div>

              <div class="d-flex justify-content-end mb-2">
                <div class="mr-2">
                  Pendapatan Leader
                </div>
                <div>
                  <strong><?=currency($totalKomisiLeader);?></strong>
                </div>
              </div>
              
              <div class="d-flex justify-content-end mb-2">
                <div class="mr-2">
                  Pendapatan Affiliator
                </div>
                <div>
                  <strong><?=currency($totalKomisiAfiliator);?></strong>
                </div>
              </div>

              <div class="d-flex justify-content-end mb-2">
                <div class="mr-2">
                  Fee Maintenance
                </div>
                <div>
                  <strong><?=currency($totalFeeMaintenance);?></strong>
                </div>
              </div>

            </div>
            <?php endif;?>
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
                <div class="w-35 w-xs-100 mb-3 mb-sm-0 pr-3">
                  <div class="d-flex flex-column">
                    <div>
                      <small class="text-muted">NO. RESI</small>
                    </div>
                    <div>
                      <div class="form-group">
                        <?php if($detail['transaction']->item_status != 'waiting_transfer'):?>
                          <input type="text" id="no-receipt" data-id="<?=$detail['transaction']->id;?>" class="form-control form-control-lg form-search" placeholder="Masukan nomor Resi" value="<?=$detail['transaction']->no_receipt;?>">
                        <?php else:?>
                          <span>-</span>
                        <?php endif;?>
                      </div>
                    </div>
                  </div>
                </div>
                <div class="w-30 w-xs-100 align-self-center mb-3 mb-sm-0">
                  <?php if(is_payment($detail['transaction']->item_status) && $detail['transaction']->item_status != 'pending'):?>
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
      <div class="bg-white border">
        <div class="p-3">
          <?php if($detail['transaction']->item_status == 'pending'):?>
            <button class="btn-block btn btn-info btn-info-gradient">Proses Pesanan</button>
            <hr/>
          <?php endif;?>
          <?php if($detail['transaction']->item_status == 'send'):?>
            <div class="alert alert-info bg-info-gradient">Pesanan sudah dikirim</div>
            <div class="dropdown-divider"></div>
          <?php endif;?>
          <?php if($detail['transaction']->item_status == 'complete'):?>
            <div class="alert alert-success bg-success-gradient">Pesanan sudah selesai</div>
            <div class="dropdown-divider"></div>
          <?php endif;?>
          <?php if($detail['transaction']->item_status == 'cancel'):?>
            <div class="alert alert-danger bg-danger-gradient">Pesanan dibatalakan</div>
            <div class="dropdown-divider"></div>
          <?php endif;?>
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
              <small class="text-muted">STATUS PENGIRIMAN</small>
            </div>
            <div>
              <input type="hidden" id="trx_id" value="<?=$detail['transaction']->id;?>" />
              <select class="form-control select2" id="status" data-id="<?=$detail['transaction']->id;?>" style="width: 100%;">
                <option <?=$detail['transaction']->item_status == 'pending' ? 'selected' : '';?> value="pending">Pending</option>
                <option <?=$detail['transaction']->item_status == 'process' ? 'selected' : '';?> value="process">Diproses</option>
                <option <?=$detail['transaction']->item_status == 'send' ? 'selected' : '';?> value="send">Dikirim</option>
                <option <?=$detail['transaction']->item_status == 'complete' ? 'selected' : '';?> value="complete">Selesai</option>
              </select>
            </div>
          </div>
          <div class="dropdown-divider"></div>
          <div class="d-flex flex-column">
            <div>
              <small class="text-muted">JENIS PEMBAYARAN</small>
            </div>
            <div> <?=$detail['transaction']->cash_on_delivery == 1 ? 'COD' : 'Cash';?></div>
          </div>
          <div class="dropdown-divider"></div>
          <?php if($detail['transaction']->cash_on_delivery == 1):?>
          <div class="d-flex flex-column">
            <div>
              <small class="text-muted">BIAYA COD</small>
            </div>
            <div>
              <div class="form-group">
                <input type="number" class="form-control form-search form-control-lg" data-id="<?=$detail['transaction']->id;?>" name="cod_price" id="cod_price" value="<?=$detail['transaction']->cash_on_delivery_markup;?>">
              </div>
            </div>
          </div>
          <div class="dropdown-divider"></div>
          <?php endif;?>
          <div class="d-flex flex-column">
            <div>
              <small class="text-muted">METODE PEMBAYARAN</small>
            </div>
            <div>Transfer Virtual Account</div>
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
  $(function() {
    $('#no-receipt').change(function() {
      update_no_receipt($(this).data('id'), $(this).val())
    })

    $('#status').change(function() {
     update_status($(this).data('id'), $(this).val())
    })

    $('#cod_price').change(function() {
     update_cod_price($(this).data('id'), $(this).val())
    })
  })
  function check_waybill(walbill, courier) {
    $('#history-delivery').html('Loading..')
    
    if(courier.toLowerCase() == 'j&t') {
        courier = 'jnt'
    }
    
    $.ajax({
      url: BASE_URL + `rajaongkirapi/waybill/${walbill}/${courier}`,
      type: 'get',
      success: function(res) {
        if(res.success) {
          let history = `<ul class="timeline">`

          if(res.data.rajaongkir.result.delivery_status.status == 'DELIVERED') {
            update_status($('#trx_id').val(), 'complete', false)
            history += `<li class="complete">
              <span class="text-muted pl-4">${res.data.rajaongkir.result.delivery_status.pod_date}</span>
              <p class="pl-4">
                <strong>Diterima oleh Penerima Paket (${res.data.rajaongkir.result.delivery_status.pod_receiver}) ${res.data.rajaongkir.result.delivery_status.pod_time}</strong>
              </p>
            </li>`
          }

          res.data.rajaongkir.result.manifest.reverse().map(m => {
            history += `<li>
              <span class="text-muted pl-4">${m.manifest_date}</span>
              <p class="pl-4">
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
  function update_no_receipt(id, value) {
    $('#loading-wrapper').loading()
    let formData = new FormData();
    formData.append("id", id)
    formData.append("value", value)
    formData.append(INITSTATE[0], INITSTATE[1])

    $.ajax({
      url: BASE_URL + 'backoffice/transaction/update_no_receipt/' + id,
      processData: false,
      contentType: false,
      data: formData,
      type: 'POST',
      success: function(data){    
        console.log(data)
        $('#loading-wrapper').loading("stop")
        window.location.reload()
      },
      error: function(data){    
        console.log(data)
        $('#loading-wrapper').loading("stop")
        window.location.reload()
      }
    })
  }

  function update_cod_price(id, value) {
    $('#loading-wrapper').loading()
    let formData = new FormData();
    formData.append("id", id)
    formData.append("value", value)
    formData.append(INITSTATE[0], INITSTATE[1])

    $.ajax({
      url: BASE_URL + 'backoffice/transaction/update_cod_price/' + id,
      processData: false,
      contentType: false,
      data: formData,
      type: 'POST',
      success: function(data){    
        console.log(data)
        $('#loading-wrapper').loading("stop")
        window.location.reload()
      },
      error: function(data){    
        console.log(data)
        $('#loading-wrapper').loading("stop")
        window.location.reload()
      }
    })
  }

  function update_status(id, value, refresh = true) {
    $('#loading-wrapper').loading()
    let formData = new FormData();
    formData.append("id", id)
    formData.append("value", value)
    formData.append(INITSTATE[0], INITSTATE[1])

    $.ajax({
      url: BASE_URL + 'backoffice/transaction/update_status/' + id,
      processData: false,
      contentType: false,
      data: formData,
      type: 'POST',
      success: function(data){    
        console.log(data)
        
        $('#loading-wrapper').loading("stop")
        if(!refresh) return;
        window.location.reload()
      },
      error: function(data){    
        console.log(data)
        $('#loading-wrapper').loading("stop")
        if(!refresh) return;
        window.location.reload()
      }
    })
  }
</script>
