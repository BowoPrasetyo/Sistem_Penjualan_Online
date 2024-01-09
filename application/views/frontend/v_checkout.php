<div id="product-header">
  <section class="bg-theme-gradient breadcrumb-area">
    <div class="container">
      <div class="row">
        <div class="col-md-12 breadcrumb-contents">
          <div class="pt-5 pb-5">
            <h2 class="page-title">
              Checkout Transaksi
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
<div class="mt-4"></div>
<div id="checkout">
  <div class="container">
    <div class="row">

      <div class="col-lg-12 mt-3 form-shipping">
        <div class="bg-white border border-radius-10 " id="tabs">
          <nav>
            <div class="nav nav-tabs nav-fill" id="nav-tab" role="tablist">
              <a class="nav-item nav-link active" id="nav-pesanan-tab" data-toggle="tab" href="#nav-pesanan" role="tab" aria-controls="nav-pesanan" aria-selected="true">Pesanan</a>
              <a class="nav-item nav-link" id="nav-pengiriman-tab" data-toggle="tab" href="#nav-pengiriman" role="tab" aria-controls="nav-pengiriman" aria-selected="false">Pengiriman</a>
              <!-- <a class="nav-item nav-link" id="nav-pembayaran-tab" data-toggle="tab" href="#nav-pembayaran" role="tab" aria-controls="nav-pembayaran" aria-selected="false">Pembayaran</a> -->
            </div>
          </nav>
          <div class="p-4">
            <div class="tab-content" id="nav-tabContent">
              <!-- Deskripsi -->
              <div class="tab-pane fade show active" id="nav-pesanan" role="tabpanel" aria-labelledby="nav-pesanan-tab">
                <div id="product-lists">
                  <?php
                  $unique_3digit = rand(100, 999);
                  ?>
                  <?php foreach($this->cart->contents() as $key => $item):?>
                  <div class="d-flex mb-4">
                    <div class="w-15 pr-4 d-none d-md-block">
                      <img src="<?=$item['image'] ?? 'https://dummyimage.com/50x50/55595c/fff';?>" class="img-fluid img-150" />
                    </div>
                    <div class="w-75">
                      <h5 class="mb-4">
                        <a class="text-dark" target="_blank" href="<?=base_url('product-detail/' . $item['slug']);?>"><?=$item['name'];?></a>
                      </h5>
                      <div class="row mt-2">
                        <div class="col-lg-2">
                          <h6 class="text-muted">Total</h6>
                        </div>
                        <div class="col-lg-10">
                          <h6><?=$item['qty'];?></h6>
                        </div>
                      </div>

                      <div class="row mt-2">
                        <div class="col-lg-2">
                          <h6 class="text-muted">Total Berat</h6>
                        </div>
                        <div class="col-lg-10">
                          <h6><?=ceil((int) $item['weight'] / 1000 * (int) $item['qty']);?>kg</h6>
                        </div>
                      </div>

                      <div class="row mt-2">
                        <div class="col-lg-2">
                          <h6 class="text-muted">Subtotal</h6>
                        </div>
                        <div class="col-lg-10">
                          <h6 class="text-theme"><?=currency($item['subtotal']);?></h6>
                        </div>
                      </div>

                      <div class="row mt-2 d-none">
                        <div class="col-lg-2">
                          <h6 class="text-muted">Catatan</h6>
                        </div>
                        <div class="col-lg-10">
                          <div class="form-group">
                            <textarea class="form-control form-search" placeholder="Masukan catatan khusus.." data-rowid="<?=$item['rowid'];?>" id="<?=$item['rowid'];?>" onchange="changeNote('<?=$item['rowid'];?>')"><?=$item['note'];?></textarea>
                          </div>
                        </div>
                      </div>

                    </div>
                  </div>
                  <hr/>
                  <?php endforeach;?>
                  <div class="d-flex justify-content-end">
                    <div class="mr-2">
                      Grand Total
                    </div>
                    <div>
                      <h4 class="text-theme"><?=currency((int) $this->cart->total());?></h4>
                    </div>
                  </div>
                </div>
              </div>
              <div class="tab-pane fade show" id="nav-pengiriman" role="tabpanel" aria-labelledby="nav-pengiriman-tab">
              <form action="<?=base_url();?>" method="post" id="form-checkout">
                <div class="row">
                  <div class="col-md-6">
                    <input type="hidden" id="total_weight" value="<?=$weight;?>">
                    <input type="hidden" id="unique_3digit" value="<?=$unique_3digit;?>">
                    <div class="form-group">
                      <label for="">
                        <strong>Nama Penerima</strong>
                      </label>
                      <input type="text" class="form-control form-search" id="recipient_name" name="recipient_name" placeholder="Nama penerima" value="">
                    </div>
                  </div>
                  <div class="col-md-6">
                    <div class="form-group">
                      <label for="">
                        <strong>No .Telepon</strong>
                      </label>
                      <input type="text" id="phone" name="phone" class="form-control form-search" placeholder="No. Telepon">
                    </div>
                  </div>
                  <div class="col-md-12">
                    <div class="form-group">
                      <label for="">
                        <strong>Alamat Lengkap</strong>
                      </label>
                      <textarea class="form-control form-search" id="recipient_address" name="recipient_address" placeholder="Alamat penerima"></textarea>
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <label for="">
                    <strong>Pilih Provinsi</strong>
                  </label>
                  <select class="province" id="province" name="province">
                  </select>
                </div>
                <div class="form-group">
                  <label for="">
                    <strong>Pilih Kota</strong>
                  </label>
                  <select class="city" id="city" name="city">
                    <option disabled selected>Pilih Kota</option>
                  </select>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-6">
                      <label for="">
                      <strong>Pilih Kecamatan</strong>
                      </label>
                      <select class="district" id="district" name="district">
                        <option disabled selected>Pilih Kecamatan</option>
                      </select>
                    </div>
                    <div class="col-md-6">
                      <label for="">
                        <strong>Kode POS</strong>
                      </label>
                      <input type="text" class="form-control form-search" id="postal_code" name="postal_code" placeholder="Kode POS" value="">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <label for="">
                    <strong>Pembayaran</strong>
                  </label>
                  <select class="service" id="service" name="service">
                      <option value="">Pilih Pembayaran</option>
                      <option value="cash">Midtrans</option>
                      <!--option value="cod">Cash on Delivery</option>
                      <option value="transfer">Transfer</option-->
                  </select>
                </div>
                <div class="form-group jasa-pengiriman">
                  <label for="">
                    <strong>Jasa Pengiriman</strong>
                  </label>
                  <select class="courier" id="courier" name="courier">
                    <option disabled selected>Pilih Jasa pengiriman</option>
                  </select>
                </div>
                <div class="service-cash d-none">
                  <h4 class="mb-3 mt-2">Metode Pembayaran</h4>
                  <hr/>
                  <div class="custom-control custom-radio">
                    <input id="midtrans" name="paymentMethod" type="radio" class="custom-control-input" checked required>
                    <label class="custom-control-label" for="midtrans">Bank Transfer (Virtual Account)</label>
                  </div>
                  <div class="mt-2">
                    <p class="text-muted">Setelah pembayaran selesai pesanan akan otomatis terverifikasi. Biasanya membutuhkan 5 - 15 Menit. Jika pembayaran berhasil namun pesanan belum terverifikasi, silahkan hubungi Customer Service.</p>
                  </div>
                </div>
                <div class="service-cod d-none">
                  <div class="mt-2">
                    <p class="text-muted">Harga yang tertera akan ditambah biaya layanan COD sebesar Rp. 5.000-. Dan hanya tersedia untuk pengiriman menggunakan JNT</p>
                  </div>
                </div>
                  <div class="service-transfer d-none">
                      <div class="mt-2">
                          <p>Silahkan Transfer ke Rekening di bawah ini dengan nominal <span id="total_pembayaran"></span></p>
                          <p>
                              BRI<br/>
                              345201012455536<br/>
                              a.n Yuspita Noviyanti
                          </p>
                          <p>Jumlah pembayaran harus sesuai dengan nominal yang tercantum agar dapat diproses otomatis</p>
                      </div>
                  </div>
                <div class="mt-2" id="validation-checkout-error">
                  <p class="text-danger">**Mohon lengkapi semua form yang tersedia untuk melanjutkan pemesanan.</p>
                </div>
                <div class="form-group mt-3">
                  <button type="submit" disabled class="btn btn-theme btn-theme-gradient btn-block btn-lg border-radius-none" id="btn-proses-pesanan">
                    Proses Pesanan
                  </button>
                </div>
              </form>
              </div>
              <div class="tab-pane fade show" id="nav-pembayaran" role="tabpanel" aria-labelledby="nav-pembayaran-tab">
                  
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

    </div>
  </div>
</div>
<link href="https://cdn.jsdelivr.net/npm/select2@4.0.13/dist/css/select2.min.css" rel="stylesheet" />
<link href="<?=resource_url();?>css/select2-bootstrap.css" rel="stylesheet" />
<script src="https://cdn.jsdelivr.net/npm/select2@4.0.13/dist/js/select2.min.js"></script>

<?php if($this->data['setting_midtrans_mode'] == 'dev'):?>
  <script type="text/javascript" src="https://app.sandbox.midtrans.com/snap/snap.js" data-client-key="<?=$this->data['setting_midtrans_mode'] == 'dev' ? $this->data['setting_midtrans_client_key_dev'] : $this->data['setting_midtrans_client_key'];?>"></script>
<?php elseif($this->data['setting_midtrans_mode'] == 'production'):?>
  <script type="text/javascript" src="https://app.midtrans.com/snap/snap.js" data-client-key="<?=$this->data['setting_midtrans_mode'] == 'dev' ? $this->data['setting_midtrans_client_key_dev'] : $this->data['setting_midtrans_client_key'];?>"></script>
<?php endif;?>
<script>
  let courierSelected = null;
  let provinceSelected = null;
  let citySelected = null;
  let districtSelected = null;

  $(document).ready(function() {
    $.fn.select2.defaults.set( "theme", "bootstrap" );

    $('.province').select2();
    $('.city').select2();
    $('.district').select2();
    $('.courier').select2();
    $('.service').select2();

    getProvince();

    $('.service').change(function(e) {
      if($(this).val() == 'cod') {
        $('.service-cod').toggleClass('d-none')
        $('.service-cash').toggleClass('d-none')
        appendCourier($('.district').val(), 'J&T')
        $('.courier').html("<option disabled selected>Pilih Kurir</option>")
        courierSelected == null
      } else if($(this).val() == 'cash') {
        //$('.jasa-pengiriman').toggleClass('d-none');
        appendCourier($('.district').val())
        $('.courier').html("<option disabled selected>Pilih Kurir</option>")
        courierSelected == null
        $('.service-cod').toggleClass('d-none')
        // $('.service-cash').toggleClass('d-none')
      } else if($(this).val() == 'transfer') {
          //$('.jasa-pengiriman').toggleClass('d-none');
          appendCourier($('.district').val())
          $('.courier').html("<option disabled selected>Pilih Kurir</option>")
          courierSelected == null
          // $('.service-cod').toggleClass('d-none')
          // $('.service-cash').toggleClass('d-none')
      }
    })
    
    $('.province').change(function(e) {
      appendCities($(this).val())
      $('.city').html("<option disabled selected>Pilih Kota</option>")
      $('.district').html("<option disabled selected>Pilih Kecamatan</option>")
      provinceSelected = $(this).find("option:selected").data("province")
      courierSelected = null
      districtSelected = null
      citySelected = null
    })

    $('.city').change(function(e) {
      appendDistrict($(this).val())
      $('.district').html("<option disabled selected>Pilih Kecamatan</option>")
      citySelected = $(this).find("option:selected").data("city")
      courierSelected = null
      districtSelected = null
    })

    $('.district').change(function(e) {
      appendCourier($(this).val())
      $('.courier').html("<option disabled selected>Pilih Kurir</option>")
      districtSelected = $(this).find("option:selected").data("district")
      courierSelected = null
    })

    $('.courier').change(function(e) {
      let dataCourier = $(this).find("option:selected").data("courier")
      console.log(dataCourier)
      courierSelected = dataCourier
    })
  });

  function getProvince() {
    $(".form-shipping").loading();

    $.ajax({
      url: BASE_URL + '/rajaongkirapi/province',
      type: 'GET',
      success: function(data) {
        let appendProvinces = ''
        
        appendProvinces += '<option disabled selected>Pilih Provinsi</option>'
        
        if(data.data != null || data.data != undefined) {
          data.data.rajaongkir.results.forEach(item => {
            appendProvinces += `<option data-province='${JSON.stringify(item)}' value="${item.province_id}">${item.province}</option>`
          })
        }

        $('.province').html(appendProvinces)
        $(".form-shipping").loading("stop");
      },
      error: function(e) {
        $(".form-shipping").loading("stop");
      }
    })
  }

  function appendCities(province) {
    $(".form-shipping").loading();

    $.ajax({
      url: BASE_URL + '/rajaongkirapi/city/' + province,
      type: 'GET',
      success: function(data) {
        let appendCities = ''

        appendCities += '<option disabled selected>Pilih Kota</option>'

        if(data.data != null || data.data != undefined) {
          data.data.rajaongkir.results.forEach(item => {
            appendCities += `<option data-city='${JSON.stringify(item)}' value="${item.city_id}">${item.type} ${item.city_name}</option>`
          })
        }

        $('.city').html(appendCities)
        $(".form-shipping").loading("stop");
      },
      error: function(e) {
        $(".form-shipping").loading("stop");
      }
    })
  }

  function appendDistrict(city) {
    $(".form-shipping").loading();

    $.ajax({
      url: BASE_URL + '/rajaongkirapi/district/' + city,
      type: 'GET',
      success: function(data) {
        let appendDistricts = ''

        appendDistricts += '<option disabled selected>Pilih Kecamatan</option>'

        if(data.data != null || data.data != undefined) {
          data.data.rajaongkir.results.forEach(item => {
            appendDistricts += `<option data-district='${JSON.stringify(item)}' value="${item.subdistrict_id}">${item.subdistrict_name}</option>`
          })
        }

        $('.district').html(appendDistricts)
        $(".form-shipping").loading("stop");
      },
      error: function(e) {
        $(".form-shipping").loading("stop");
      }
    })
  }

  function appendCourier(subdistrict, code = null) {
    $(".form-shipping").loading();

    $.ajax({
      url: BASE_URL + `/rajaongkirapi/costs/60/${subdistrict}/10/city/subdistrict`,
      type: 'GET',
      success: function(data) {
        let appendCourier = ''

        appendCourier += '<option disabled selected>Pilih Kurir</option>'

        if(data.data != null || data.data != undefined) {
          data.data.forEach(item => {
            if(code != null) {
              if(item.code == code) {
                appendCourier += `<option data-courier='${JSON.stringify(item)}' value="${item.service}">${item.code_display} ${item.service} (${item.cost.etd}) - ${item.cost.value_format}</option>`
              }
            } else {
              appendCourier += `<option data-courier='${JSON.stringify(item)}' value="${item.service}">${item.code_display} ${item.service} (${item.cost.etd}) - ${item.cost.value_format}</option>`
            }
          })
        }

        $('.courier').html(appendCourier)
        $(".form-shipping").loading("stop");
      },
      error: function(e) {
        $(".form-shipping").loading("stop");
      }
    })
  }

  function changeNote(rowid) {
    let formData = new FormData();
    formData.append('rowid', rowid)
    formData.append('note', $(`#${rowid}`).val())
    formData.append(INISTATE[0], INITSTATE[1])

    $.ajax({
      url: BASE_URL + 'cart/update_note',
      processData: false,
      contentType: false,
      data: formData,
      type: 'POST',
      success: function(data){

      }
    })
  }

  if($("#form-checkout").length > 0 ) {
    $("#btn-proses-pesanan").removeAttr("disabled");
    $("#form-checkout").validate({
      rules: {
        recipient_name: {
          required: true,
          minlength: 2
        },
        phone: {
          required: true,
          number: true
        },
        recipient_address: {
          required: true,
        },
        province: {
          required: true,
        },
        city: {
          required: true,
        },
        district: {
          required: true,
        },
        postal_code: {
          required: true,
        },
        courier: {
          required: true,
        }
      },
      errorPlacement: function (error, element) {
        var name = element.attr('name');
        var type = element[0].tagName;
        console.log(type)
        var errorSelector = '.form-control-feedback[for="' + name + '"]';
        var $element = $(errorSelector);
        if ($element.length) {
            $(errorSelector).html(error.html());
        } else {
            if (type == 'SELECT') {
                error.insertAfter(element.next());
            }
            else {
                error.insertAfter(element);
            }
        }
      },
      debug: true,
      submitHandler: function(form) {
        form.submit()
      },
    });
  }

  $("#form-checkout").submit(function(e) {
    e.preventDefault()
    if($("#form-checkout").valid()) {
      $("#btn-proses-pesanan").prop("disabled", true);
      $("#body-wrapper").loading();
    
      let formData = new FormData();
      formData.append("recipient_name", $('#recipient_name').val())
      formData.append("recipient_address", $('#recipient_address').val())
      formData.append("phone", $('#phone').val())
      formData.append("postal_code", $('#postal_code').val())
      formData.append("unique_3digit", $('#unique_3digit').val())
      formData.append("cash_on_delivery", $('#service').val())
      formData.append("province", JSON.stringify(provinceSelected))
      formData.append("city", JSON.stringify(citySelected))
      formData.append("district", JSON.stringify(districtSelected))
      formData.append("courier", JSON.stringify(courierSelected))
      formData.append(INITSTATE[0], INITSTATE[1])

      $.ajax({
        url: BASE_URL + 'transaction/create_transaction',
        processData: false,
        contentType: false,
        data: formData,
        type: 'POST',
        success: function(data){    
          $("#body-wrapper").loading("stop");
          if(data.success) {
            if($('.service').val() == 'cash') {
              snap.pay(data.data.snap_token, {
                onSuccess: function(result){
                  window.location.href = BASE_URL + 'member/transaction'
                },
                onPending: function(result){
                  window.location.href = BASE_URL + 'member/transaction'
                },
                onError: function(result){
                  window.location.href = BASE_URL
                },
                onClose: function(){
                  window.location.href = BASE_URL
                }
              })
            } else if($('.service').val() == 'transfer') {
                $('.service-transfer').removeClass('d-none')
                $('#total_pembayaran').html(`<strong>${data.data.amount}</strong>`)
            } else {
              window.location.href = BASE_URL + 'member/transaction'
            }
            
          } else {
            $("#btn-proses-pesanan").prop("disabled", false);
          }
        },
        error: function(data){    
          $("#body-wrapper").loading("stop");
          $("#btn-proses-pesanan").prop("disabled", false);
        }
      })
    }
  })
</script>