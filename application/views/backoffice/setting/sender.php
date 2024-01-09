<div class="container-fluid">
  <div class="row">
    <div class="col-md-12">
    <?php $this->load->view('backoffice/partials/_alert');?>
      <div class="bg-white border-radius-10 border">
        <div class="p-3">
        <form action="<?=base_url();?>backoffice/setting/sender_update" method="post" id="form">
        <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
        <?php
          $summary  = json_decode($setting_sender_summary, TRUE);
        ?>
        <input type="hidden" name="district_value" id="district_value" value="<?=$setting_sender_district;?>">
        <input type="hidden" name="province_value" id="province_value" value="<?=$summary['province'];?>">
        <input type="hidden" name="city_value" id="city_value" value="<?=$summary['city'];?>">

                <div class="form-group">
                  <label for="">
                    <strong>Pilih Provinsi</strong>
                  </label>
                  <select class="select2" id="province" name="province" style="width:100%">
                    <option disabled selected>Pilih Province</option>
                  </select>
                </div>
                <div class="form-group">
                  <label for="">
                    <strong>Pilih Kota</strong>
                  </label>
                  <select class="select2" id="city" name="city"  style="width:100%">
                    <option disabled selected>Pilih Kota</option>
                  </select>
                </div>
                <div class="form-group">
                  <div class="row">
                    <div class="col-md-12">
                      <label for="">
                      <strong>Pilih Kecamatan</strong>
                      </label>
                      <select class="select2" id="district" name="district"  style="width:100%">
                        <option disabled selected>Pilih Kecamatan</option>
                      </select>
                    </div>
                  </div>
                </div>
              <div class="form-group">
              <button class="btn btn-info btn-info-gradient btn-block btn-lg" type="submit">Simpan</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>
<link href="https://cdn.jsdelivr.net/npm/select2@4.0.13/dist/css/select2.min.css" rel="stylesheet" />
<link href="<?=resource_url();?>css/select2-bootstrap.css" rel="stylesheet" />
<script src="https://cdn.jsdelivr.net/npm/select2@4.0.13/dist/js/select2.min.js"></script>
<script>
  $(document).ready(function() {
    $.fn.select2.defaults.set( "theme", "bootstrap" );

    getProvince();
    
    $('#province').change(function(e) {
      appendCities($(this).val())
      $('#district_value').val($(this).val())
      $('#city').html("<option disabled selected>Pilih Kota</option>")
      $('#district').html("<option disabled selected>Pilih Kecamatan</option>")
    })

    $('#city').change(function(e) {
      appendDistrict($(this).val())
      $('#city_value').val($(this).val())
      $('#district').html("<option disabled selected>Pilih Kecamatan</option>")
    })

    $('#district').change(function(e) {
      $('#district_value').val($(this).val())
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

        $('#province').html(appendProvinces)
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

        $('#city').html(appendCities)
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

        $('#district').html(appendDistricts)
        $(".form-shipping").loading("stop");
      },
      error: function(e) {
        $(".form-shipping").loading("stop");
      }
    })
  }
</script>