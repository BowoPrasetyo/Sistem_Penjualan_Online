<div class="clearfix"></div>
<div class="mt-4"></div>
<div class="container">
  <div class="row">
    <div class="col-md-12">
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
      <h4 class="mb-3">Affiliator Saya</h4>
      <div class="bg-white border-left border-right border-top border-bottom " id="tabs">
        <nav>
          <div class="nav nav-tabs nav-fill" id="nav-tab" role="tablist">
            <a class="nav-item nav-link active" id="nav-description-tab" data-toggle="tab" href="#nav-description" role="tab" aria-controls="nav-description" aria-selected="true">Affiliator</a>
            <a class="nav-item nav-link" id="nav-ulasan-tab" data-toggle="tab" href="#nav-ulasan" role="tab" aria-controls="nav-ulasan" aria-selected="false">Tambah</a>
          </div>
        </nav>
        <div class="p-3">
          <div class="tab-content" id="nav-tabContent">
            <!-- Deskripsi -->
            <div class="tab-pane fade show active" id="nav-description" role="tabpanel" aria-labelledby="nav-description-tab">
              <div class="table-responsive">
                <table class="table" id="table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Nama Affiliator</th>
                      <th>Email</th>
                      <th>Tgl. Gabung</th>
                    </tr>
                  </thead>
                </table>
              </div>
            </div>
            <div class="tab-pane fade show" id="nav-ulasan" role="tabpanel" aria-labelledby="nav-ulasan-tab">
              <form action="<?=base_url('auth/doRegisterAffiliator?redirect=' . $this->input->get('redirect'));?>" method="post" id="form">
                <input type="hidden" id="captcha-validate" value="0">
                  <div class="form-group">
                    <label for="">
                      <strong>Nama Depan</strong>
                    </label>
                    <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
                    <input type="text" name="first_name" class="form-control form-search" placeholder="Masukan Nama Depan" required autocomplete="off">
                  </div>
                  <div class="form-group">
                    <label for="">
                      <strong>Nama Belakang</strong>
                    </label>
                    <input type="text" name="last_name" class="form-control form-search" placeholder="Masukan Nama Belakang"  autocomplete="off">
                  </div>
                  <div class="form-group">
                    <label for="">
                      <strong>Nomor Handphone</strong>
                    </label>
                    <input type="text" name="phone" class="form-control form-search" placeholder="Masukan No. Handphone" required autocomplete="off">
                  </div>
                  <div class="form-group">
                    <label for="">
                      <strong>Email</strong>
                    </label>
                    <input type="email" name="email" class="form-control form-search" placeholder="Masukan Email" required autocomplete="off">
                  </div>
                  <div class="form-group">
                    <label for="">
                      <strong>Password</strong>
                    </label>
                    <input type="password" id="password" name="password" class="form-control form-search" placeholder="Masukan Password" required autocomplete="off">
                  </div>
                  <div class="form-group">
                    <label for="">
                      <strong>Ulangi Password</strong>
                    </label>
                    <input type="password" name="password_confirm" class="form-control form-search" placeholder="Masukan Ulang Password" required autocomplete="off">
                  </div>
                  <div class="form-group">
                    <div class="slidercaptcha card">
                        <div class="card-header">
                            <span>Verifikasi</span>
                        </div>
                        <div class="card-body mb-5"><div id="captcha"></div></div>
                    </div>
                  </div>
                  <div class="form-group">
                    <button disabled id="btn" class="btn btn-info btn-block btn-lg border-radius-none btn-info-gradient">Daftar</button>
                  </div>
                </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
<link rel="stylesheet" href="<?=resource_url();?>plugins/datatable/dataTables.bootstrap4.min.css">
<script src="<?=resource_url();?>plugins/datatable/jquery.dataTables.min.js"></script>
<script src="<?=resource_url();?>plugins/datatable/dataTables.bootstrap4.min.js"></script> 
<script type="text/javascript">
$(document).ready(function() {
  var table = $('#table').DataTable( {
    "language": {
        "search": "Cari",
        "lengthMenu": "Tampilkan _MENU_ baris per halaman",
        "zeroRecords": "Data tidak ditemukan",
        "info": "Menampilkan _PAGE_ dari _PAGES_",
        "infoEmpty": "Tidak ada data yang ditampilkan ",
        "infoFiltered": "(pencarian dari _MAX_ total records)",
        "paginate": {
            "first":      "Pertama",
            "last":       "Terakhir",
            "next":       "Selanjutnya",
            "previous":   "Sebelum"
        },
    },
    "processing": true,
    "serverSide": true,
    "order": [[ 0, "desc" ]],
    "ajax":{
        "url": BASE_URL + 'user/affiliators',
        "dataType": "json",
        "type": "POST",
        "data": function(d) {
          d[INITSTATE[0]] = INITSTATE[1]
        }
    },
    "columns": [
        { "data": "id" },
        {
          "data": "first_name",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              return `${row.first_name} ${row.last_name}`
            }
          }
        },
        { "data": "email" },
        { "data": "created_at" },
    ]
  });  
});
</script>
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.1/css/all.css" integrity="sha384-50oBUHEmvpQ+1lW4y57PTFmhCaXp0ML5d60M1M7uH2+nqUivzIebhndOJK28anvf" crossorigin="anonymous">
<link href="<?=resource_url();?>css/jquerysctipttop.css" rel="stylesheet" type="text/css">
<link href="<?=resource_url();?>css/slidercaptcha.css" rel="stylesheet" />
<script src="<?=resource_url();?>js/longbow.slidercaptcha.js"></script>
<script>
  let trycaptcha = 0;
  
  $('#captcha').sliderCaptcha({
    width: 250,
    height: 150,
    sliderL: 42,
    sliderR: 9,
    offset: 5, 
    loadingText: 'Loading...',
    failedText: 'Coba Lagi',
    barText: 'Geser untuk Verifikasi',
    repeatIcon: 'fa fa-repeat',
    maxLoadCount: 3,
    localImages: function () { // uses local images instead
      return 'images/Pic' + Math.round(Math.random() * 4) + '.jpg';
    },
    onSuccess:function() {
      trycaptcha++
      $('#captcha-validate').val("1")
      $('#btn').prop("disabled", false)
    },
    onFail: function() {
      trycaptcha++
      $('#captcha-validate').val("0")
      $('#btn').prop("disabled", true)
    }
  });

  if($("#form").length > 0 ) {
    $("#btn-proses-pesanan").removeAttr("disabled");
    $("#form").validate({
      rules: {
        first_name: {
          required: true,
          minlength: 2
        },
        registrasi: {
          required: true,
        },
        last_name: {
          required: true,
          minlength: 2
        },
        email: {
          required: true,
          minlength: 2,
          email: true
        },
        phone: {
          required: true,
          minlength: 10,
          number: true
        },
        password: {
          required: true,
          minlength: 8
        },
        password_confirm: {
          required: true,
          equalTo: "#password"
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
      submitHandler: function(form) {
        if($('#captcha-validate').val() == "1" && trycaptcha > 0) {
          $('#btn').prop("disabled", true)
          form.submit()
        }
      },
    });
  }  
</script>