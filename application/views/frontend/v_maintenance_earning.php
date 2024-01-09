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
      <h4>Penghasilan Saya</h4>
      <div class="bg-white border-radius-10 border">
        <div class="p-3">

          <div class="row">

          <div class="col-md-4 mb-3">
              <div class="card bg-success bg-success-gradient">
                <div class="card-body text-white">
                  <div class="d-flex flex-column">
                    <div>
                      <span class="text-light">SALDO AKTIF</span>
                    </div>
                    <div>
                      <h3><?=currency($saldo);?></h3>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="col-md-4 mb-3">
              <div class="card bg-warning bg-warning-gradient">
                <div class="card-body">
                  <div class="d-flex flex-column">
                    <div>
                      <span class="text-dark">PENGHASILAN HARI INI</span>
                    </div>
                    <div>
                      <h3><?=currency($earning_today);?></h3>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="col-md-4 mb-3">
              <div class="card bg-info bg-info-gradient">
                <div class="card-body text-white">
                  <div class="d-flex flex-column">
                    <div>
                      <span class="text-light">TERKAHIR PENARIKAN</span>
                    </div>
                    <div>
                      <h3>-</h3>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="col-md-4">
              <div class="card bg-white">
                <div class="card-body text-dark">
                  <div class="d-flex flex-column">
                    <div>
                      <span class="text-secondary">PENGHASILAN BULAN INI</span>
                    </div>
                    <div>
                      <h3><?=currency($earning_month);?></h3>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="col-md-4">
              <div class="card bg-white">
                <div class="card-body text-dark">
                  <div class="d-flex flex-column">
                    <div>
                      <span class="text-secondary">PENGHASILAN BULAN KEMARIN</span>
                    </div>
                    <div>
                      <h3><?=currency($earning_month_yesterday);?></h3>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            
            <?php if((int) $saldo > 10000 && $can_withdraw):?>
            <div class="col-md-4">
              <div class="card bg-white">
                <div class="card-body text-dark">
                  <div class="d-flex flex-column">
                    <div>
                      <span class="text-secondary">SALDO DAPAT DICARIKAN</span>
                    </div>
                    <div>
                      <form action="<?=base_url();?>member/withdraw" method="post">
                        <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
                        <button type="submit" class="btn btn-success btn-block">
                          Tarik Saldo
                        </button>
                      </form>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <?php endif;?>

          </div>

        </div>
      </div>
    </div>
    <div class="col-md-12 mt-5">
      <h4 class="mb-2">Penjualan Produk</h4>
      <hr/>
      <form action="" method="get">
        <div class="row">
          <div class="col-md-5">
            <div class="form-group">
              <label for=""><strong>Dari</strong></label>
              <input type="date" name="start" class="form-control" required value="<?=$this->input->get('start');?>">
            </div>
          </div>
          <div class="col-md-5">
            <div class="form-group">
              <label for=""><strong>Sampai</strong></label>
              <input type="date" name="end" class="form-control" required value="<?=$this->input->get('end');?>">
            </div>
          </div>
          <div class="col-md-2">
            <div class="form-group">
              <label for=""><span class="text-grey">.</span></label>
              <button type="submit" class="btn btn-block btn-light">Filter</button>
            </div>
          </div>
        </div>
      </form>
      <div class="bg-white border-radius-10 border">
        <div class="p-3">
          <div class="table-responsive">
            <table class="table" id="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>No. Transaksi</th>
                  <th>Komisi</th>
                  <th>Tanggal</th>
                  <th>Aksi</th>
                </tr>
              </thead>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
<link rel="stylesheet" href="<?=resource_url();?>plugins/datatable/dataTables.bootstrap4.min.css">
<script src="<?=resource_url();?>plugins/datatable/jquery.dataTables.min.js"></script>
<script src="<?=resource_url();?>plugins/datatable/dataTables.bootstrap4.min.js"></script> 
<script>
$(document).ready(function() {
  let url = BASE_URL + 'transaction/commision'
  <?php if($this->input->get('start') && $this->input->get('end')){?>
  url = BASE_URL + 'transaction/commision?start=<?=$this->input->get('start');?>&end=<?=$this->input->get('end');?>'
  <?php } ?>

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
        "url": url,
        "dataType": "json",
        "type": "POST",
        "data": function(d) {
          d[INITSTATE[0]] = INITSTATE[1]
        }
    },
    "columns": [
        { "data": "id" },
        { "data": "order_id" },
        {
          "data": "total_commision_maintenance",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              return currency(row.total_commision_maintenance)
            }
          }
        },
        { "data": "created_at" },
        { "data": "action" ,"orderable": false}
    ]
  });
});

function change_to_active(element) {
  $('.btn-filter').each(function(index) {
    if($(this).hasClass('btn-info')) {
      $(this)
        .removeClass('btn-info btn-info-gradient')
        .addClass('btn-outline-info btn-outline-info-gradient')

      $(`#${element}`)
        .removeClass('btn-outline-info btn-outline-info-gradient')
        .addClass('btn-info btn-info-gradient');
    }
  })
}

function filter_status(status) {
  $("#body-wrapper").loading();

  if(status != '') {
    if ($('#table').DataTable().column(3).search() !== status) {
      $('#table').DataTable().column(3)
        .search(status)
        .draw()
        change_to_active(status)
      
      $("#body-wrapper").loading("stop");
      return;
    }
  }

  $("#body-wrapper").loading("stop");
}
</script>