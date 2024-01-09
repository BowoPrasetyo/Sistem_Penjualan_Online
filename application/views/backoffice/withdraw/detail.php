<div class="container-fluid">
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
    </div>
    <div class="col-lg-6 col-6">
      <!-- small box -->
      <div class="small-box bg-info bg-info-gradient">
        <div class="inner">
          <h3><?=currency($detail['amount']);?></h3>

          <p>Saldo Ditarik</p>
        </div>
        <div class="icon">
          <i class="ion ion-bag"></i>
        </div>
      </div>
    </div>
    <!-- ./col -->
    <div class="col-lg-6 col-6">
      <!-- small box -->
      <div class="small-box bg-success bg-success-gradient">
        <div class="inner">
          <h3><?=$detail['bank_name'] ?? '-';?></h3>

          <p>Nama Bank</p>
        </div>
        <div class="icon">
          <i class="ion ion-stats-bars"></i>
        </div>
      </div>
    </div>
    <!-- ./col -->
    <div class="col-lg-6 col-6">
      <!-- small box -->
      <div class="small-box bg-warning bg-warning-gradient">
        <div class="inner">
          <h3><?=$detail['account_name'] ?? '-';?></h3>

          <p>Nama Pemilik</p>
        </div>
        <div class="icon">
          <i class="ion ion-person-add"></i>
        </div>
      </div>
    </div>
    <!-- ./col -->
    <div class="col-lg-6 col-6">
      <!-- small box -->
      <div class="small-box bg-danger bg-danger-gradient">
        <div class="inner">
          <h3><?=$detail['account_number'] ?? '-';?></h3>

          <p>Nomor Rekening</p>
        </div>
        <div class="icon">
          <i class="ion ion-pie-graph"></i>
        </div>
      </div>
    </div>
    <!-- ./col -->
    <div class="col-md-12">
      <h4>Riwayat</h4>
        <div class="alert alert-info">
          Tanggal Komisi terkahir pada saat saldo di withdraw : <strong><?=date('Y-m-d', strtotime($detail['created_at']));?></strong>
        </div>
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
                <label for=""><span class="text-white">.</span></label>
                <button type="submit" class="btn btn-block btn-light border">Filter</button>
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
    <div class="col-md-12 mt-3">
      <form action="<?=base_url('backoffice/withdraw/update_status/' . $detail['id']);?>" method="post">
      <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
        <div class="form-group">
          <label for="">Pilih Status</label>
          <select name="status" class="form-control select2" style="width:100%!important">
            <option <?=$detail['status'] == 'pending' ? 'selected' : '' ?> value="pending">Pending</option>
            <option <?=$detail['status'] == 'process' ? 'selected' : '' ?> value="process">Sudah di Transfer</option>
          </select>
        </div>
        <div class="form-group">
          <button type="submit" class="btn btn-block btn-info btn-info-gradient btn-lg">
            Proses
          </button>
        </div>
      </form>
    </div>
    <!-- col -->
  </div>
</div>
<script>
$(document).ready(function() {
  let url = BASE_URL + 'backoffice/transaction/commision?user=<?=$detail['user_id'];?>'
  <?php if($this->input->get('start') && $this->input->get('end')){?>
  url = BASE_URL + 'backoffice/transaction/commision?user=<?=$detail['user_id'];?>&start=<?=$this->input->get('start');?>&end=<?=$this->input->get('end');?>'
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
          "data": "total_commision_affiliator",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              let commision = 0;

              if(row.user_role == 'affiliate') {
                commision = row.total_commision_affiliator
              } else if(row.user_role == 'provider') {
                commision = row.total_commision_provider
              } else if(row.user_role == 'developer') {
                commision = row.total_commision_maintenance
              }
              return currency(commision)
            }
          }
        },
        { "data": "created_at" },
        { "data": "action" ,"orderable": false}
    ]
  });
});  
</script>