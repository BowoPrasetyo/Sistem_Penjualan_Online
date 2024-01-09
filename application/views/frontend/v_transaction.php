<div id="product-header">
  <section class="bg-info-gradient breadcrumb-area">
    <div class="container">
      <div class="row">
        <div class="col-md-12 breadcrumb-contents">
          <div class="pt-5 pb-5">
            <h2 class="page-title">
              Transaksi Anda
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
<!-- Modal -->
<div class="modal fade" id="exampleModal" tabindex="-1" role="dialog" aria-labelledby="exampleModalLabel" aria-hidden="true">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="exampleModalLabel">Pembayaran Transaksi</h5>
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                <div class="mt-2">
                    <p>Silahkan Transfer ke Rekening di bawah ini</p>
                    <hr/>
                    <p>
                        <h4 id="total_pembayaran"></h4>
                        <h4>BRI</h4>
                        <h4>345201012455536</h4>
                        <h4>a.n Yuspita Noviyanti</h4>
                    </p>
                    <hr/>
                    <p>Jumlah pembayaran harus sesuai dengan nominal yang tercantum agar dapat diproses otomatis</p>
                </div>
            </div>
        </div>
    </div>
</div>

<div id="transaction-lists">
  <div class="container">
    <div class="row">
      <div class="col-md-12">
        <div class="mb-3">
          <span class="d-block d-sm-inline">Status: </span>
          <button onclick="filter_status('all')" id="all" class="btn-filter btn btn-info btn-info-gradient">All</button>
          <button onclick="filter_status('pending')" id="pending" class="btn-filter btn btn-outline-info btn-outline-info-gradient">Pending</button>
          <button onclick="filter_status('process')" id="process" class="btn-filter btn btn-outline-info btn-outline-info-gradient">Diproses</button>
          <button onclick="filter_status('send')" id="send" class="btn-filter btn btn-outline-info btn-outline-info-gradient">Dikirim</button>
          <button onclick="filter_status('complete')" id="complete" class="btn-filter btn btn-outline-info btn-outline-info-gradient">Selesai</button>
        </div>
        <div class="bg-white border-radius-10 border">
          <div class="p-3">
            <div class="table-responsive">
            <table class="table" id="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Invoice</th>
                  <th>Jumlah</th>
                  <th>Biaya COD</th>
                  <th>Total</th>
                  <th>Jenis Pembayaran</th>
                  <th>Status</th>
                  <th>No. Resi</th>
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
</div>
<link rel="stylesheet" href="<?=resource_url();?>plugins/datatable/dataTables.bootstrap4.min.css">
<script src="<?=resource_url();?>plugins/datatable/jquery.dataTables.min.js"></script>
<script src="<?=resource_url();?>plugins/datatable/dataTables.bootstrap4.min.js"></script> 
<?php if($this->data['setting_midtrans_mode'] == 'dev'):?>
  <script type="text/javascript" src="https://app.sandbox.midtrans.com/snap/snap.js" data-client-key="<?=$this->data['setting_midtrans_mode'] == 'dev' ? $this->data['setting_midtrans_client_key_dev'] : $this->data['setting_midtrans_client_key'];?>"></script>
<?php elseif($this->data['setting_midtrans_mode'] == 'production'):?>
  <script type="text/javascript" src="https://app.midtrans.com/snap/snap.js" data-client-key="<?=$this->data['setting_midtrans_mode'] == 'dev' ? $this->data['setting_midtrans_client_key_dev'] : $this->data['setting_midtrans_client_key'];?>"></script>
<?php endif;?>
<script>
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
        "url": BASE_URL + 'transaction/member',
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
          "data": "amount",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              return currency(row.amount)
            }
          }
        },
        {
          "data": "amount",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              return currency(row.cash_on_delivery_markup)
            }
          }
        },
        {
          "data": "amount",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              return currency(parseInt(row.amount) + parseInt(row.cash_on_delivery_markup))
            }
          }
        },
        {
          "data": "cash_on_delivery",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              return row.cash_on_delivery == 1 ? 'COD' : 'Transfer'
            }
          }
        },
        {
          "data": "item_status",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              let status = row.item_status
              switch(status) {
                case 'waiting_transfer':
                  //status = '<span class="badge badge-warning bg-warning-gradient p-2">Belum Dibayar</span>'
                  if(row.cash_on_delivery == 1) {
                    status = '<span class="badge badge-info p-2">Menunggu</span>'
                  } else {
                    // if(parseInt(row.expired_time) > parseInt(row.current_time)) {
                    //   status = `<span onclick="payment_transaction('${row.snap_token}')" class="badge badge-warning bg-warning-gradient p-2">Bayar</span>`
                    // } else {
                    //   status = '<span class="badge badge-danger bg-danger-gradient p-2">Expired</span>'
                    // }
                      status = `<span onclick="show_rekening('${currency(row.amount)}')" class="badge badge-warning bg-warning-gradient p-2">Bayar</span>`
                  }
                  break;
                case 'process':
                  status = '<span class="badge badge-warning bg-warning-gradient p-2">Diproses</span>'
                  break; 
                case 'pending':
                  status = '<span class="badge badge-info p-2">Menunggu</span>'
                  break;    
                case 'send':
                  status = '<span class="badge badge-primary p-2">Dikirim</span>'
                  break; 
                case 'complete':
                  status = '<span class="badge badge-success bg-success-gradient p-2">Selesai</span>'
                  break;    
                case 'cancel':
                  status = '<span class="badge badge-danger bg-danger-gradient p-2">Dibatalkan</span>'
                  break;  
              }
              return status
            }
          }
        },
        { "data": "no_receipt" },
        { "data": "action" ,"orderable": false}
    ]
  });
});

function show_rekening(total = 0)
{
    $('#total_pembayaran').html("Total Pembayaran : " + total)
    $('#exampleModal').modal('show')
}

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

function payment_transaction(token = null) {
  if(token != null) {
    snap.pay(token, {
      onSuccess: function(result){console.log('success');console.log(result);},
      onPending: function(result){console.log('pending');console.log(result);},
      onError: function(result){console.log('error');console.log(result);},
      onClose: function(){
        console.log('sds')
      }
    })
  }
}
</script>