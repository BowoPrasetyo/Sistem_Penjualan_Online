<div class="container-fluid">
  <div class="row">
    <div class="col-md-12">
      <div class="mb-3">
        <span class="d-block d-sm-inline">Status: </span>
        <button onclick="filter_status('all')" id="all" class="btn-filter btn btn-info btn-info-gradient">All</button>
        <button onclick="filter_status('waiting_transfer')" id="waiting_transfer" class="btn-filter btn btn-outline-info btn-outline-info-gradient">Belum Bayar</button>
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
                  <th>No. Transaksi</th>
                  <th>Customer</th>
                  <th>Email</th>
                  <th>Pembayaran</th>
                  <th>Biaya COD</th>
                  <th>Total</th>
                  <th>Jenis Pembayaran</th>
                  <th>Status</th>
                  <th>No. Resi</th>
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
<script>
$(document).ready(function() {
  let url = BASE_URL + 'backoffice/transaction/datatable'

  <?php if($parameterData = $this->input->get('data')){?>
  url = BASE_URL + 'backoffice/transaction/datatable?data=<?=$parameterData;?>'
  <?php } ?>

  <?php if($parameterStatus = $this->input->get('status')){?>
  url = BASE_URL + 'backoffice/transaction/datatable?data=&status=<?=$parameterStatus;?>'
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
          "data": "user_first_name",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              return row.user_first_name + ' ' + row.user_last_name
            }
          }
        },
        {
          "data": "user_email",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              return row.user_email
            }
          }
        },
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
          "data": "cash_on_delivery_markup",
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
              return row.cash_on_delivery == 1 ? 'COD' : 'Cash'
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
                  status = '<span class="badge badge-warning bg-warning-gradient p-2">Belum Dibayar</span>'
                  break;
                case 'process':
                  status = '<span class="badge badge-warning bg-warning-gradient p-2">Diproses</span>'
                  break; 
                case 'pending':
                  status = '<span class="badge badge-info p-2">Menunggu Diproses</span>'
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
        {
          "data": "created_at",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              return row.created_at
            }
          }
        },
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