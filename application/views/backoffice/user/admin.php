<div class="container-fluid">
  <div class="row">

    <div class="col-md-12">
      <div class="mb-3">
        <a href="<?=base_url();?>backoffice/user/admin_add" class="btn btn-primary float-right">Tambah Admin</a>
        <div class="clearfix"></div>
      </div>
      
      <div class="bg-white border-radius-10 border">
        <div class="p-3">
          <div class="clearfix"></div>
          <div class="table-responsive">
            <table class="table" id="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Nama</th>
                  <th>Email</th>
                  <!-- <th>Aksi</th> -->
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
  let url = BASE_URL + 'backoffice/user/admins'

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
        {
          "data": "first_name",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              return row.first_name + ' ' + row.last_name
            }
          }
        },
        {
          "data": "email",
          "render": function(data, type, row) {
            if ( type === "sort" || type === 'type' ) {
              return data
            } else {
              return row.email
            }
          }
        },
        // { "data": "action" ,"orderable": false}
    ]
  });
});

function change_to_active(element) {
  $('#item_status').val(element)
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