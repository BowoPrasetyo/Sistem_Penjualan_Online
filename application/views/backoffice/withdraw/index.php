<div class="container-fluid">
  <div class="row">
    <div class="col-md-12">
      <div class="bg-white border-radius-10 border">
        <div class="p-3">
				<div class="float-left">
						<div class="form-group">
							<a href="#" class="btn btn-info btn-info-gradient">Export Data</a>
						</div>
					</div>
          <div class="table-responsive">
            <table class="table" id="table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Member</th>
                  <th>Jumlah</th>
                  <th>Status</th>
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
  $(function() {
    var tableWithdraw = $('#table').DataTable( {
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
          "url": BASE_URL + 'backoffice/withdraw/datatable',
          "dataType": "json",
          "type": "POST",
          "data": function(d) {
            d[INITSTATE[0]] = INITSTATE[1]
          }
      },
      "columns": [
          { "data": "id" },
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
            "data": "status",
            "render": function(data, type, row) {
              if ( type === "sort" || type === 'type' ) {
                return data
              } else {
                let status = row.status
                switch(status) {
                  case 'process':
                    status = '<span class="badge badge-success bg-success-gradient p-2">Sudah Diproses</span>'
                    break; 
                  case 'pending':
                    status = '<span class="badge badge-info p-2">Menunggu Diproses</span>'
                    break;    
                }
                return status
              }
            }
          },
          { "data": "created_at" },
          { "data": "action" ,"orderable": false}
      ]
    });
  })
</script>
