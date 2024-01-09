<div class="container-fluid">
  <div class="row">
    <div class="col-md-12">
      <div class="bg-white border-radius-10 border">
        <div class="p-3">
          <div class="table-responsive">
          <table class="table" id="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Produk</th>
                <th>Harga</th>
                <th>Stok</th>
                <th>Berat (gr)</th>
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
  $('#table').DataTable( {
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
    "ajax":{
        "url": BASE_URL + 'backoffice/product/dataList',
        "dataType": "json",
        "type": "POST",
        "data": function(d) {
          d[INITSTATE[0]] = INITSTATE[1]
        }
    },
    "columns": [
        { "data": "id" },
        { "data": "title" },
        { "data": "price" },
        { "data": "stock" },
        { "data": "weight" },
        { "data": "action" ,"orderable": false}
    ]
  });
});
</script>