<div class="container-fluid">
  <div class="row">
    <div class="col-md-12">
      <div class="bg-white border-radius-10 border">
        <div class="p-3">
        <form action="<?=$edit ? base_url('backoffice/category/update/' . $edit['id']) : base_url('backoffice/category/store');?>" method="post" id="form">
            <div class="form-group">
              <label for="">Nama Kategori</label>
              <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
              <input type="text" class="form-control form-search" name="name" placeholder="Nama Kategori" value="<?=$edit ? $edit['name'] : '';?>">
            </div>
            <div class="form-group">
              <label for="">Deskripsi</label>
              <textarea class="form-control form-search" name="description" placeholder="Deskripsi Kategori" rows="10"><?=$edit ? $edit['description'] : '';?></textarea>
            </div>
            <div class="form-group">
              <label for="">Status</label>
              <select class="form-control select2" id="status" name="status" style="width: 100%;">
                <option>Pilih Status</option>
                  <option <?=$edit['status'] == 'draft' ? 'selected' : ''?> value="draft">Draft</option>
                  <option <?=$edit['status'] == 'publish' ? 'selected' : ''?> value="publish">Publish</option>
              </select>
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