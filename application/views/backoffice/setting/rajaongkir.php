<div class="container-fluid">
  <div class="row">
    <div class="col-md-12">
    <?php $this->load->view('backoffice/partials/_alert');?>
      <div class="bg-white border-radius-10 border">
        <div class="p-3">
        <form action="<?=base_url();?>backoffice/setting/rajaongkir_update" method="post" id="form">
        <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
            <div class="form-group">
              <label for="">TIpe Akun</label>
              <select class="form-control form-search select2" name="rajaongkir_account_type" required>
                <option>Pilih Tipe Akun</option>
                <option <?=$setting_rajaongkir_account_type == 'starter' ? 'selected' : '';?> value="starter">Starter</option>
                <option <?=$setting_rajaongkir_account_type == 'basic' ? 'selected' : '';?> value="basic">Basic</option>
                <option <?=$setting_rajaongkir_account_type == 'api' ? 'selected' : '';?> value="api">Pro</option>
              </select>
            </div>
            <div class="form-group">
              <label for="">API Key</label>
              <input type="text" class="form-control form-search" name="rajaongkir_api_key" value="<?=$setting_rajaongkir_api_key;?>" required>
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