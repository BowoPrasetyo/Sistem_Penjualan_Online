<div class="container-fluid">
  <div class="row">
    <div class="col-md-12">
      <?php $this->load->view('backoffice/partials/_alert');?>
      <div class="bg-white border-radius-10 border">
        <div class="p-3">
        <form action="<?=base_url();?>backoffice/setting/payment_midtran_update" method="post" id="form">
            <h4>Production Credential</h4>
            <div class="form-group">
              <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
              <label for="">Client Secret Key</label>
              <input type="text" class="form-control form-search" name="midtrans_client_key" value="<?=$setting_midtrans_client_key;?>">
            </div>
            <div class="form-group">
              <label for="">Server Secret Key</label>
              <input type="text" class="form-control form-search" name="midtrans_server_key" value="<?=$setting_midtrans_server_key;?>">
            </div>
            <h4>Development Credential</h4>
            <div class="form-group">
              <label for="">Client Secret Key</label>
              <input type="text" class="form-control form-search" name="midtrans_client_key_dev" value="<?=$setting_midtrans_client_key_dev;?>">
            </div>
            <div class="form-group">
              <label for="">Server Secret Key</label>
              <input type="text" class="form-control form-search" name="midtrans_server_key_dev" value="<?=$setting_midtrans_server_key_dev;?>">
            </div>
            <div class="form-group">
              <label for="">Midtrans Mode</label>
              <select class="form-control form-search select2" name="midtrans_mode" required>
                <option>Pilih Mode</option>
                <option <?=$setting_midtrans_mode == 'dev' ? 'selected' : '';?> value="dev">Development</option>
                <option <?=$setting_midtrans_mode == 'production' ? 'selected' : '';?> value="production">Production</option>
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