<div class="container-fluid">
  <div class="row">

    <div class="col-md-12">
    <?php $this->load->view('backoffice/partials/_alert');?>
      <div class="bg-white border-radius-10 border">
        <div class="p-3">
          <form action="<?=base_url();?>backoffice/user/update_password" method="post" id="form">
          <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
            <div class="row">
              <div class="col-md-12">
                <div class="form-group">
                  <label for="">Password Lama</label>
                  <input type="password" class="form-control form-search form-control-lg" name="password_old" required>
                </div>
              </div>
              <div class="col-md-12">
                <div class="form-group">
                  <label for="">Password Baru</label>
                  <input type="password" class="form-control form-search form-control-lg" name="password" required>
                </div>
              </div>
              <div class="col-md-12">
                <div class="form-group">
                  <label for="">Ulangi Password Baru</label>
                  <input type="password" class="form-control form-search form-control-lg" name="password_confirm" required>
                </div>
              </div>
              <div class="col-md-12">
                <button class="btn btn-info btn-info-gradient btn-block btn-lg">Ubah Password</button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>