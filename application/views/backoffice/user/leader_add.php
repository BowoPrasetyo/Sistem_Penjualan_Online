<div class="container-fluid">
  <div class="row">

    <div class="col-md-12">
    <?php $this->load->view('backoffice/partials/_alert');?>
      <div class="bg-white border-radius-10 border">
        <div class="p-3">
          <form action="<?=base_url();?>backoffice/user/leader_add_post" method="post" id="form">
          <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
            <div class="row">
              <div class="col-md-6">
                <div class="form-group">
                  <label for="">Nama Depan</label>
                  <input type="text" class="form-control form-seach" name="first_name" required>
                </div>
              </div>
              <div class="col-md-6">
                <div class="form-group">
                  <label for="">Nama Belakang</label>
                  <input type="text" class="form-control form-seach" name="last_name" required>
                </div>
              </div>
              <div class="col-md-12">
                <div class="form-group">
                  <label for="">Email</label>
                  <input type="email" class="form-control form-seach" name="email" required>
                </div>
              </div>
              <div class="col-md-6">
                <div class="form-group">
                  <label for="">Password</label>
                  <input type="password" class="form-control form-seach" name="password" required>
                </div>
              </div>
              <div class="col-md-6">
                <div class="form-group">
                  <label for="">Ulangi Passowrd</label>
                  <input type="password" class="form-control form-seach" name="password_confirm" required>
                </div>
              </div>
              <div class="col-md-12">
                <button class="btn btn-info btn-info-gradient btn-block btn-lg">Simpan</button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>