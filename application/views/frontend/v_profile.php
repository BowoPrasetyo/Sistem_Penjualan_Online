<div class="clearfix"></div>
<div class="mt-4"></div>
<div class="container">
  <div class="row">
    <div class="col-md-12">
      <?php if($this->session->flashdata('success')){ ?>
        <div class="alert alert-success">
          <?php echo $this->session->flashdata('success'); ?>
        </div>
      <?php }else if($this->session->flashdata('err')){  ?>
        <div class="alert alert-danger">
          <?php echo $this->session->flashdata('err'); ?>
        </div>
      <?php }else if($this->session->flashdata('warning')){  ?>
        <div class="alert alert-warning">
          <?php echo $this->session->flashdata('warning'); ?>
        </div>
      <?php }else if($this->session->flashdata('info')){  ?>
        <div class="alert alert-info">
          <?php echo $this->session->flashdata('info'); ?>
        </div>
      <?php } ?>
      <h4 class="mb-3">Proile Saya</h4>
      <div class="bg-white border-left border-right border-top border-bottom " id="tabs">
        <nav>
          <div class="nav nav-tabs nav-fill" id="nav-tab" role="tablist">
            <a class="nav-item nav-link active" id="nav-description-tab" data-toggle="tab" href="#nav-description" role="tab" aria-controls="nav-description" aria-selected="true">Profil</a>
            <a class="nav-item nav-link" id="nav-ulasan-tab" data-toggle="tab" href="#nav-ulasan" role="tab" aria-controls="nav-ulasan" aria-selected="false">Password</a>
          </div>
        </nav>
        <div class="p-3">
          <div class="tab-content" id="nav-tabContent">
            <!-- Deskripsi -->
            <div class="tab-pane fade show active" id="nav-description" role="tabpanel" aria-labelledby="nav-description-tab">
              <form action="<?=base_url();?>member/update_profile" method="post">
              <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
                <div class="row">
                  <div class="col-md-6">
                    <div class="form-group">
                      <label for=""><strong>Nama Depan</strong></label>
                      <input type="text" name="first_name" class="form-control form-search" value="<?=$user->first_name;?>" autocomplete="off">
                    </div>
                  </div>
                  <div class="col-md-6">
                    <div class="form-group">
                      <label for=""><strong>Nama Belakang</strong></label>
                      <input type="text" name="last_name" class="form-control form-search" value="<?=$user->last_name;?>" autocomplete="off">
                    </div>
                  </div>
                </div>
                <div class="row">
                  <div class="col-md-6">
                    <div class="form-group">
                      <label for=""><strong>Email</strong></label>
                      <input type="email" name="email" readonly class="form-control form-search" value="<?=$user->email;?>">
                    </div>
                  </div>
                  <div class="col-md-6">
                    <div class="form-group">
                      <label for=""><strong>No. HP</strong></label>
                      <input type="text" name="phone" class="form-control form-search" value="<?=$user->phone ?? '';?>" autocomplete="off">
                    </div>
                  </div>
                </div>
                <div class="row">
                  <div class="col-md-6">
                    <div class="form-group">
                      <label for=""><strong>Nama Bank</strong></label>
                      <input type="text" name="bank_name" class="form-control form-search" value="<?=$user->bank_name;?>" autocomplete="off">
                    </div>
                  </div>
                  <div class="col-md-6">
                    <div class="form-group">
                      <label for=""><strong>Pemilik Rekening</strong></label>
                      <input type="text" name="account_name" class="form-control form-search" value="<?=$user->account_name ?? '';?>" autocomplete="off">
                    </div>
                  </div>
                </div>
                <div class="row">
                  <div class="col-md-12">
                    <div class="form-group">
                      <label for=""><strong>No. Rekening</strong></label>
                      <input type="text" name="account_number" class="form-control form-search" value="<?=$user->account_number ?? '';?>" autocomplete="off">
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <div class="alert alert-info">
                    Referral Kamu : <strong><?=base_url('landing?reff=' . $user->referral);?></strong>
                  </div>
                  <span>Isi detail Rekening untuk penarikan Penghasilan.</span>
                </div>
                <div class="form-group">
                  <button type="submit" class="btn btn-info btn-block btn-info-gradient">Update</button>
                </div>
              </form>
            </div>
            <div class="tab-pane fade show" id="nav-ulasan" role="tabpanel" aria-labelledby="nav-ulasan-tab">
              <form action="<?=base_url();?>member/update_password" method="post">
              <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
                <div class="row">
                  <div class="col-md-12">
                    <div class="form-group">
                      <label for=""><strong>Password Lama</strong></label>
                      <input type="password" name="password_old" class="form-control form-search" required>
                    </div>
                  </div>
                  <div class="col-md-12">
                    <div class="form-group">
                      <label for=""><strong>Password Baru</strong></label>
                      <input type="password" name="password" class="form-control form-search" required>
                    </div>
                  </div>
                  <div class="col-md-12">
                    <div class="form-group">
                      <label for=""><strong>Ulangi Password Baru</strong></label>
                      <input type="password" name="password_confirm" class="form-control form-search" required>
                    </div>
                  </div>
                </div>
                <div class="form-group">
                  <button type="submit" class="btn btn-info btn-block btn-info-gradient">Update</button>
                </div>
              </form>
            </div>
            <div class="tab-pane fade show" id="nav-diskusi" role="tabpanel" aria-labelledby="nav-diskusi-tab">
              <div class="row">
                <div class="col-md-4">
                  <div class="card bg-white">
                    <div class="card-body text-dark">
                      <div class="d-flex flex-column">
                        <div>
                          <span class="text-secondary">UTAMA</span>
                        </div>
                        <div>
                          <h3>Rumah</h3>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div class="col-md-4">
                  <div class="card bg-white">
                    <div class="card-body text-dark">
                      <div class="d-flex flex-column">
                        <div>
                          <span class="text-secondary">TAMBAHAN</span>
                        </div>
                        <div>
                          <h3>Alamat Rumah</h3>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div class="col-md-4">
                  <div class="card bg-white">
                    <div class="card-body text-dark">
                      <div class="d-flex flex-column">
                        <div>
                          <span class="text-secondary">UTAMA</span>
                        </div>
                        <div>
                          <h3>Alamat Rumah</h3>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

              </div>
              <hr/> 
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>