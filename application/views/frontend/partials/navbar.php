<div>
  <div class="container-fluid border-bottom-theme bg-white">
    <div class="row d-none d-lg-block">
      <div class="col-md-12 bg-theme">
        <div class="d-flex justify-content-between pl-5 pr-5 pb-1 pt-1">
          <div class="text-white">
            <?=$this->data['top_description'];?>
          </div>
          <div class="w-s">
            <!--<a href="" class="text-white mr-2">Cara Belanja</a>-->
            <!--<a href="" class="text-white mr-2">Cek Ongkir</a>-->
            <!--<a href="" class="text-white mr-2">Afiliasi</a>-->
            <a href="<?=base_url();?>payment_confirmation" class="text-white"></a>
          </div>
        </div>
      </div>
    </div>
    <div class="row">
      <div class="col-md-12 d-none d-lg-block">
        <div class="d-flex justify-content-between pl-5 pr-5">
          <div class="align-self-center w-15">
            <h4>
              <a class="text-theme" href="<?=base_url();?>">
                <?php if(isset($setting_website_logo) && $setting_website_logo != '' && $setting_website_logo != null):?>
                  <img src="<?=$setting_website_logo;?>" class="img-fluid mt-2" alt="">
                <?php else:?>
                  <?=$this->data['title'];?>
                <?php endif;?>
              </a>
            </h4>
          </div>
          <div class="pl-4 pr-4 pb-3 pt-3 align-self-center w-65 w-md-55 border-left border-right">
            <form action="<?=base_url();?>home/search">
              <div class="d-flex">
                <div class="w-90">
                  <input type="text" name="q" maxlength="30"class="form-control form-search border-right-none" placeholder="<?=$this->input->get('q') ?? $this->data['search_placeholder'];?>">
                </div>
                <div class="w-10">
                  <button type="submit" class="btn btn-theme btn-theme-gradient btn-lg btn-block btn-search">
                    <img src="<?=resource_url();?>img/search.svg" width="20" alt="">
                  </button>
                </div>
              </div>
              
            </form>
          </div>
          <div class="align-self-center w-25">
            <?php if(!$this->data['is_login']):?>
            <div class="d-flex">
              <div class="align-self-center w-50 text-theme">
                <a href="<?=base_url('auth/register?redirect=' . current_url());?>" class="btn bg-white text-theme">
                  Daftar
                </a>
              </div>
              <div class="align-self-center w-50">
                <a href="<?=base_url('auth/login?redirect=' . current_url());?>" class="btn btn-outline-theme btn-outline-theme-gradient">
                  Masuk
                </a>
              </div>
            </div>
            <?php else:?>
            <div class="d-flex">
              <div class="align-self-center w-25 text-theme">
                <button class="btn bg-white" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" id="hover-notification">
                  <img src="<?=resource_url();?>img/bell.svg" width="30" alt="">
                </button>
                <div class="dropdown-menu dropdown-menu-right">
                  <?php foreach($user_notifications as $key => $notification):?>
                  <a href="" class="dropdown-item" type="button">
                    <small class="text-muted"><?=date('d F Y', strtotime($notification->created_at));?></small><br/>
                    <span><?=$notification->content;?></span>
                  </a>
                  <?php if($key < count($user_notifications) - 1):?>
                    <hr/>
                  <?php endif;?>
                  <?php endforeach;?>
                </div>
              </div>
              <div class="align-self-center w-25 text-theme" data-toggle="tooltip" data-placement="top" title="Transaksi">
                <a href="<?=base_url();?>member/transaction" class="btn bg-white " id="hover-transaction">
                  <img src="<?=resource_url();?>img/pay.svg" width="30" alt="">
                </a>
              </div>
              <div class="align-self-center w-25 text-theme" data-toggle="tooltip" data-placement="top" title="Keranjang">
                <a href="<?=base_url();?>home/cart" class="btn bg-white " id="hover-basket">
                  <img src="<?=resource_url();?>img/basket-blue.svg" width="24" alt="">
                </a>
              </div>
              <div class="align-self-center w-25">
                <button class="btn btn-theme btn-theme-gradient" id="hover-account" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                  <img src="<?=resource_url();?>img/user.svg" width="30" alt="">
                </button>
                <div class="dropdown-menu dropdown-menu-right">
                  <a href="<?=base_url();?>member/my_profile" class="dropdown-item" type="button">Profil</a>
                  <?php if(
                      $this->data['user']->role == 'affiliate' || 
                      $this->data['user']->role == 'developer' || 
                      $this->data['user']->role == 'provider' ||
                      $this->data['user']->role == 'leader' ||
                      $this->data['user']->role == 'cs' ||
                      $this->data['user']->role == 'mediator'
                  ):?>
                    <a href="<?=base_url();?>member/my_earning" class="dropdown-item" type="button">Penghasilan Saya</a>
                  <?php endif;?>
                  <a class="dropdown-item" type="button">Pengaturan</a>
                  <a href="<?=base_url();?>auth/logout" class="dropdown-item" type="button">Keluar</a>
                </div>
              </div>
            </div>
            <?php endif;?>

          </div>
        </div>
      </div>
      <!-- Mobile Nav -->
      <div class="col-md-12 d-lg-none">
        <div class="d-flex justify-content-between">

          <div class="align-self-center w-15">
            <button class="btn bg-white">
              <img src="<?=resource_url();?>img/switch.svg" width="30" alt="">
            </button>
          </div>

          <div class="pb-3 pt-3 align-self-center w-70 text-center">
            <span class="brand-title text-bold">
              <a class="text-theme" href="<?=base_url();?>"><?=$this->data['title'];?></a>
            </span>
          </div>

          <div class="align-self-center w-15">
            <button class="btn btn-theme" id="drawer-menu-right">
              <img src="<?=resource_url();?>img/user.svg" width="30" alt="">
            </button>
          </div>

        </div>
      </div>

      <!-- End Mobile -->
    </div>
  </div>
  <div class="menu-drawer-right d-lg-none">
    <div class="bg-white content border-left">
      <div class="p-3">
        <button class="btn btn-warning btn-block" id="drawer-menu-right-close">&times; Close</button>
        <hr/>
        <?php if(!$this->data['is_login']):?>
          <a href="<?=base_url();?>auth/login" class="text-theme btn btn-outline-theme btn-block text-left mb-2">Masuk</a>
          <a href="<?=base_url();?>auth/register" class="text-theme btn btn-outline-theme btn-block text-left mb-2">Daftar</a>
        <?php else:?>
          <a href="<?=base_url();?>member/my_profile" class="text-theme btn btn-outline-theme btn-block text-left mb-2">Profile</a>
          <a href="<?=base_url();?>member/transaction" class="text-theme btn btn-outline-theme btn-block text-left mb-2">Transaksi</a>
          <?php if($this->data['user']->role == 'affiliate' || $this->data['user']->role == 'developer' || $this->data['user']->role == 'provider'):?>
          <a href="<?=base_url();?>member/my_earning" class="text-theme btn btn-outline-theme btn-block text-left mb-2">Penghasilan Saya</a>
          <?php else:?>
            <a href="<?=base_url();?>member/my_profile" class="text-theme btn btn-outline-theme btn-block text-left mb-2">Daftar Afiliasi</a>
          <?php endif;?>
          <a href="<?=base_url();?>auth/logout" class="text-theme btn btn-outline-theme btn-block text-left mb-2">Keluar</a>
        <?php endif;?>
      </div>
    </div>
  </div>  
</div>