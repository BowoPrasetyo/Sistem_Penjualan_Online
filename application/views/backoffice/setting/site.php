<div class="container-fluid">
  <div class="row">
    <div class="col-md-12">
      <?php $this->load->view('backoffice/partials/_alert');?>
      <div class="bg-white border-radius-10 border">
        <div class="p-3">
        <form action="<?=base_url();?>backoffice/setting/site_update" method="post" id="form">
        <input type="hidden" name="<?=$csrf['name'];?>" value="<?=$csrf['hash'];?>" />
            <div class="form-group">
              <label for="">Judul Website</label>
              <input type="text" class="form-control form-search" name="website_title" value="<?=$setting_website_title;?>">
            </div>
            <div class="form-group">
              <label for="">Top Headline</label>
              <input type="text" class="form-control form-search" name="website_top_headline" value="<?=$setting_website_top_headline;?>">
            </div>
            <div class="form-group">
              <label for="">Deskripsi Website</label>
              <textarea  class="form-control form-search" name="website_description" rows="10"><?=$setting_website_description;?></textarea>
            </div>
            <div class="form-group">
              <label for="">Placeholder Pencarian</label>
              <input type="text" class="form-control form-search" name="website_search_placeholder" value="<?=$setting_website_search_placeholder;?>">
            </div>
            <div class="form-group">
              <label for="">Logo Website</label>
              <input type="file" class="form-control form-search" name="website_logo" value="<?=$setting_website_logo;?>">
            </div>
            <div class="form-group">
              <label for="">Jasa Pengiriman</label><br/>
              <small>Pisahkan dengan koma tanpa Spasi</small>
              <textarea class="form-control form-search" name="website_shipping_courier" rows="10"><?=$setting_website_shipping_courier;?></textarea>
            </div><div class="form-group">
              <label for="">Maintenance Mode</label>
             <select class="form-control select2"  name="maintenance_mode">
               <option <?=$setting_maintenance_mode == 'false' ? 'selected' : '';?> value="false">Tidak</option>
               <option <?=$setting_maintenance_mode == 'true' ? 'selected' : '';?> value="true">Ya</option>
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