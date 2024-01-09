<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?=$this->data['page_title'];?></title>
  <link href="https://fonts.googleapis.com/css?family=Work+Sans:400,500,600" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css?family=Poppins:300,400,500&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="<?=resource_url();?>plugins/adminlte/plugins/fontawesome-free/css/all.min.css">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
  <link rel="stylesheet" href="<?=resource_url();?>css/style.css">
  <link rel="stylesheet" href="<?=resource_url();?>css/color.css">
  <link rel="stylesheet" href="<?=resource_url();?>css/animate.min.css">
  <link rel="stylesheet" href="<?=resource_url();?>plugins/slick/slick.css"/>
  <link rel="stylesheet" href="<?=resource_url();?>plugins/slick/slick-theme.css"/>

  <script src="<?=resource_url();?>plugins/adminlte/plugins/jquery/jquery.min.js"></script>
  <script src="<?=resource_url();?>plugins/validate/dist/jquery.validate.min.js"></script> 
  <script src="<?=resource_url();?>js/jquery.loading.min.js"></script>
  <script src="<?=resource_url();?>plugins/slick/slick.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>  
  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@9"></script>


  <script>
    const BASE_URL = '<?=base_url();?>'
    const CURRENT_URL = '<?=current_url();?>'
    const INITSTATE  = ['<?=$csrf['name'];?>', '<?=$csrf['hash'];?>']
  </script>
</head>
<body id="body-wrapper">
  <div id="navbar">
    <?php require_once 'partials/navbar.php'; ?>
  </div>

  <?php isset($page) ? $this->load->view($page) : '';?>
    <div id="footer" class="mt-4">
      <div class="bg-light">
        <div class="container">
          <div class="row">
            <div class="col-md-12">
              <div class="p-3 text-center">
                Copyright <a href="<?=base_url();?>"><?=$setting_website_title;?></a> All Reserved.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  <script>
    $(function () {
      $('[data-toggle="tooltip"]').tooltip()
    })
    function currency(totalharga) {
      var	hargastring = totalharga.toString();
      var rupiah = '';
	    var angkarev = totalharga.toString().split('').reverse().join('');
	    for(var i = 0; i < angkarev.length; i++) if(i%3 == 0) rupiah += angkarev.substr(i,3)+'.';
      var hasil = 'Rp. '+rupiah.split('',rupiah.length-1).reverse().join('') + ',-';
      return hasil;
    }

    $(function() {
      let drawerWrapper = $('.menu-drawer-right');
      let content = drawerWrapper.children();

      $('#drawer-menu-right').click(function(e) {
        content.css({
          marginRight: '0px',
        })
      })

      $('#drawer-menu-right-close').click(function(e) {
        content.css({
          marginRight: '-300px',
        })
      })
    })
  </script>
</body>
</html>