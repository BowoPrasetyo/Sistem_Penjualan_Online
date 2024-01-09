
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title><?=$page_title;?></title>
  <!-- Tell the browser to be responsive to screen width -->
  <link href="https://fonts.googleapis.com/css?family=Poppins:300,400,500&display=swap" rel="stylesheet">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- Font Awesome -->
  <link rel="stylesheet" href="<?=resource_url();?>plugins/adminlte/plugins/fontawesome-free/css/all.min.css">
  <!-- Ionicons -->
  <link rel="stylesheet" href="<?=resource_url();?>plugins/adminlte/https://code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css">
  <!-- Tempusdominus Bbootstrap 4 -->
  <link rel="stylesheet" href="<?=resource_url();?>plugins/adminlte/plugins/tempusdominus-bootstrap-4/css/tempusdominus-bootstrap-4.min.css">
  <!-- iCheck -->
  <link rel="stylesheet" href="<?=resource_url();?>plugins/adminlte/plugins/icheck-bootstrap/icheck-bootstrap.min.css">
  <!-- JQVMap -->
  <link rel="stylesheet" href="<?=resource_url();?>plugins/adminlte/plugins/jqvmap/jqvmap.min.css">
  <!-- Theme style -->
  <link rel="stylesheet" href="<?=resource_url();?>plugins/adminlte/dist/css/adminlte.min.css">
  <!-- overlayScrollbars -->
  <link rel="stylesheet" href="<?=resource_url();?>plugins/adminlte/plugins/overlayScrollbars/css/OverlayScrollbars.min.css">
  <!-- Daterange picker -->
  <link rel="stylesheet" href="<?=resource_url();?>plugins/adminlte/plugins/daterangepicker/daterangepicker.css">
  <!-- summernote -->
  <link rel="stylesheet" href="<?=resource_url();?>plugins/adminlte/plugins/summernote/summernote-bs4.css">
  <link rel="stylesheet" href="<?=resource_url();?>plugins/adminlte/plugins/select2/css/select2.min.css">
  <link rel="stylesheet" href="<?=resource_url();?>css/select2-bootstrap.css">
  <link rel="stylesheet" href="<?=resource_url();?>css/style.css">
  <link rel="stylesheet" href="<?=resource_url();?>plugins/datatable/dataTables.bootstrap4.min.css">
  <!-- Google Font: Source Sans Pro -->
  <link href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700" rel="stylesheet">
  <style>
    #tabs .nav-tabs .nav-item.show .nav-link, .nav-tabs .nav-link.active {
        color: #17a2b8 !important;
        background-color: transparent;
        border-color: transparent transparent #17a2b8 !important;
        border-bottom: 4px solid !important;
        font-size: 20px;
        font-weight: bold;
    }
    #tabs .nav-tabs .nav-link {
        border: 1px solid transparent;
        border-top-left-radius: .25rem;
        border-top-right-radius: .25rem;
        color: #5a5a5a !important;
        font-size: 20px;
    }

    #tabs .nav-tabs .nav-link.active {
      color: #17a2b8 !important;
    }
  </style>

  <!-- jQuery -->
  <script src="<?=resource_url();?>plugins/adminlte/plugins/jquery/jquery.min.js"></script>
  <!-- jQuery UI 1.11.4 -->
  <script src="<?=resource_url();?>plugins/adminlte/plugins/jquery-ui/jquery-ui.min.js"></script>
  <!-- Resolve conflict in jQuery UI tooltip with Bootstrap tooltip -->
  <script>
    $.widget.bridge('uibutton', $.ui.button)
  </script>
  <!-- Bootstrap 4 -->
  <script src="<?=resource_url();?>plugins/adminlte/plugins/bootstrap/js/bootstrap.bundle.min.js"></script>
  <!-- ChartJS -->
  <script src="<?=resource_url();?>plugins/adminlte/plugins/chart.js/Chart.min.js"></script>
  <!-- Sparkline -->
  <script src="<?=resource_url();?>plugins/adminlte/plugins/sparklines/sparkline.js"></script>
  <!-- JQVMap -->
  <script src="<?=resource_url();?>plugins/adminlte/plugins/jqvmap/jquery.vmap.min.js"></script>
  <script src="<?=resource_url();?>plugins/adminlte/plugins/jqvmap/maps/jquery.vmap.usa.js"></script>
  <!-- jQuery Knob Chart -->
  <script src="<?=resource_url();?>plugins/adminlte/plugins/jquery-knob/jquery.knob.min.js"></script>
  <!-- daterangepicker -->
  <script src="<?=resource_url();?>plugins/adminlte/plugins/moment/moment.min.js"></script>
  <script src="<?=resource_url();?>plugins/adminlte/plugins/daterangepicker/daterangepicker.js"></script>
  <!-- Tempusdominus Bootstrap 4 -->
  <script src="<?=resource_url();?>plugins/adminlte/plugins/tempusdominus-bootstrap-4/js/tempusdominus-bootstrap-4.min.js"></script>
  <!-- Summernote -->
  <script src="<?=resource_url();?>plugins/adminlte/plugins/summernote/summernote-bs4.min.js"></script>
  <!-- overlayScrollbars -->
  <script src="<?=resource_url();?>plugins/adminlte/plugins/overlayScrollbars/js/jquery.overlayScrollbars.min.js"></script>
  <!-- AdminLTE App -->
  <script src="<?=resource_url();?>plugins/adminlte/dist/js/adminlte.js"></script>
  <!-- AdminLTE dashboard demo (This is only for demo purposes) -->
  <script src="<?=resource_url();?>plugins/adminlte/dist/js/pages/dashboard.js"></script>
  <!-- AdminLTE for demo purposes -->
  <script src="<?=resource_url();?>js/jquery.loading.min.js"></script>
  <script src="<?=resource_url();?>plugins/adminlte/dist/js/demo.js"></script>
  <script src="<?=resource_url();?>plugins/adminlte/plugins/select2/js/select2.full.min.js"></script>  
  <script src="<?=resource_url();?>plugins/validate/dist/jquery.validate.min.js"></script>  
  <script src="<?=resource_url();?>plugins/datatable/jquery.dataTables.min.js"></script>
  <script src="<?=resource_url();?>plugins/datatable/dataTables.bootstrap4.min.js"></script>  
  <script>
    const BASE_URL = '<?=base_url();?>'
    const CURRENT_URL = '<?=current_url();?>'
    const RESOURCE_URL = '<?=resource_url();?>'
    const INITSTATE  = ['<?=$csrf['name'];?>', '<?=$csrf['hash'];?>']
  </script>
</head>
<body class="hold-transition sidebar-mini layout-fixed " id="loading-wrapper">
<div class="wrapper">

  <!-- Navbar -->
  <nav class="main-header navbar navbar-expand navbar-white navbar-light">
    <!-- Left navbar links -->
    <ul class="navbar-nav">
      <li class="nav-item">
        <a class="nav-link" data-widget="pushmenu" href="#"><i class="fas fa-bars"></i></a>
      </li>
    </ul>
    <!-- Right navbar links -->
    <ul class="navbar-nav ml-auto">
      <li class="nav-item">
        <a class="nav-link" href="<?=base_url();?>backoffice/user/password">
          <i class="fas fa-user"></i> Ubah Password
        </a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="<?=base_url();?>backoffice/auth/logout">
          <i class="fas fa-sign-out-alt"></i>
        </a>
      </li>
    </ul>
  </nav>
  <!-- /.navbar -->
  <?php require_once 'partials/sidebar.php'; ?>
  <!-- Content Wrapper. Contains page content -->
  <div class="content-wrapper">
    <!-- Content Header (Page header) -->
    <div class="content-header">
      <div class="container-fluid">
        <div class="row mb-2">
          <div class="col-sm-6">
            <h1 class="m-0 text-dark"><?=$page_title;?></h1>
          </div><!-- /.col -->
          <div class="col-sm-6">
            <ol class="breadcrumb float-sm-right">
              <?php if(isset($breadcrumbs)):?>
                <?php foreach($breadcrumbs as $key => $value):?>
                  <?php if((int) $key + 1 != count($breadcrumbs)):?>
                    <li class="breadcrumb-item"><a href="<?=$value['link'];?>"><?=$value['title'];?></a></li>
                  <?php else:?>
                    <li class="breadcrumb-item active"><?=$value['title'];?></li>  
                  <?php endif;?>
                <?php endforeach;?>
              <?php endif;?>
            </ol>
          </div><!-- /.col -->
        </div><!-- /.row -->
      </div><!-- /.container-fluid -->
    </div>
    <!-- /.content-header -->

    <!-- Main content -->
    <section class="content">
      <?php isset($page) ? $this->load->view($page) : '';?>
      <div class="mb-3"></div>
    </section>
    <!-- /.content -->
  </div>
  <!-- /.content-wrapper -->
  <footer class="main-footer">
    <strong>Copyright &copy; 2014-2019 <a href="http://adminlte.io">AdminLTE.io</a>.</strong>
    All rights reserved.
    <div class="float-right d-none d-sm-inline-block">
      <b>Version</b> 3.0.2
    </div>
  </footer>

  <!-- Control Sidebar -->
  <aside class="control-sidebar control-sidebar-dark">
    <!-- Control sidebar content goes here -->
  </aside>
  <!-- /.control-sidebar -->
</div>
<!-- ./wrapper -->
<script>
$(function() {
  $.fn.select2.defaults.set( "theme", "bootstrap" );
  $('.select2').select2()

  //Initialize Select2 Elements
  $('.select2bs4').select2({
    theme: 'bootstrap4'
  }) 
  /** add active class and stay opened when selected */
  var url = window.location;

  // for sidebar menu entirely but not cover treeview
  $('ul.nav-sidebar a').filter(function() {
      return this.href == url;
  }).addClass('active');

  // for treeview
  $('ul.nav-treeview a').filter(function() {
      return this.href == url;
  }).parentsUntil(".nav-sidebar > .nav-treeview").addClass('menu-open').prev('a').addClass('active');  
})  
function currency(totalharga) {
  var	hargastring = totalharga.toString();
  var rupiah = '';
  var angkarev = totalharga.toString().split('').reverse().join('');
  for(var i = 0; i < angkarev.length; i++) if(i%3 == 0) rupiah += angkarev.substr(i,3)+'.';
  var hasil = 'Rp. '+rupiah.split('',rupiah.length-1).reverse().join('') + ',-';
  return hasil;
}
</script>
</body>
</html>
