<div class="container-fluid">
  <!-- Small boxes (Stat box) -->
  <div class="row">
    <div class="col-12 col-lg-6 col-6">
      <!-- small box -->
      <div class="small-box bg-info bg-info-gradient">
        <div class="inner">
          <h3><?=$order_today;?></h3>

          <p>Pesanan Hari Ini</p>
        </div>
        <div class="icon">
          <i class="ion ion-bag"></i>
        </div>
        <a href="<?=base_url();?>backoffice/transaction?data=today" class="small-box-footer">More info <i class="fas fa-arrow-circle-right"></i></a>
      </div>
    </div>
    <!-- ./col -->
    <div class="col-12 col-lg-6 col-6">
      <!-- small box -->
      <div class="small-box bg-success bg-success-gradient">
        <div class="inner">
          <h3><?=currency($earning_today);?></h3>

          <p>Pendapatan Hari Ini</p>
        </div>
        <div class="icon">
          <i class="ion ion-stats-bars"></i>
        </div>
        <a href="<?=base_url();?>backoffice/transaction?data=today" class="small-box-footer">More info <i class="fas fa-arrow-circle-right"></i></a>
      </div>
    </div>
    <div class="col-12 col-lg-6 col-6">
      <!-- small box -->
      <div class="small-box bg-warning bg-warning-gradient">
        <div class="inner">
          <h3><?=$total_valid_transaction;?></h3>

          <p>Total Transaksi Berhasil</p>
        </div>
        <div class="icon">
          <i class="ion ion-bag"></i>
        </div>
        <a href="<?=base_url();?>backoffice/transaction?data=today" class="small-box-footer">More info <i class="fas fa-arrow-circle-right"></i></a>
      </div>
    </div>
    <div class="col-12 col-lg-6 col-6">
      <!-- small box -->
      <div class="small-box bg-danger bg-danger-gradient">
        <div class="inner">
          <h3><?=$total_valid_order;?></h3>

          <p>Total Produk Terjual</p>
        </div>
        <div class="icon">
          <i class="ion ion-bag"></i>
        </div>
        <a href="<?=base_url();?>backoffice/transaction?data=today" class="small-box-footer">More info <i class="fas fa-arrow-circle-right"></i></a>
      </div>
    </div>
    <div class="col-12 col-lg-6 col-6">
      <!-- small box -->
      <div class="small-box bg-secondary">
        <div class="inner">
          <h3><?=$total_process;?></h3>

          <p>Pesanan Diproses</p>
        </div>
        <div class="icon">
          <i class="ion ion-bag"></i>
        </div>
        <a href="<?=base_url();?>backoffice/transaction?data=today" class="small-box-footer">More info <i class="fas fa-arrow-circle-right"></i></a>
      </div>
    </div>
    <div class="col-12 col-lg-6 col-6">
      <!-- small box -->
      <div class="small-box bg-dark">
        <div class="inner">
          <h3><?=$total_sending;?></h3>

          <p>Sedang dalam Pengiriman</p>
        </div>
        <div class="icon">
          <i class="ion ion-bag"></i>
        </div>
        <a href="<?=base_url();?>backoffice/transaction?data=today" class="small-box-footer">More info <i class="fas fa-arrow-circle-right"></i></a>
      </div>
    </div>
    <!-- ./col -->
    <div class="col-12 col-lg-6 col-6">
      <!-- small box -->
      <div class="small-box bg-light">
        <div class="inner">
          <h3><?=$count_member;?></h3>

          <p>Total Member</p>
        </div>
        <div class="icon">
          <i class="ion ion-person-add"></i>
        </div>
        <a href="#" class="small-box-footer">More info <i class="fas fa-arrow-circle-right"></i></a>
      </div>
    </div>
    <!-- ./col -->
    <div class="col-12 col-lg-6 col-6">
      <!-- small box -->
      <div class="small-box bg-primary">
        <div class="inner">
          <h3><?=$count_affiliator;?></h3>

          <p>Total Affiliator</p>
        </div>
        <div class="icon">
          <i class="ion ion-pie-graph"></i>
        </div>
        <a href="#" class="small-box-footer">More info <i class="fas fa-arrow-circle-right"></i></a>
      </div>
    </div>
    <!-- ./col -->
    <!-- col -->
  </div>
  <!-- /.row -->

</div><!-- /.container-fluid -->