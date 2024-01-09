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