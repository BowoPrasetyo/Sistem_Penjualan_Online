<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Withdraw extends Frontend_Controller {
  public function __construct()
  {
    parent::__construct();
    $this->load->model('Widthdraw_affiliate_model');

    if(!$this->data['is_login']) {
      return redirect(base_url('auth/login'));
    }
  }

  public function datatable()
  {
    validate_self_request();
    header('Content-Type: application/json');
    echo $this->Widthdraw_affiliate_model->datatable(
        $this->session->userdata('user')->id
    );
  }
}