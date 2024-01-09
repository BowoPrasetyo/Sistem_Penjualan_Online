<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Transaction_detail extends Frontend_Controller{

  function __construct()
  {
    parent::__construct();
    $params = array('server_key' => 'SB-Mid-server-KtVmhxvigdmrtNRZdnQHh8KW', 'production' => false);
    $this->load->library('midtrans');
    $this->midtrans->config($params);
    $this->load->model('Transaction_detail_model');
    $this->load->model('Transaction_shipping_model');
  } 

  /*
    * Listing of transactions
    */
  function detail($id)
  {
    $data['transactions'] = $this->Transaction_detail_model->get_transaction_detail($id);
    
    return toJson([
        'success' => true,
        'data' => $data['transactions']
    ]);
  }
}