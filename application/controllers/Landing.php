<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Landing extends Frontend_Controller {
  public function __construct()
  {
    parent::__construct();
    $this->load->model('User_model');
    $this->load->model('Product_model');

    // if($referral = $this->input->get('reff')) {
    //   $checkAffiliate = $this->User_model->findByReferral($referral);
    //   if($checkAffiliate) {
    //     // jika aff data sebelumnya masih valid
    //     if(!get_cookie('aff_data')) {
    //       set_cookie('aff_data', $checkAffiliate['id'], 86400 * 30);
    //     }
    //   }
    // }
  }
	public function index()
	{
    // $this->output->cache(5);

    if (!$this->data['products'] = $this->cache->file->get('products_home')){
      $this->data['products'] = $this->Product_model->get_all_valid_products();

      $this->cache->file->save('products_home', $this->data['products'], 60);
    }
		$this->load->view('landing/index', $this->data);
  }
}