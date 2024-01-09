<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Backoffice_Controller.php';

class Dashboard extends Backoffice_Controller {
  public function __construct()
  {
    parent::__construct();
    $this->load->model('Transaction_model');
    $this->load->model('User_model');

    if(!$this->data['is_login']) {
      return redirect(base_url('backoffice/auth/login'));
    }
  }

	public function index()
	{
    $this->data['page_title'] = 'Dashboard';
    $this->data['page'] = 'backoffice/v_dashboard';
    $this->data['earning_today'] = $this->Transaction_model->get_earning_today();
    $this->data['order_today'] = $this->Transaction_model->get_order_today();
    $this->data['count_member'] = $this->User_model->count_member('member');
    $this->data['count_affiliator'] = $this->User_model->count_member('affiliate');
    $this->data['total_valid_order'] = $this->Transaction_model->get_total_valid_order();
    $this->data['total_valid_transaction'] = $this->Transaction_model->total_valid_transaction();
    $this->data['total_sending'] = $this->Transaction_model->pesanan_dikirim();
    $this->data['total_process'] = $this->Transaction_model->pesanan_diproses();

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Dashboard',
        'link' => 1
      ]
    ];
    

		$this->load->view('backoffice/index', $this->data);
  }
}
