<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Backoffice_Controller.php';

class Auth extends CI_Controller {
  public function __construct()
  {
    parent::__construct();
    $this->load->model('User_model');
    
    $this->data = array();
    
    $this->data['csrf'] = [
      'name' => $this->security->get_csrf_token_name(),
      'hash' => $this->security->get_csrf_hash()
    ];
  }

  public function login()
	{
    $this->data['page_title'] = 'Login';
    $this->data['page'] = 'backoffice/auth/login';
    

		$this->load->view('backoffice/auth/index', $this->data);
  }

  public function doLogin()
	{
    $email = $this->input->post('email', TRUE);
    $password = $this->input->post('password', TRUE);
    $redirect = $this->input->get('redirect', TRUE);

    $check = $this->User_model->checkAuthAdmin($email, $password);

    if(!$check) {
      return redirect(base_url('backoffice/dashboard'));
    }

    $token = $this->User_model->createToken($check);

    if(!$check || !$token) {
      return redirect(base_url('backoffice/dashboard'));
    }

		return redirect(base_url('backoffice/dashboard'));
  }

  public function logout()
  {
    $this->session->unset_userdata('admin');
    $this->session->sess_destroy();
    return redirect(base_url('backoffice/auth/login'));
  }
}
