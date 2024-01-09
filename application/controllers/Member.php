<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Member extends Frontend_Controller {
  public function __construct()
  {
    parent::__construct();
    $this->load->model('Product_model');
    $this->load->model('Category_model');
    $this->load->model('Product_image_model');
    $this->load->model('Transaction_model');
    $this->load->model('Transaction_detail_model');
    $this->load->model('Transaction_shipping_model');
    $this->load->model('User_model');
    $this->load->model('Commision_model');
    $this->load->model('Widthdraw_affiliate_model');

    if(!$this->data['is_login']) {
      return redirect(base_url('auth/login'));
    }
  }

  public function my_profile()
	{
    $this->data['page'] = 'frontend/v_profile';
    $this->data['user'] = (object) $this->User_model->get_user($this->data['user']->id);
		$this->load->view('frontend/index', $this->data);
  }

  public function my_affiliators()
	{
    if($this->data['user']->role == 'leader') {
      $this->data['page'] = 'frontend/v_my_affiliators';
      $this->data['user'] = (object) $this->User_model->get_user($this->data['user']->id);
      $this->load->view('frontend/index', $this->data);
    } else {
      return redirect(base_url('member/my_profile'));
    }
  }

  public function my_earning()
	{
    if($this->data['user']->role != 'affiliate' && $this->data['user']->role != 'developer' && $this->data['user']->role != 'provider' && $this->data['user']->role != 'leader' && $this->data['user']->role != 'cs' && $this->data['user']->role != 'mediator') {
      return redirect(base_url(''));
    }

    if($this->data['user']->role == 'affiliate') {
      $this->data['can_withdraw'] = false;
      $this->data['latest_widthdraw'] = $this->Widthdraw_affiliate_model->get_latest_withdraw($this->data['user']->id);

      $check = $this->User_model->get_user($this->data['user']->id);
      if(empty($check['bank_name']) || empty($check['account_number']) || empty($check['account_name'])) {
        $this->data['can_withdraw'] = false;
      } else {
        $this->data['can_withdraw'] = true;
      }

      // cachce data
      if (!$this->data['saldo'] = $this->cache->file->get('saldo_affiliate_' . $this->data['user']->id)){
        $this->data['saldo'] = $this->Commision_model->get_total_commision_affiliator($this->data['user']->id);
  
        $this->cache->file->save('saldo_affiliate_'. $this->data['user']->id, $this->data['saldo'], 60);
      }

      if (!$this->data['earning_today'] = $this->cache->file->get('earning_today_' . $this->data['user']->id)){
        $this->data['earning_today'] = $this->Commision_model->get_earning_today($this->data['user']->id);
  
        $this->cache->file->save('earning_today_'. $this->data['user']->id, $this->data['earning_today'], 60);
      }

      if (!$this->data['earning_month'] = $this->cache->file->get('earning_month_' . $this->data['user']->id)){
        $this->data['earning_month'] = $this->Commision_model->get_earning_month($this->data['user']->id);
  
        $this->cache->file->save('earning_month_'. $this->data['user']->id, $this->data['earning_month'], 60);
      }

      if (!$this->data['earning_month_yesterday'] = $this->cache->file->get('earning_month_yesterday_' . $this->data['user']->id)){
        
  
        $this->cache->file->save('earning_month_yesterday_'. $this->data['user']->id, $this->data['earning_month_yesterday'], 60);
      }

      $this->data['page'] = 'frontend/v_my_earning';
    } else if($this->data['user']->role == 'developer') {
      $check = $this->User_model->get_user($this->data['user']->id);
      if(empty($check['bank_name']) || empty($check['account_number']) || empty($check['account_name'])) {
        $this->data['can_withdraw'] = false;
      } else {
        $this->data['can_withdraw'] = true;
      }
      $this->data['saldo'] = $this->Commision_model->get_total_commision_maintenance();
      $this->data['earning_today'] = $this->Commision_model->get_earning_today_maintenance();
      $this->data['earning_month'] = $this->Commision_model->get_earning_month_maintenance();
      $this->data['earning_month_yesterday'] = $this->Commision_model->get_earning_month_yesterday_maintenance();
      $this->data['page'] = 'frontend/v_maintenance_earning';
    } else if($this->data['user']->role == 'provider') {
      $this->data['saldo'] = $this->Commision_model->get_total_commision_provider();
      $this->data['earning_today'] = $this->Commision_model->get_earning_today_provider();
      $this->data['earning_month'] = $this->Commision_model->get_earning_month_provider();
      $this->data['earning_month_yesterday'] = $this->Commision_model->get_earning_month_yesterday_provider();
      $this->data['page'] = 'frontend/v_provider_earning';
    } else if($this->data['user']->role == 'leader') {
      $this->data['can_withdraw'] = false;
      $this->data['latest_widthdraw'] = $this->Widthdraw_affiliate_model->get_latest_withdraw($this->data['user']->id);

      $check = $this->User_model->get_user($this->data['user']->id);
      if(empty($check['bank_name']) || empty($check['account_number']) || empty($check['account_name'])) {
        $this->data['can_withdraw'] = false;
      } else {
        $this->data['can_withdraw'] = true;
      }
      
      $this->data['saldo'] = $this->Commision_model->get_total_commision_leader($this->data['user']->id);
      $this->data['earning_today'] = $this->Commision_model->get_earning_today_leader($this->data['user']->id);
      $this->data['earning_month'] = $this->Commision_model->get_earning_month_leader($this->data['user']->id);
      $this->data['earning_month_yesterday'] = $this->Commision_model->get_earning_month_yesterday_leader($this->data['user']->id);
      $this->data['page'] = 'frontend/v_leader_earning';
    } else if($this->data['user']->role == 'mediator') {
      $this->data['saldo'] = $this->Commision_model->get_total_commision_mediator();
      $this->data['earning_today'] = $this->Commision_model->get_earning_today_mediator();
      $this->data['earning_month'] = $this->Commision_model->get_earning_month_mediator();
      $this->data['earning_month_yesterday'] = $this->Commision_model->get_earning_month_yesterday_mediator();
      $this->data['page'] = 'frontend/v_mediator_earning';
    } else if($this->data['user']->role == 'cs') {
      $this->data['saldo'] = $this->Commision_model->get_total_commision_cs();
      $this->data['earning_today'] = $this->Commision_model->get_earning_today_cs();
      $this->data['earning_month'] = $this->Commision_model->get_earning_month_cs();
      $this->data['earning_month_yesterday'] = $this->Commision_model->get_earning_month_yesterday_cs();
      $this->data['page'] = 'frontend/v_cs_earning';
    }
    
		$this->load->view('frontend/index', $this->data);
  }

  public function transaction()
	{
    $this->data['page'] = 'frontend/v_transaction';
		$this->load->view('frontend/index', $this->data);
  }

  public function transaction_detail($order_id = 0)
	{
    $this->data['detail']['transaction'] = $this->Transaction_model->findByOrderId($order_id, $this->session->userdata('user')->id);
    $this->data['detail']['product'] = $this->Transaction_detail_model->findByTransaction($this->data['detail']['transaction']->id ?? 0);
    $this->data['detail']['shipping'] = $this->Transaction_shipping_model->findByTransaction($this->data['detail']['transaction']->id ?? 0);
    $this->data['page'] = 'frontend/v_transaction_detail';
		$this->load->view('frontend/index', $this->data);
  }

  public function update_profile()
  {
    try {
      $params = [
        'first_name' => htmlspecialchars($this->input->post('first_name')),
        'last_name' => htmlspecialchars($this->input->post('last_name')),
        'phone' => htmlspecialchars($this->input->post('phone')),
        'bank_name' => htmlspecialchars($this->input->post('bank_name')),
        'account_name' => htmlspecialchars($this->input->post('account_name')),
        'account_number' => htmlspecialchars($this->input->post('account_number')),
      ];

      $update = $this->User_model->update_user($this->data['user']->id, $params);

      if(!$update) {
        $this->session->set_flashdata('err', 'Gagal Update Profile');
        return redirect(base_url('member/my_profile'));
      }

      $this->session->set_flashdata('success', 'Berhasil Update Profile');

      return redirect(base_url('member/my_profile'));
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Sistem sedang gangguan');
      return redirect(base_url('member/my_profile'));
    }
  }

  public function update_password()
  {
    try {
      $params = [
        'password_old' => htmlspecialchars($this->input->post('password_old')),
        'password' => htmlspecialchars($this->input->post('password')),
        'password_confirm' => htmlspecialchars($this->input->post('password_confirm')),
      ];

      if($params['password'] != $params['password_confirm']) {
        $this->session->set_flashdata('err', 'Password Tidak Sama');
        return redirect(base_url('member/my_profile'));
      }

      $user = $this->User_model->get_user($this->data['user']->id);

      if(!password_verify($params['password_old'], $user['password'])) {
        $this->session->set_flashdata('err', 'Password Lama Tidak Sama');
        return redirect(base_url('member/my_profile'));
      }

      if(password_verify($params['password'], $user['password'])) {
        $this->session->set_flashdata('err', 'Password Tidak Boleh sama dengan sebelumnya');
        return redirect(base_url('member/my_profile'));
      }

      $update = $this->User_model->update_user($this->data['user']->id, [
        'password' => password_hash($params['password'], PASSWORD_BCRYPT)
      ]);

      if(!$update) {
        $this->session->set_flashdata('err', 'Gagal Update Password');
        return redirect(base_url('member/my_profile'));
      }

      $this->session->set_flashdata('success', 'Berhasil Update Password');

      return redirect(base_url('member/my_profile'));
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Sistem sedang gangguan');
      return redirect(base_url('member/my_profile'));
    }
  }

  public function withdraw()
  {
    try {
      validate_self_request();
      $this->db->trans_start();

      $check = $this->User_model->get_user($this->data['user']->id);

      if(empty($check['bank_name']) || empty($check['account_number']) || empty($check['account_name'])) {
        $this->session->set_flashdata('err', 'Mohon lengkapi informasi Rekening di Profil.');
        return redirect(base_url('member/my_earning'));
      }

      if($this->data['user']->role == 'affiliate') {
        $this->data['saldo'] = $this->Commision_model->get_total_commision_affiliator($this->data['user']->id);
        $this->db->where('user_id', $this->data['user']->id);
        $this->db->set('amount', "amount-{$this->data['saldo']}", FALSE);
        $this->db->update('affiliators_commision');
      } else if($this->data['user']->role == 'developer') {
        $this->data['saldo'] = $this->Commision_model->get_total_commision_maintenance();
        $this->db->set('amount', "amount-{$this->data['saldo']}", FALSE);
        $this->db->update('maintenance_commision');
      } else if($this->data['user']->role == 'provider') {
        $this->data['saldo'] = $this->Commision_model->get_total_commision_provider();
        $this->db->set('amount', "amount-{$this->data['saldo']}", FALSE);
        $this->db->update('provider_commision');
      } else if($this->data['user']->role == 'leader') {
        $this->data['saldo'] = $this->Commision_model->get_total_commision_leader($this->data['user']->id);
        $this->db->where('user_id', $this->data['user']->id);
        $this->db->set('amount', "amount-{$this->data['saldo']}", FALSE);
        $this->db->update('leaders_commision');
      } 

      if((int) $this->data['saldo'] <= 0) {
        $this->session->set_flashdata('err', 'Saldo tidak cukup.');
        return redirect(base_url('member/my_earning'));
      }

      $withdraw = $this->Widthdraw_affiliate_model->add_withdraw_affiliate([
        'user_id' => $this->data['user']->id,
        'amount' => $this->data['saldo'],
        'status' => 'pending',
        'created_at' => date('Y-m-d H:i:s'),
        'updated_at' => date('Y-m-d H:i:s'),
      ]);

      if(!$withdraw) {
        $this->session->set_flashdata('err', 'Gagal melakukan withdraw');
        return redirect(base_url('member/my_earning'));
      }

      $this->db->trans_complete();
    
      if ($this->db->trans_status() === FALSE) {
        $this->db->trans_rollback();
        $this->session->set_flashdata('err', 'Gagal melakukan withdraw');
        return redirect(base_url('member/my_earning'));

      } else {
        $this->db->trans_commit();
        $this->session->set_flashdata('success', 'Berhasil Withdraw, Mohon tunggu proses selanjutnya.');
        return redirect(base_url('member/my_earning'));
      }
    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Sistem sedang gangguan');
      return redirect(base_url('member/my_earning'));
    }
  }
}