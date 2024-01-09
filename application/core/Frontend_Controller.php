<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Frontend_Controller extends CI_Controller {
 	public function __construct()
	{
    parent::__construct();
    $this->load->model('Setting_model');
    $this->load->model('Notification_model');
    $this->load->driver('cache');
		$this->load->model('User_model');
    $this->data = array();
		
		if($referral = $this->input->get('reff')) {
			$checkAffiliate = $this->User_model->findByReferral($referral);
			if($checkAffiliate) {
				// jika aff data sebelumnya masih valid
//        if(!get_cookie('aff_data')) {
//          set_cookie('aff_data', $checkAffiliate['id'], 86400 * 30);
//        }
				set_cookie('aff_data', $checkAffiliate['id'], 86400 * 30);
			}
		}

    if (!$settings = $this->cache->file->get('settings')){
      $settings = $this->Setting_model->get_all_settings();

      $this->cache->file->save('settings', $settings, 60);
    }

    foreach($settings as $key => $setting) {
      $this->data["setting_" . $setting['name']] = $setting['value'];
    }
    
    $this->data['title'] = $this->isValue('setting_website_title', 'UMKM Store');
    $this->data['page_title'] = $this->isValue('setting_website_page_title', 'Belanja Menjadi Menyenangkan | UMKM Store');
    $this->data['top_description'] = $this->isValue('setting_website_top_headline', 'Selamat datang di UMKM Store - Buka : Senin-Sabtu, 10.00-19.00 WIB');
    $this->data['search_placeholder'] = $this->isValue('setting_website_search_placeholder', 'Mau Belanja apa kamu?');
    $this->data['is_login'] = $this->session->userdata('user') ? true : false;
    $this->data['user'] = $this->session->userdata('user');
    $this->data['user_notifications'] = $this->Notification_model->get_notifications_by_user($this->data['user']->id ?? 0);
    $this->data['csrf'] = [
      'name' => $this->security->get_csrf_token_name(),
      'hash' => $this->security->get_csrf_hash()
    ];

    if($this->data['setting_maintenance_mode'] != "false") {
      redirect(base_url('maintenance'));
      exit;
    }

  }

  public function isValue($value, $default = '')
  {
    return isset($this->data[$value]) ? $this->data[$value] : $default;
  }
}