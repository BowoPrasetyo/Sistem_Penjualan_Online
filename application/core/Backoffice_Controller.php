<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Backoffice_Controller extends CI_Controller {
 	public function __construct()
	{
    parent::__construct();
    $this->load->model('Setting_model');
    $this->data = array();

    $settings = $this->Setting_model->get_all_settings();

    foreach($settings as $key => $setting) {
      $this->data["setting_" . $setting['name']] = $setting['value'];
    }
    
    $this->data['title'] = $this->isValue('setting_website_title', 'UMKM Store');
    $this->data['settings'] = $settings;
    $this->data['page_title'] = $this->isValue('setting_website_page_title', 'Belanja Menjadi Menyenangkan | UMKM Store');
    $this->data['top_description'] = $this->isValue('setting_website_top_headline', 'Selamat datang di UMKM Store - Buka : Senin-Sabtu, 10.00-19.00 WIB');
    $this->data['search_placeholder'] = $this->isValue('setting_website_search_placeholder', 'Mau Belanja apa kamu?');
    $this->data['is_login'] = $this->session->userdata('admin') ? true : false;
    $this->data['admin'] = $this->session->userdata('admin');

    if(!$this->data['is_login']) {
      return redirect(base_url('backoffice/auth/login'));
    }
    
    $this->data['csrf'] = [
      'name' => $this->security->get_csrf_token_name(),
      'hash' => $this->security->get_csrf_hash()
		];
	
		
		if($this->session->userdata('role') == 'owner'){
			$this->data['menu_sidear'] = [
				[
					'type' => 'menu',
					'title' => 'Dashboard',
					'icon' => 'fas fa-tachometer-alt',
					'link' => base_url('backoffice/dashboard'),
					'childrens' => []
				],
				[
					'type' => 'header',
					'title' => 'MANAJEMEN PENJUALAN'
				],
				[
					'type' => 'menu',
					'title' => 'Pesanan',
					'icon' => 'fas fa-exchange-alt',
					'link' => '#',
					'childrens' => [
						[
							'type' => 'menu',
							'title' => 'Daftar Pesanan',
							'icon' => 'fas fa-shopping-cart',
							'link' => base_url('backoffice/transaction'),
							'childrens' => []
						],
						[
							'type' => 'menu',
							'title' => 'Hari Ini',
							'icon' => 'far fa-calendar-alt',
							'link' => base_url('backoffice/transaction?data=today'),
							'childrens' => []
						],
						[
							'type' => 'menu',
							'title' => 'Belum Bayar',
							'icon' => 'fas fa-credit-card',
							'link' => base_url('backoffice/transaction?status=waiting_transfer'),
							'childrens' => []
						],
						[
							'type' => 'menu',
							'title' => 'Pending',
							'icon' => 'fas fa-clock',
							'link' => base_url('backoffice/transaction?status=pending'),
							'childrens' => []
						],
						[
							'type' => 'menu',
							'title' => 'Diproses',
							'icon' => 'fas fa-sync-alt',
							'link' => base_url('backoffice/transaction?status=process'),
							'childrens' => []
						],
						[
							'type' => 'menu',
							'title' => 'Dikirim',
							'icon' => 'fas fa-shipping-fast',
							'link' => base_url('backoffice/transaction?status=send'),
							'childrens' => []
						],
					]
				],
				[
					'type' => 'header',
					'title' => 'MANAJEMEN LAPORAN'
				],
				[
					'type' => 'menu',
					'title' => 'Laporan Transaksi',
					'icon' => 'fas fa-shipping-fast',
					'link' => base_url('backoffice/transaction/report'),
					'childrens' => []
				],
				[
				
				],
				[
					'type' => 'menu',
					'title' => 'Laporan Penyedia',
					'icon' => 'fas fa-money-bill-wave-alt',
					'link' => base_url('backoffice/withdraw/provider'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Laporan Mediator',
					'icon' => 'fas fa-money-check-alt',
					'link' => base_url('backoffice/withdraw/mediator'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Laporan CS',
					'icon' => 'fas fa-money-check-alt',
					'link' => base_url('backoffice/withdraw/cs'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Laporan Maintenance',
					'icon' => 'fas fa-money-check-alt',
					'link' => base_url('backoffice/withdraw/maintenance'),
					'childrens' => []
				],
				[
					'type' => 'header',
					'title' => 'MANAJEMEN PENGGUNA'
				],
				[
					'type' => 'menu',
					'title' => 'Admin',
					'icon' => 'fas fa-user',
					'link' => base_url('backoffice/user/admin'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Owner',
					'icon' => 'fas fa-user',
					'link' => base_url('backoffice/user/leader'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Member',
					'icon' => 'fas fa-users',
					'link' => base_url('backoffice/user/members'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Affiliator',
					'icon' => 'fas fa-user-tie',
					'link' => base_url('backoffice/user/affiliators'),
					'childrens' => []
				],
				[
					'type' => 'header',
					'title' => 'MANAJEMEN PENGATURAN'
				],
				[
					'type' => 'menu',
					'title' => 'Situs',
					'icon' => 'fas fa-cog',
					'link' => base_url('backoffice/setting/site'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Rajaongkir',
					'icon' => 'fas fa-truck',
					'link' => base_url('backoffice/setting/rajaongkir'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Alamat Pengirim',
					'icon' => 'fas fa-truck',
					'link' => base_url('backoffice/setting/sender'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Pembayaran',
					'icon' => 'fas fa-credit-card',
					'link' => '#',
					'childrens' => [
						[
							'type' => 'menu',
							'title' => 'Midtrans',
							'icon' => 'far fa-dot-circle',
							'link' => base_url('backoffice/setting/payment_midtrans'),
							'childrens' => []
						],
					]
				],
			];
		} else {
			$this->data['menu_sidear'] = [
				[
					'type' => 'menu',
					'title' => 'Dashboard',
					'icon' => 'fas fa-tachometer-alt',
					'link' => base_url('backoffice/dashboard'),
					'childrens' => []
				],
				[
					'type' => 'header',
					'title' => 'MANAJEMEN MASTER'
				],
				[
					'type' => 'menu',
					'title' => 'Kategori',
					'icon' => 'fas fa-tags',
					'link' => '#',
					'childrens' => [
						[
							'type' => 'menu',
							'title' => 'Daftar Kategori',
							'icon' => 'far fa-dot-circle',
							'link' => base_url('backoffice/category'),
							'childrens' => []
						],
						[
							'type' => 'menu',
							'title' => 'Tambah Kategori',
							'icon' => 'far fa-dot-circle',
							'link' => base_url('backoffice/category/create'),
							'childrens' => []
						],
					]
				],
				[
					'type' => 'header',
					'title' => 'MANAJEMEN PRODUK'
				],
				[
					'type' => 'menu',
					'title' => 'Produk',
					'icon' => 'fab fa-product-hunt',
					'link' => '#',
					'childrens' => [
						[
							'type' => 'menu',
							'title' => 'Daftar Produk',
							'icon' => 'far fa-dot-circle',
							'link' => base_url('backoffice/product'),
							'childrens' => []
						],
						[
							'type' => 'menu',
							'title' => 'Tambah Produk',
							'icon' => 'far fa-dot-circle',
							'link' => base_url('backoffice/product/create'),
							'childrens' => []
						],
					]
				],
				[
					'type' => 'header',
					'title' => 'MANAJEMEN PENJUALAN'
				],
				[
					'type' => 'menu',
					'title' => 'Pesanan',
					'icon' => 'fas fa-exchange-alt',
					'link' => '#',
					'childrens' => [
						[
							'type' => 'menu',
							'title' => 'Daftar Pesanan',
							'icon' => 'fas fa-shopping-cart',
							'link' => base_url('backoffice/transaction'),
							'childrens' => []
						],
						[
							'type' => 'menu',
							'title' => 'Hari Ini',
							'icon' => 'far fa-calendar-alt',
							'link' => base_url('backoffice/transaction?data=today'),
							'childrens' => []
						],
						[
							'type' => 'menu',
							'title' => 'Belum Bayar',
							'icon' => 'fas fa-credit-card',
							'link' => base_url('backoffice/transaction?status=waiting_transfer'),
							'childrens' => []
						],
						[
							'type' => 'menu',
							'title' => 'Pending',
							'icon' => 'fas fa-clock',
							'link' => base_url('backoffice/transaction?status=pending'),
							'childrens' => []
						],
						[
							'type' => 'menu',
							'title' => 'Diproses',
							'icon' => 'fas fa-sync-alt',
							'link' => base_url('backoffice/transaction?status=process'),
							'childrens' => []
						],
						[
							'type' => 'menu',
							'title' => 'Dikirim',
							'icon' => 'fas fa-shipping-fast',
							'link' => base_url('backoffice/transaction?status=send'),
							'childrens' => []
						],
					]
				],
				[
					'type' => 'header',
					'title' => 'MANAJEMEN LAPORAN'
				],
				[
					'type' => 'menu',
					'title' => 'Laporan Transaksi',
					'icon' => 'fas fa-shipping-fast',
					'link' => base_url('backoffice/transaction/report'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Laporan Penarikan',
					'icon' => 'fas fa-money-bill',
					'link' => base_url('backoffice/withdraw'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Laporan Penyedia',
					'icon' => 'fas fa-money-bill-wave-alt',
					'link' => base_url('backoffice/withdraw/provider'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Laporan Mediator',
					'icon' => 'fas fa-money-check-alt',
					'link' => base_url('backoffice/withdraw/mediator'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Laporan CS',
					'icon' => 'fas fa-money-check-alt',
					'link' => base_url('backoffice/withdraw/cs'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Laporan Maintenance',
					'icon' => 'fas fa-money-check-alt',
					'link' => base_url('backoffice/withdraw/maintenance'),
					'childrens' => []
				],
				[
					'type' => 'header',
					'title' => 'MANAJEMEN PENGGUNA'
				],
				[
					'type' => 'menu',
					'title' => 'Admin',
					'icon' => 'fas fa-user',
					'link' => base_url('backoffice/user/admin'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Owner',
					'icon' => 'fas fa-user',
					'link' => base_url('backoffice/user/leader'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Member',
					'icon' => 'fas fa-users',
					'link' => base_url('backoffice/user/members'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Affiliator',
					'icon' => 'fas fa-user-tie',
					'link' => base_url('backoffice/user/affiliators'),
					'childrens' => []
				],
				[
					'type' => 'header',
					'title' => 'MANAJEMEN PENGATURAN'
				],
				[
					'type' => 'menu',
					'title' => 'Situs',
					'icon' => 'fas fa-cog',
					'link' => base_url('backoffice/setting/site'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Rajaongkir',
					'icon' => 'fas fa-truck',
					'link' => base_url('backoffice/setting/rajaongkir'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Alamat Pengirim',
					'icon' => 'fas fa-truck',
					'link' => base_url('backoffice/setting/sender'),
					'childrens' => []
				],
				[
					'type' => 'menu',
					'title' => 'Pembayaran',
					'icon' => 'fas fa-credit-card',
					'link' => '#',
					'childrens' => [
						[
							'type' => 'menu',
							'title' => 'Midtrans',
							'icon' => 'far fa-dot-circle',
							'link' => base_url('backoffice/setting/payment_midtrans'),
							'childrens' => []
						],
					]
				],
			];
		}

  }

  public function isValue($value, $default = '')
  {
    return isset($this->data[$value]) ? $this->data[$value] : $default;
  }
}
