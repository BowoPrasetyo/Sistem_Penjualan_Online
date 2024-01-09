<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Backoffice_Controller.php';

class Setting extends Backoffice_Controller {
  public function __construct()
  {
    parent::__construct();
    $this->load->model('Product_model');
    $this->load->model('Category_model');
    $this->load->model('Setting_model');
  }

  public function sender()
	{
    $this->data['page_title'] = 'Alamat Pengiriman';
    $this->data['page'] = 'backoffice/setting/sender';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Alamat Pengiriman',
        'link' => 1
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function sender_update()
  {
    try {
      $sender_district = $this->input->post('district_value');
      $sender_summary = json_encode([
        'city' => $this->input->post('city_value'),
        'province' => $this->input->post('province_value')
      ]);

      $this->Setting_model->update_by_name('sender_district', $sender_district);
      $this->Setting_model->update_by_name('sender_summary', $sender_summary);

      $this->session->set_flashdata('success', 'Berhasil Mengubah Pengaturan Pengirim');
      return redirect(base_url('backoffice/setting/sender'));

    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Gagal Update Pengaturan Pengirim');
      return redirect(base_url('backoffice/setting/sender'));
    }
  }

	public function site()
	{
    $this->data['page_title'] = 'Pengaturan Website';
    $this->data['page'] = 'backoffice/setting/site';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Pengaturan Situs',
        'link' => 1
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function site_update()
  {
    try {
      $params = $this->input->post();

      foreach($params as $key => $value) {
        $this->Setting_model->update_by_name($key, $value);
      }

      $this->session->set_flashdata('success', 'Berhasil Mengubah Pengaturan Situs');
      return redirect(base_url('backoffice/setting/site'));

    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Gagal Update Pengaturan Situs');
      return redirect(base_url('backoffice/setting/site'));
    }
  }

  public function rajaongkir()
	{
    $this->data['page_title'] = 'Pengaturan Rajaongkir';
    $this->data['page'] = 'backoffice/setting/rajaongkir';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Pengaturan Raja Ongkir',
        'link' => 1
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function rajaongkir_update()
  {
    try {
      $params = $this->input->post();

      foreach($params as $key => $value) {
        $this->Setting_model->update_by_name($key, $value);
      }

      $this->session->set_flashdata('success', 'Berhasil Mengubah Pengaturan Rajaongkir');
      return redirect(base_url('backoffice/setting/rajaongkir'));

    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Gagal Update Pengaturan Rajaongkir');
      return redirect(base_url('backoffice/setting/rajaongkir'));
    }
  }

  public function payment_midtrans()
	{
    $this->data['page_title'] = 'Pengaturan Midtrans';
    $this->data['page'] = 'backoffice/setting/payment_midtrans';

    $this->data['breadcrumbs'] = [
      [
        'title' => 'Apps',
        'link' => '#'
      ],
      [
        'title' => 'Pengaturan Midtrans',
        'link' => 1
      ]
    ];

		$this->load->view('backoffice/index', $this->data);
  }

  public function payment_midtran_update()
  {
    try {
      $params = $this->input->post();

      foreach($params as $key => $value) {
        $this->Setting_model->update_by_name($key, $value);
      }

      $this->session->set_flashdata('success', 'Berhasil Mengubah Pengaturan Midtrans');
      return redirect(base_url('backoffice/setting/payment_midtrans'));

    } catch (Exception $e) {
      $this->session->set_flashdata('err', 'Gagal Update Pengaturan Midtrans');
      return redirect(base_url('backoffice/setting/payment_midtrans'));
    }
  }
}