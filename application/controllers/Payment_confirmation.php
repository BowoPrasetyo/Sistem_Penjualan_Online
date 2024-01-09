<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require_once APPPATH.'core/Frontend_Controller.php';

class Payment_confirmation extends Frontend_Controller {
  public function __construct()
	{
		parent::__construct();
	}

	public function index()
	{
		$this->data['page'] = 'frontend/v_payment_confirmation';
		$this->load->view('frontend/index', $this->data);
	}

	public function confirmation()
	{
		try {
			if(isset($_POST) > 0) {
				$params = [
					'order_id' => htmlspecialchars($this->input->post('order_id', TRUE)),
					'amount' => htmlspecialchars($this->input->post('amount', TRUE)),
                    'bank_name' => htmlspecialchars($this->input->post('bank_name', TRUE)),
                    'bank_number' => htmlspecialchars($this->input->post('bank_number', TRUE)),
                    'account_name' => htmlspecialchars($this->input->post('account_name', TRUE)),
				];

                $upload = uploadGlobalFile(
                    'image',
                    'resources/upload/img',
                    'image'
                );

                if($upload != null) {
                    $params['file'] = $upload;
                } else {
                    $this->session->set_flashdata('err', 'Harap lampirkan bukti transfer');
                }

                $checkTransaction = $this->db
                    ->where('order_id', $params['order_id'])
                    ->get('transactions')
                    ->num_rows();

                if($checkTransaction <= 0) {
                    $this->session->set_flashdata('err', 'Transaksi Tidak ada');
                    return redirect(base_url('payment_confirmation'));
                }

                $this->db->insert('transfer_confirmations', $params);

                $this->session->set_flashdata('success', 'Berhasil melakukan konfirmasi, pembayaran akan segera di verifikasi,');
                return redirect(base_url('payment_confirmation'));
			}
		} catch (Exception $e) {
            $this->session->set_flashdata('err', 'Konfirmasi gagal, coba beberapa saat lagi');
            return redirect(base_url('payment_confirmation'));
		}
	}
}
